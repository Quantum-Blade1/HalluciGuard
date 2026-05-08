#!/usr/bin/env python3
"""
HalluciGuard Scanner — CLI entry point.

Walks a workspace, finds all .py/.js files, runs Sentinel → Validator → Profiler
on each, and streams NDJSON results to stdout.

Usage:
    python -m scanner.halluciguard_scanner --workspace /path/to/project
    python -m scanner.halluciguard_scanner --workspace /path --files src/app.py src/utils.py
    python -m scanner.halluciguard_scanner --workspace /path --threshold 80

Output (stdout, one JSON per line):
    {"type": "progress", "file": "relative/path.py", "status": "scanning"}
    {"type": "finding", "file": "...", "package": "...", "line": 3, ...}
    {"type": "summary", "files_scanned": 12, ...}

All log/error output goes to stderr, NEVER stdout.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
import time
from pathlib import Path

# ── Ensure scanner/ is importable when run as a script ──────────────────────
# When invoked as `python scanner/halluciguard_scanner.py`, the parent dir
# of scanner/ needs to be on sys.path so `from scanner.x import y` works.
_SCANNER_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _SCANNER_DIR.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from scanner.config import SKIP_DIRS, SUPPORTED_EXTENSIONS, DEFAULT_RISK_THRESHOLD, AUDIT_LOG_PATH
from scanner.data.bloom_filter import package_bloom_filter
from scanner.data.hallucination_db import HallucinationDB
from scanner.agents.sentinel import SentinelAgent, PackageRef
from scanner.agents.validator import ValidatorAgent, ValidationResult
from scanner.agents.profiler import ProfilerAgent, ProfileResult
from scanner.agents.auditor import AuditorAgent

# ── Logging: everything to stderr ───────────────────────────────────────────
logging.basicConfig(
    level=logging.WARNING,
    format="%(levelname)s %(name)s: %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("halluciguard_scanner")


# ── NDJSON helpers ──────────────────────────────────────────────────────────

def emit(obj: dict) -> None:
    """Write a single JSON line to stdout and flush immediately."""
    print(json.dumps(obj, ensure_ascii=False), flush=True)


def emit_progress(file: str) -> None:
    emit({"type": "progress", "file": file, "status": "scanning"})


def emit_finding(
    file: str,
    ref: PackageRef,
    profile: ProfileResult,
) -> None:
    action = "BLOCK" if profile.risk_score >= 80 else (
        "WARN" if profile.is_high_risk else "ALLOW"
    )
    emit({
        "type": "finding",
        "file": file,
        "package": ref.package_name,
        "line": ref.line_no,
        "risk_score": round(profile.risk_score, 1),
        "action": action,
        "flags": profile.flags,
        "nearest": profile.nearest_package,
        "distance": profile.levenshtein_distance,
        "suggested": profile.suggested,
        "language": ref.language,
    })


def emit_summary(
    files_scanned: int,
    packages_found: int,
    high_risk: int,
    passed: int,
    duration_ms: float,
) -> None:
    emit({
        "type": "summary",
        "files_scanned": files_scanned,
        "packages_found": packages_found,
        "high_risk": high_risk,
        "passed": passed,
        "duration_ms": round(duration_ms),
    })


def emit_audit_summary(entries: int, chain_valid: bool) -> None:
    emit({
        "type": "audit_summary",
        "entries_logged": entries,
        "chain_valid": chain_valid,
    })


# ── File discovery ──────────────────────────────────────────────────────────

def discover_files(workspace: Path, file_filter: list[str] | None = None) -> list[Path]:
    """Walk workspace and return all .py/.js files, respecting SKIP_DIRS.

    If file_filter is provided, only return those specific files.
    """
    if file_filter:
        # Resolve relative to workspace
        files: list[Path] = []
        for f in file_filter:
            p = workspace / f
            if p.is_file() and p.suffix in SUPPORTED_EXTENSIONS:
                files.append(p)
            else:
                logger.warning("Skipping %s (not found or unsupported extension)", f)
        return files

    files = []
    for path in workspace.rglob("*"):
        # Skip hidden/excluded directories
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.is_file() and path.suffix in SUPPORTED_EXTENSIONS:
            files.append(path)
    return sorted(files)


# ── Per-file scan ───────────────────────────────────────────────────────────

async def scan_file(
    file_path: Path,
    workspace: Path,
    sentinel: SentinelAgent,
    validator: ValidatorAgent,
    profiler: ProfilerAgent,
    auditor: AuditorAgent,
) -> tuple[int, int, int]:
    """Scan a single file through the 3-agent pipeline.

    Returns:
        (packages_found, high_risk, passed) counts.
    """
    relative = str(file_path.relative_to(workspace))
    emit_progress(relative)

    try:
        code = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.error("Cannot read %s: %s", relative, e)
        return (0, 0, 0)

    # Detect language from extension
    language = "javascript" if file_path.suffix == ".js" else "python"

    # Agent 1: Sentinel
    refs: list[PackageRef] = sentinel.analyze(code, language)
    if not refs:
        return (0, 0, 0)

    # Agent 2: Validator
    try:
        validations: list[ValidationResult] = await asyncio.wait_for(
            validator.validate(refs), timeout=15.0
        )
    except asyncio.TimeoutError:
        logger.warning("Validator timed out for %s", relative)
        validations = [
            ValidationResult(
                package_name=r.package_name,
                exists_on_registry=False,
                bloom_hit=False,
                is_hallucinated=False,
            )
            for r in refs
        ]

    # Agent 3: Profiler
    profiles: list[ProfileResult] = await profiler.profile(refs, validations)

    # Emit findings
    pkg_count = len(refs)
    high_risk_count = 0
    passed_count = 0

    for ref, profile in zip(refs, profiles):
        action = "BLOCK" if profile.risk_score >= 80 else ("WARN" if profile.is_high_risk else "ALLOW")
        # Agent 4: Auditor — log every decision with hash chain
        auditor.log_event(profile, action, language=language)

        if profile.is_high_risk:
            emit_finding(relative, ref, profile)
            high_risk_count += 1
        else:
            passed_count += 1

    return (pkg_count, high_risk_count, passed_count)


# ── Main scan loop ──────────────────────────────────────────────────────────

async def run_scan(workspace: Path, file_filter: list[str] | None, threshold: int) -> None:
    """Discover files, scan each, emit results."""
    start = time.monotonic()

    sentinel = SentinelAgent()
    validator = ValidatorAgent()
    profiler = ProfilerAgent(risk_threshold=threshold)
    auditor = AuditorAgent(log_path=AUDIT_LOG_PATH)

    files = discover_files(workspace, file_filter)
    if not files:
        logger.warning("No .py or .js files found in %s", workspace)
        emit_summary(0, 0, 0, 0, 0)
        return

    total_packages = 0
    total_high_risk = 0
    total_passed = 0

    try:
        for file_path in files:
            pkg, hr, ps = await scan_file(
                file_path, workspace, sentinel, validator, profiler, auditor
            )
            total_packages += pkg
            total_high_risk += hr
            total_passed += ps
    finally:
        await validator.close()
        await profiler.close()

    elapsed_ms = (time.monotonic() - start) * 1000
    emit_summary(len(files), total_packages, total_high_risk, total_passed, elapsed_ms)
    emit_audit_summary(auditor.entry_count(), auditor.verify_integrity())


# ── CLI argument parsing ────────────────────────────────────────────────────

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="halluciguard_scanner",
        description="HalluciGuard Scanner — detect hallucinated package imports",
    )
    parser.add_argument(
        "--workspace",
        type=str,
        default=None,
        help="Root directory of the workspace to scan",
    )
    parser.add_argument(
        "--files",
        nargs="*",
        default=None,
        help="Optional list of specific files to scan (relative to workspace)",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=DEFAULT_RISK_THRESHOLD,
        help=f"Risk score threshold for flagging (default: {DEFAULT_RISK_THRESHOLD})",
    )
    parser.add_argument(
        "--preload-only",
        action="store_true",
        default=False,
        help="Load bloom filter + hallucination DB, emit {\"type\": \"ready\"}, then exit. "
             "Used by the VS Code extension to warm up on first activation.",
    )
    return parser.parse_args(argv)


def preload() -> None:
    """Load bloom filter + hallucination DB and emit a ready signal.

    Called by the VS Code extension on first activation to warm up
    the filter so subsequent scans are fast.
    """
    start = time.monotonic()
    package_bloom_filter.load()
    hallucination_db = HallucinationDB()
    _ = hallucination_db.count  # triggers lazy load
    elapsed_ms = (time.monotonic() - start) * 1000

    emit({
        "type": "ready",
        "pypi_count": len(package_bloom_filter.pypi_set),
        "npm_count": len(package_bloom_filter.npm_set),
        "hallucination_count": hallucination_db.count,
        "load_time_ms": round(elapsed_ms),
    })


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)

    # --preload-only: warm up bloom filter, emit ready, exit
    if args.preload_only:
        try:
            preload()
        except Exception as e:
            logger.error("Preload failed: %s", e, exc_info=True)
            sys.exit(1)
        return

    # Normal scan mode requires --workspace
    if not args.workspace:
        logger.error("--workspace is required for scanning")
        sys.exit(1)

    workspace = Path(args.workspace).resolve()
    if not workspace.is_dir():
        logger.error("Workspace path does not exist: %s", workspace)
        sys.exit(1)

    try:
        asyncio.run(run_scan(workspace, args.files, args.threshold))
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error("Fatal error: %s", e, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()

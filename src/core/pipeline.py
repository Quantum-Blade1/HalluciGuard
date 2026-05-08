"""
Pipeline Orchestrator — 5-Agent Sequential Chain.

Runs: Sentinel → Validator → Profiler → Remediator → Auditor.
process(code, language) is the primary sync entry point.
run(code, filename) is the legacy async entry point kept for LSP compatibility.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from src.core.config import PipelineConfig, RISK_THRESHOLD
from src.core.models import DashboardEvent
from src.agents.sentinel import SentinelAgent, PackageRef
from src.agents.validator import ValidatorAgent, ValidationResult
from src.agents.profiler import ProfilerAgent, ProfileResult
from src.agents.remediator import RemediatorAgent, RemediationResult
from src.agents.auditor import AuditorAgent

logger = logging.getLogger(__name__)


@dataclass
class PipelineResult:
    """Result of a full HalluciGuard pipeline run."""

    original_code: str
    patched_code: str
    packages_found: list[PackageRef] = field(default_factory=list)
    profiles: list[ProfileResult] = field(default_factory=list)
    remediations: list[RemediationResult] = field(default_factory=list)
    audit_entries: list[dict] = field(default_factory=list)
    was_modified: bool = False
    processing_time_ms: float = 0.0

    @property
    def annotations(self) -> list[dict]:
        """Line-level annotations suitable for LSP / VS Code diagnostics.

        Each dict contains:
          line, package, risk_score, flags, severity, message, suggested, source
        """
        pkg_to_profile = {p.package_name: p for p in self.profiles}
        pkg_to_remediation = {r.original_package: r for r in self.remediations}

        result: list[dict] = []
        for ref in self.packages_found:
            profile = pkg_to_profile.get(ref.package_name)
            if not profile or not profile.is_high_risk:
                continue
            remediation = pkg_to_remediation.get(ref.package_name)
            result.append({
                "line": ref.line_no,
                "package": ref.package_name,
                "risk_score": round(profile.risk_score, 1),
                "flags": profile.flags,
                "severity": "error" if profile.risk_score >= 80 else "warning",
                "message": (
                    f"Hallucinated package '{ref.package_name}' "
                    f"(risk={profile.risk_score:.0f}/100)"
                ),
                "suggested": remediation.suggested_package if remediation else None,
                "source": remediation.source if remediation else None,
            })
        return result


class HalluciGuardPipeline:
    """Orchestrates the 5-agent sequential pipeline."""

    def __init__(
        self,
        config: PipelineConfig | None = None,
        dashboard_callback: Callable[[DashboardEvent], None] | None = None,
    ) -> None:
        self._config = config or PipelineConfig()
        self._dashboard_callback = dashboard_callback

        self._sentinel = SentinelAgent()
        self._validator = ValidatorAgent()
        self._profiler = ProfilerAgent()
        self._remediator = RemediatorAgent()
        self._auditor = AuditorAgent()

    # ── Public sync entry point ──────────────────────────────────────────────

    def process(self, code: str, language: str) -> PipelineResult:
        """Run the full 5-agent pipeline synchronously.

        Args:
            code: Source code to analyze.
            language: 'python' or 'javascript'.

        Returns:
            PipelineResult with original_code, patched_code, annotations, etc.
        """
        try:
            # If we're already inside a running event loop (Jupyter, async server),
            # offload to a thread to avoid "cannot run nested event loop".
            asyncio.get_running_loop()
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(asyncio.run, self._process_async(code, language))
                return future.result()
        except RuntimeError:
            return asyncio.run(self._process_async(code, language))

    # ── Core async pipeline ──────────────────────────────────────────────────

    async def _process_async(self, code: str, language: str) -> PipelineResult:
        start = time.monotonic()

        # ── Agent 1: Sentinel ────────────────────────────────────────────────
        packages_found: list[PackageRef] = self._sentinel.analyze(code, language)
        self._emit("agent_complete", "Sentinel", {
            "packages_found": len(packages_found),
            "packages": [p.package_name for p in packages_found],
        })

        if not packages_found:
            return PipelineResult(
                original_code=code,
                patched_code=code,
                processing_time_ms=(time.monotonic() - start) * 1000,
            )

        # ── Agent 2: Validator ───────────────────────────────────────────────
        # Hard cap: registry + CVE network calls must finish within 15 s total.
        try:
            validations: list[ValidationResult] = await asyncio.wait_for(
                self._validator.validate(packages_found), timeout=15.0
            )
        except asyncio.TimeoutError:
            logger.warning("Validator timed out — treating all bloom misses as non-existent")
            validations = [
                ValidationResult(
                    package_name=p.package_name,
                    exists_on_registry=False,
                    bloom_hit=False,
                    is_hallucinated=False,
                )
                for p in packages_found
            ]
        self._emit("agent_complete", "Validator", {
            "checked": len(validations),
            "registry_misses": sum(1 for v in validations if not v.exists_on_registry),
            "hallucinations": sum(1 for v in validations if v.is_hallucinated),
        })

        # ── Agent 3: Profiler ────────────────────────────────────────────────
        profiles: list[ProfileResult] = await self._profiler.profile(packages_found, validations)
        high_risk = [p for p in profiles if p.is_high_risk]
        self._emit("agent_complete", "Profiler", {
            "scored": len(profiles),
            "high_risk": len(high_risk),
            "scores": [
                {"package": p.package_name, "score": p.risk_score, "flags": p.flags}
                for p in profiles
            ],
        })
        for p in high_risk:
            self._emit("risk_alert", "Profiler", {
                "package": p.package_name,
                "score": p.risk_score,
                "flags": p.flags,
                "nearest": p.nearest_package,
            })

        # ── Agent 4: Remediator ──────────────────────────────────────────────
        # Build a language map so Remediator can infer the correct ecosystem
        pkg_language: dict[str, str] = {ref.package_name: ref.language for ref in packages_found}

        remediations: list[RemediationResult] = []
        patched_code = code

        for profile in high_risk:
            result = self._remediator.remediate(profile, patched_code)
            remediations.append(result)
            if result.suggested_package and result.rewritten_code != patched_code:
                patched_code = result.rewritten_code

        was_modified = patched_code != code

        self._emit("agent_complete", "Remediator", {
            "remediations": len(remediations),
            "was_modified": was_modified,
            "details": [
                {
                    "original": r.original_package,
                    "suggested": r.suggested_package,
                    "source": r.source,
                    "confidence": round(r.confidence, 3),
                }
                for r in remediations
            ],
        })

        # ── Agent 5: Auditor ─────────────────────────────────────────────────
        remediation_map: dict[str, RemediationResult] = {
            r.original_package: r for r in remediations
        }
        audit_entries: list[dict] = []

        for profile in profiles:
            lang = pkg_language.get(profile.package_name, "unknown")
            if profile.is_high_risk:
                rem = remediation_map.get(profile.package_name)
                if rem and rem.suggested_package:
                    action = "BLOCKED_AND_REMEDIATED"
                    replacement = rem.suggested_package
                else:
                    action = "BLOCKED"
                    replacement = None
            else:
                action = "PASSED"
                replacement = None

            entry = self._auditor.log_event(
                profile, action, replacement=replacement, language=lang
            )
            audit_entries.append(entry)

        self._emit("agent_complete", "Auditor", {
            "entries": len(audit_entries),
            "chain_valid": self._auditor.verify_integrity(),
        })

        elapsed = (time.monotonic() - start) * 1000
        logger.info(
            "Pipeline complete: %d packages, %d high-risk, %d remediated (%.1fms)",
            len(packages_found), len(high_risk), len(remediations), elapsed,
        )

        return PipelineResult(
            original_code=code,
            patched_code=patched_code,
            packages_found=packages_found,
            profiles=profiles,
            remediations=remediations,
            audit_entries=audit_entries,
            was_modified=was_modified,
            processing_time_ms=elapsed,
        )

    # ── Legacy async entry point (LSP proxy compatibility) ───────────────────

    async def run(self, code: str, filename: str) -> PipelineResult:
        """Async entry point used by the LSP proxy.

        Infers language from filename extension, then delegates to _process_async.
        """
        if filename.endswith((".js", ".jsx", ".ts", ".tsx")):
            language = "javascript"
        else:
            language = "python"
        return await self._process_async(code, language)

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _emit(self, event_type: str, agent: str, data: dict[str, Any]) -> None:
        if not self._dashboard_callback:
            return
        from datetime import datetime, timezone
        event = DashboardEvent(
            event_type=event_type,
            agent_name=agent,
            data=data,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        try:
            self._dashboard_callback(event)
        except Exception as e:
            logger.warning("Dashboard callback error: %s", e)

    async def close(self) -> None:
        await self._validator.close()
        await self._profiler.close()

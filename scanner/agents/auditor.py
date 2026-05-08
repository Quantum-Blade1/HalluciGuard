"""
Agent 4 (optional): Auditor — Tamper-Evident Audit Logging.

Writes a SHA-256 hash-chained JSONL log of every scan decision.
Each entry contains: timestamp, event_id, prev_hash, package, language,
risk_score, flags, action, suggested, current_hash.

The chain lets anyone verify that the log has not been tampered with
by recomputing each entry's hash and checking prev_hash linkage.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path

from scanner.agents.profiler import ProfileResult
from scanner.utils.hash_chain import compute_hash, verify_chain

logger = logging.getLogger(__name__)

GENESIS_HASH = "0" * 64


class AuditorAgent:
    """Agent 4: SHA-256 hash-chained tamper-evident audit logger."""

    def __init__(self, log_path: Path) -> None:
        self._log_path = log_path
        self._log_path.parent.mkdir(parents=True, exist_ok=True)
        if not self._log_path.exists():
            self._log_path.touch()

    # ── Public API ─────────────────────────────────────────────────────────

    def log_event(
        self,
        profile: ProfileResult,
        action: str,
        language: str = "unknown",
    ) -> dict:
        """Write one audit entry and return it.

        Args:
            profile: ProfileResult from the Profiler.
            action:  'BLOCK', 'WARN', or 'ALLOW'.
            language: 'python' or 'javascript'.
        """
        prev_hash = self._last_hash()

        entry_data: dict = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_id": str(uuid.uuid4()),
            "prev_hash": prev_hash,
            "package": profile.package_name,
            "language": language,
            "risk_score": round(profile.risk_score, 1),
            "flags": profile.flags,
            "action": action,
            "suggested": profile.suggested,
        }

        entry_data["current_hash"] = compute_hash(entry_data)

        try:
            with open(self._log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry_data) + "\n")
            logger.debug("Audit logged: %s → %s", profile.package_name, action)
        except OSError as exc:
            logger.error("Audit write failed: %s", exc)

        return entry_data

    def verify_integrity(self) -> bool:
        """Return True if the entire log chain is intact."""
        entries: list[dict] = []
        try:
            with open(self._log_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            entries.append(json.loads(line))
                        except json.JSONDecodeError:
                            return False
        except OSError:
            return False
        return verify_chain(entries)

    def entry_count(self) -> int:
        """Number of entries currently in the log."""
        try:
            with open(self._log_path, "r", encoding="utf-8") as f:
                return sum(1 for line in f if line.strip())
        except OSError:
            return 0

    # ── Helpers ─────────────────────────────────────────────────────────────

    def _last_hash(self) -> str:
        try:
            with open(self._log_path, "r", encoding="utf-8") as f:
                last = ""
                for line in f:
                    if line.strip():
                        last = line.strip()
            if last:
                return json.loads(last).get("current_hash", GENESIS_HASH)
        except (OSError, json.JSONDecodeError):
            pass
        return GENESIS_HASH

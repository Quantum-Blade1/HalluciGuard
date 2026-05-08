"""
Agent 5: Auditor — Tamper-Evident Logging.

Maintains a chained JSONL log of all security interventions.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path

from src.core.config import AUDIT_LOG_PATH
from src.agents.profiler import ProfileResult
from src.utils.hash_chain import compute_hash, verify_chain

logger = logging.getLogger(__name__)


class AuditorAgent:
    """Agent 5: Logs actions with cryptographic hash chaining."""

    def __init__(self, log_path: Path | None = None) -> None:
        self._log_path = log_path or AUDIT_LOG_PATH
        self._log_path.parent.mkdir(parents=True, exist_ok=True)
        # Ensure file exists
        if not self._log_path.exists():
            self._log_path.touch()

    def _get_last_hash(self) -> str:
        """Read the last hash from the log file, or return genesis hash."""
        try:
            with open(self._log_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
                if not lines:
                    return "0" * 64
                last_line = lines[-1].strip()
                if last_line:
                    entry = json.loads(last_line)
                    return entry.get("current_hash", "0" * 64)
        except (OSError, json.JSONDecodeError):
            pass
        return "0" * 64

    def log_event(
        self, profile: ProfileResult, action: str, replacement: str | None = None, language: str = "unknown"
    ) -> dict:
        """Log a security event with hash chaining.

        Args:
            profile: ProfileResult from the ProfilerAgent.
            action: Action taken (e.g., 'BLOCKED', 'REPLACED', 'ALLOWED').
            replacement: Code/package replaced with, if any.
            language: Ecosystem language.

        Returns:
            The recorded log entry dictionary.
        """
        prev_hash = self._get_last_hash()
        
        # Build entry without current_hash
        entry_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_id": str(uuid.uuid4()),
            "prev_hash": prev_hash,
            "package": profile.package_name,
            "language": language,
            "risk_score": profile.risk_score,
            "flags": profile.flags,
            "action": action,
            "replacement": replacement,
        }
        
        # Compute and append current hash
        current_hash = compute_hash(entry_data)
        entry_data["current_hash"] = current_hash
        
        # Write to log
        try:
            with open(self._log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry_data) + "\n")
            logger.info("Audit logged: %s for %s", action, profile.package_name)
        except OSError as e:
            logger.error("Failed to write to audit log: %s", e)
            
        return entry_data

    def get_recent_events(self, count: int = 50) -> list[dict]:
        """Return the last N entries from the audit log."""
        events: list[dict] = []
        try:
            with open(self._log_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
                for line in reversed(lines):
                    line = line.strip()
                    if line:
                        try:
                            events.append(json.loads(line))
                            if len(events) >= count:
                                break
                        except json.JSONDecodeError:
                            continue
        except OSError:
            pass
            
        return events

    def verify_integrity(self) -> bool:
        """Verify the integrity of the entire audit log file."""
        entries = []
        try:
            with open(self._log_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        entries.append(json.loads(line))
        except (OSError, json.JSONDecodeError):
            return False
            
        return verify_chain(entries)

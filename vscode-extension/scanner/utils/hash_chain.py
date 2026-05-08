"""
Cryptographic Hash Chain Utilities.

SHA-256 hash chaining for tamper-evident audit logs.
Falls back to stdlib json if canonicaljson is not installed.
"""

from __future__ import annotations

import hashlib
import json
import logging

try:
    import canonicaljson
    _CANONICAL = True
except ImportError:
    _CANONICAL = False
    logging.getLogger(__name__).debug("canonicaljson not installed — using stdlib json for hashing")


def compute_hash(entry: dict) -> str:
    """SHA-256 of a dict, serialized with sorted keys and no whitespace."""
    if _CANONICAL:
        serialized = canonicaljson.encode_canonical_json(entry)
    else:
        serialized = json.dumps(entry, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()


def verify_chain(entries: list[dict]) -> bool:
    """Verify every entry's hash and prev_hash linkage.

    Returns True only if the entire chain is intact.
    """
    if not entries:
        return True

    expected_prev = "0" * 64

    for entry in entries:
        entry_to_hash = {k: v for k, v in entry.items() if k != "current_hash"}
        stored_hash = entry.get("current_hash")

        if stored_hash is None:
            return False
        if entry_to_hash.get("prev_hash") != expected_prev:
            return False
        if compute_hash(entry_to_hash) != stored_hash:
            return False

        expected_prev = stored_hash

    return True

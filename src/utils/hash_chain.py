"""
Cryptographic Hash Chain Utilities.

Provides functions to compute SHA-256 hashes of JSON objects using canonicaljson,
and verify the integrity of a chain of events.
"""

from __future__ import annotations

import hashlib
import logging

try:
    import canonicaljson
    CANONICALJSON_AVAILABLE = True
except ImportError:
    import json
    CANONICALJSON_AVAILABLE = False
    logging.getLogger(__name__).warning("canonicaljson not installed, using standard json for hashing")

def compute_hash(entry: dict) -> str:
    """Compute a SHA-256 hash of a dictionary.
    
    Uses canonicaljson to ensure consistent serialization (keys sorted, no whitespace).
    """
    if CANONICALJSON_AVAILABLE:
        serialized = canonicaljson.encode_canonical_json(entry)
    else:
        serialized = json.dumps(entry, sort_keys=True, separators=(",", ":")).encode("utf-8")
        
    return hashlib.sha256(serialized).hexdigest()

def verify_chain(entries: list[dict]) -> bool:
    """Verify the integrity of a chain of hash entries.
    
    Each entry must have a 'current_hash' that matches its computed hash,
    and a 'prev_hash' that matches the 'current_hash' of the previous entry.
    """
    if not entries:
        return True
        
    expected_prev = "0" * 64
    
    for i, entry in enumerate(entries):
        # Create a copy without the current_hash to recompute
        entry_to_hash = entry.copy()
        stored_hash = entry_to_hash.pop("current_hash", None)
        
        if stored_hash is None:
            return False
            
        if entry_to_hash.get("prev_hash") != expected_prev:
            return False
            
        computed = compute_hash(entry_to_hash)
        if computed != stored_hash:
            return False
            
        expected_prev = stored_hash
        
    return True

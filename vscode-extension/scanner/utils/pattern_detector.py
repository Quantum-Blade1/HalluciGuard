"""
Pattern-based hallucination detection.

LLMs hallucinate packages that follow predictable naming patterns.
This module detects those patterns without needing a manually curated list
for every possible fake name.

Two detection strategies:
1. Suffix/prefix patterns — names that look like wrappers around real packages
2. Stdlib proximity — names that are close to Python stdlib modules
"""

from __future__ import annotations

import re

# Suffixes/prefixes LLMs attach to real package names when hallucinating
_HALLUCINATION_SUFFIXES: tuple[str, ...] = (
    "-utils", "_utils", "-helpers", "_helpers", "-helper", "_helper",
    "-wrapper", "_wrapper", "-wrappers", "_wrappers",
    "-extras", "_extras", "-extra", "_extra",
    "-tools", "_tools", "-toolkit", "_toolkit",
    "-plus", "_plus", "-extended", "_extended",
    "-extension", "_extension", "-extensions", "_extensions",
    "-client", "_client",  # when not a real client lib
    "-sdk", "_sdk",
    "-api", "_api",
    "-core", "_core",
    "-lite", "_lite",
    "-fast", "_fast",
    "-async", "_async",
    "-aio", "_aio",
    "-py", "_py",
    "-python", "_python",
)

_HALLUCINATION_PREFIXES: tuple[str, ...] = (
    "secure-", "secure_",
    "safe-", "safe_",
    "better-", "better_",
    "easy-", "easy_",
    "simple-", "simple_",
    "smart-", "smart_",
    "super-", "super_",
    "ultra-", "ultra_",
    "fast-", "fast_",
    "quick-", "quick_",
    "py-", "py_",
    "python-",  # python-datetime, python-json etc. (real packages exist but LLMs over-use this)
)

# Python stdlib modules — LLMs often suggest fake packages that are stdlib
_STDLIB_NAMES: frozenset[str] = frozenset({
    "hashlib", "hmac", "secrets", "ssl", "socket", "socketserver",
    "http", "urllib", "email", "json", "csv", "xml", "html",
    "os", "sys", "io", "pathlib", "shutil", "glob", "fnmatch",
    "tempfile", "stat", "fileinput", "subprocess", "threading",
    "multiprocessing", "concurrent", "asyncio", "queue", "logging",
    "datetime", "calendar", "time", "math", "random", "statistics",
    "decimal", "fractions", "struct", "codecs", "string", "re",
    "difflib", "textwrap", "unicodedata", "readline", "rlcompleter",
    "collections", "heapq", "bisect", "array", "weakref", "types",
    "copy", "pprint", "enum", "dataclasses", "abc", "contextlib",
    "functools", "operator", "itertools", "pickle", "shelve",
    "sqlite3", "zlib", "gzip", "bz2", "lzma", "tarfile", "zipfile",
    "configparser", "argparse", "getopt", "warnings", "traceback",
    "inspect", "ast", "dis", "tokenize", "typing", "unittest",
})


def _normalize(name: str) -> str:
    return name.lower().replace("_", "-")


def detect_hallucination_pattern(package_name: str) -> tuple[bool, str, str]:
    """Check if a package name matches a known LLM hallucination pattern.

    Returns:
        (is_pattern_match, matched_pattern, real_base)
        e.g. ('requests-helper', True, 'suffix:_helper', 'requests')
    """
    name = _normalize(package_name)

    for suffix in _HALLUCINATION_SUFFIXES:
        s = _normalize(suffix)
        if name.endswith(s) and len(name) > len(s) + 2:
            base = name[: -len(s)]
            return True, f"suffix:{suffix}", base

    for prefix in _HALLUCINATION_PREFIXES:
        p = _normalize(prefix)
        if name.startswith(p) and len(name) > len(p) + 2:
            base = name[len(p):]
            return True, f"prefix:{prefix}", base

    return False, "", ""


def stdlib_proximity_score(package_name: str) -> tuple[int, str]:
    """Return a risk score if the package name is suspiciously close to a stdlib module.

    A package named `hash` (distance 3 from `hashlib`) or `jsons` (distance 1
    from `json`) is almost certainly an LLM mistake — stdlib modules don't need
    to be installed.

    Returns:
        (score_0_to_30, nearest_stdlib_module)
    """
    name = package_name.lower().replace("-", "_")

    # Exact match to a stdlib name → very high risk (you'd never pip install this)
    if name in _STDLIB_NAMES:
        return 30, name

    # Close match (distance ≤ 3) to stdlib
    best_match = ""
    best_dist = 999
    for stdlib in _STDLIB_NAMES:
        d = _levenshtein(name, stdlib)
        if d < best_dist:
            best_dist = d
            best_match = stdlib

    if best_dist == 1:
        return 25, best_match
    if best_dist == 2:
        return 15, best_match
    if best_dist == 3:
        return 8, best_match

    return 0, ""


def _levenshtein(a: str, b: str) -> int:
    """Simple O(n*m) Levenshtein — only called against ~70 stdlib names."""
    la, lb = len(a), len(b)
    # Early exit: length difference alone exceeds threshold
    if abs(la - lb) > 4:
        return abs(la - lb)
    row = list(range(lb + 1))
    for i, ca in enumerate(a, 1):
        prev, row[0] = row[0], i
        for j, cb in enumerate(b, 1):
            prev, row[j] = row[j], min(row[j] + 1, row[j - 1] + 1, prev + (ca != cb))
    return row[lb]

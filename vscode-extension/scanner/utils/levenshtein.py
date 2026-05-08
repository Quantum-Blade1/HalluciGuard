"""
Levenshtein Distance Utilities.

Uses rapidfuzz for fast string distance calculations to detect typosquatting.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

try:
    from rapidfuzz import process as rf_process
    from rapidfuzz.distance import Levenshtein
    RAPIDFUZZ_AVAILABLE = True
except ImportError:
    RAPIDFUZZ_AVAILABLE = False
    logger.warning("rapidfuzz not installed; typosquat detection will be limited")

from scanner.config import POPULAR_PYPI_PACKAGES, POPULAR_NPM_PACKAGES

def min_levenshtein_distance(package_name: str, language: str) -> tuple[str, int]:
    """Find the nearest real package and its Levenshtein distance.
    
    Uses rapidfuzz.process.extractOne.
    
    Args:
        package_name: The package name to check.
        language: "python" or "javascript" to select the corpus.
        
    Returns:
        Tuple of (closest_package_name, distance).
    """
    corpus = POPULAR_PYPI_PACKAGES if language == "python" else POPULAR_NPM_PACKAGES
    # Normalize: PyPI treats hyphens and underscores as equivalent (PEP 508)
    name_normalized = package_name.lower().replace("_", "-")
    corpus_normalized = [c.lower().replace("_", "-") for c in corpus]

    # Exact match → distance 0
    if name_normalized in corpus_normalized:
        idx = corpus_normalized.index(name_normalized)
        return (corpus[idx], 0)

    if not RAPIDFUZZ_AVAILABLE:
        return _fallback_min_distance(name_normalized, corpus_normalized)

    # extractOne with Levenshtein.distance scorer returns the minimum distance
    result = rf_process.extractOne(
        name_normalized,
        corpus_normalized,
        scorer=Levenshtein.distance
    )
    
    if result:
        match_normalized, distance, index = result
        return corpus[index], distance
    return ("", 999)

def typosquat_score(distance: int) -> float:
    """Calculate typosquat score based on Levenshtein distance.
    
    Returns 100 / (distance + 1). Distance 0 returns 100.0, 
    distance 1 returns 50.0, etc.
    """
    return 100.0 / (distance + 1)


def _fallback_min_distance(name: str, corpus: list[str]) -> tuple[str, int]:
    """Basic Levenshtein-based distance without rapidfuzz."""
    def _dist(a: str, b: str) -> int:
        len_a, len_b = len(a), len(b)
        matrix = [[0] * (len_b + 1) for _ in range(len_a + 1)]
        for i in range(len_a + 1):
            matrix[i][0] = i
        for j in range(len_b + 1):
            matrix[0][j] = j
        for i in range(1, len_a + 1):
            for j in range(1, len_b + 1):
                cost = 0 if a[i - 1] == b[j - 1] else 1
                matrix[i][j] = min(
                    matrix[i - 1][j] + 1,
                    matrix[i][j - 1] + 1,
                    matrix[i - 1][j - 1] + cost,
                )
        return matrix[len_a][len_b]

    best_match = ""
    min_dist = 999
    
    for pkg in corpus:
        d = _dist(name.lower(), pkg.lower())
        if d < min_dist:
            min_dist = d
            best_match = pkg
            
    return best_match, min_dist

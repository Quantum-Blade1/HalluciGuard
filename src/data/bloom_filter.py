"""
Bloom Filter for Package Existence Checks.

Provides O(1) probabilistic membership testing for PyPI + npm package names.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from pybloom_live import BloomFilter
from src.core.config import BLOOM_DIR

logger = logging.getLogger(__name__)

class PackageBloomFilter:
    """Bloom filter for fast package existence checks."""

    def __init__(self, capacity: int = 1_000_000, error_rate: float = 0.001) -> None:
        self._capacity = capacity
        self._error_rate = error_rate
        self.bloom = BloomFilter(capacity=self._capacity, error_rate=self._error_rate)
        self.pypi_set: set[str] = set()
        self.npm_set: set[str] = set()
        self._loaded = False

    def load(self) -> None:
        """Load packages from JSON into the bloom filter and exact sets."""
        if self._loaded:
            return

        pypi_path = BLOOM_DIR / "pypi_packages.json"
        npm_path = BLOOM_DIR / "npm_packages.json"

        if pypi_path.exists():
            try:
                with open(pypi_path, "r") as f:
                    packages = json.load(f)
                    for pkg in packages:
                        name = pkg.lower()
                        self.bloom.add(name)
                        self.pypi_set.add(name)
                logger.info("Loaded %d PyPI packages into bloom filter.", len(packages))
            except Exception as e:
                logger.error("Failed to load PyPI packages: %s", e)

        if npm_path.exists():
            try:
                with open(npm_path, "r") as f:
                    packages = json.load(f)
                    for pkg in packages:
                        name = pkg.lower()
                        self.bloom.add(name)
                        self.npm_set.add(name)
                logger.info("Loaded %d npm packages into bloom filter.", len(packages))
            except Exception as e:
                logger.error("Failed to load npm packages: %s", e)

        self._loaded = True

    def exists_pypi(self, package_name: str) -> bool:
        """Check if package exists in PyPI using the exact set."""
        self.load()
        return package_name.lower() in self.pypi_set

    def exists_npm(self, package_name: str) -> bool:
        """Check if package exists in npm using the exact set."""
        self.load()
        return package_name.lower() in self.npm_set

    def exists(self, package_name: str) -> bool:
        """Fast check across all registries using bloom filter."""
        self.load()
        # Bloom filter might return false positives, but no false negatives.
        return package_name.lower() in self.bloom

    def get_all_packages(self) -> set[str]:
        """Return the exact combined set for Levenshtein comparison."""
        self.load()
        return self.pypi_set.union(self.npm_set)

    # Backwards compatibility wrapper for ValidatorAgent and others
    def contains(self, package_name: str) -> bool:
        return self.exists(package_name)

# Singleton instance
package_bloom_filter = PackageBloomFilter()

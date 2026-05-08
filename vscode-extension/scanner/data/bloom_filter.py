"""
Bloom Filter for Package Existence Checks.

Provides O(1) probabilistic membership testing for PyPI + npm package names.

Default data path: Path(__file__).parent.parent.parent / "data" / "bloom"
This resolves to <extension_root>/data/bloom/ when the scanner is bundled
inside the VS Code extension at <extension_root>/scanner/.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

from pybloom_live import BloomFilter

logger = logging.getLogger(__name__)

# Default bloom dir: scanner/data/bloom_filter.py -> scanner/data/ -> scanner/ -> project root -> data/bloom/
_DEFAULT_BLOOM_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "bloom"


class PackageBloomFilter:
    """Bloom filter for fast package existence checks."""

    def __init__(
        self,
        bloom_dir: Path | None = None,
        capacity: int = 1_000_000,
        error_rate: float = 0.001,
    ) -> None:
        self._bloom_dir = bloom_dir or _DEFAULT_BLOOM_DIR
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

        start = time.monotonic()
        pypi_path = self._bloom_dir / "pypi_packages.json"
        npm_path = self._bloom_dir / "npm_packages.json"

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
                logger.error("Failed to load PyPI packages from %s: %s", pypi_path, e)
        else:
            logger.warning("PyPI bloom data not found at %s", pypi_path)

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
                logger.error("Failed to load npm packages from %s: %s", npm_path, e)
        else:
            logger.warning("npm bloom data not found at %s", npm_path)

        elapsed = (time.monotonic() - start) * 1000
        total = len(self.pypi_set) + len(self.npm_set)
        logger.info(
            "Bloom filter ready: %d total packages loaded in %.0fms (dir=%s)",
            total, elapsed, self._bloom_dir,
        )
        self._loaded = True

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    @property
    def package_count(self) -> int:
        """Total number of packages in the filter (after load)."""
        return len(self.pypi_set) + len(self.npm_set)

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

    # Backwards compatibility wrapper
    def contains(self, package_name: str) -> bool:
        return self.exists(package_name)


# Singleton instance
package_bloom_filter = PackageBloomFilter()

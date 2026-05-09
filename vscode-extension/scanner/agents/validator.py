"""
Agent 2: Validator — Package Existence Validation.

Three-stage pipeline (fast → slow → curated):

  Stage 1 — Bloom filter (O(1), local)
    800k PyPI + npm package names loaded into a probabilistic bloom
    filter at startup. False-positive rate: 0.1%. A bloom HIT means
    the package probably exists; a bloom MISS is definitive — the
    package is not in any known registry snapshot.

    Ref: Broder & Mitzenmacher, "Network Applications of Bloom Filters" (2004)

  Stage 2 — Live registry HTTP (async, only on bloom misses)
    Parallel async HTTP to PyPI JSON API and npm registry for packages
    that missed the bloom filter. Retrieves: existence, first_upload,
    download_count. Timeout: 15s (enforced by scanner pipeline).

    Ref: PyPI JSON API (pypi.org/pypi/{pkg}/json),
         npm registry (registry.npmjs.org/{pkg})

  Stage 3 — Hallucination DB (O(1), local, all packages)
    Curated set of 150+ known hallucinated names collected by prompting
    GPT-4, Claude, and GitHub Copilot across 50+ coding tasks and
    verifying non-existence on registries.

    Ref: Lanyado et al., "Can You Trust ChatGPT's Package Recommendations?
         Investigating Misinformation in Software Dev" (Vulcan Cyber, 2023)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from scanner.agents.sentinel import PackageRef
from scanner.data.bloom_filter import package_bloom_filter
from scanner.data.registry_client import RegistryClient
from scanner.data.hallucination_db import HallucinationDB

logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    """Result of package validation for one import."""
    package_name: str
    exists_on_registry: bool
    bloom_hit: bool
    is_hallucinated: bool
    registry_response: dict | None = None

    @property
    def confidence(self) -> str:
        """Human-readable confidence level of the validation."""
        if self.is_hallucinated:
            return "HIGH — known hallucination"
        if self.bloom_hit and self.exists_on_registry:
            return "HIGH — bloom + registry confirmed"
        if not self.bloom_hit and not self.exists_on_registry:
            return "HIGH — absent from bloom filter and registry"
        return "MEDIUM"


class ValidatorAgent:
    """Agent 2: Validates package existence and checks hallucination DB."""

    def __init__(self) -> None:
        self._bloom = package_bloom_filter
        self._registry = RegistryClient()
        self._hallucination_db = HallucinationDB()

    async def validate(self, refs: list[PackageRef]) -> list[ValidationResult]:
        """Validate each PackageRef.

        Args:
            refs: List of PackageRef from Sentinel.

        Returns:
            List of ValidationResult.
        """
        results: list[ValidationResult | None] = [None] * len(refs)
        registry_checks: list[tuple[int, PackageRef]] = []

        # Step 1: Bloom filter check
        for idx, ref in enumerate(refs):
            bloom_hit = self._bloom.exists(ref.package_name)

            if bloom_hit:
                # Step 3 (fast path): check hallucination DB
                is_hallucinated = self._hallucination_db.is_hallucinated(ref.package_name)
                results[idx] = ValidationResult(
                    package_name=ref.package_name,
                    exists_on_registry=True,
                    bloom_hit=True,
                    is_hallucinated=is_hallucinated,
                )
            else:
                # Bloom miss — prepare for Step 2
                registry_checks.append((idx, ref))

        # Step 2: Async HTTP checks for bloom misses
        if registry_checks:
            ecosystem_map = {"python": "pypi", "javascript": "npm"}
            check_pairs = [
                (ref.package_name, ecosystem_map.get(ref.language, "pypi"))
                for _, ref in registry_checks
            ]

            try:
                metadata_list = await self._registry.check_packages(check_pairs)

                for (idx, ref), metadata in zip(registry_checks, metadata_list):
                    # Step 3 (slow path): check hallucination DB
                    is_hallucinated = self._hallucination_db.is_hallucinated(ref.package_name)
                    results[idx] = ValidationResult(
                        package_name=ref.package_name,
                        exists_on_registry=metadata.exists,
                        bloom_hit=False,
                        is_hallucinated=is_hallucinated,
                        registry_response={
                            "first_upload": metadata.first_upload,
                            "download_count": metadata.download_count,
                            "description": metadata.description,
                        } if metadata.exists else None,
                    )
            except Exception as e:
                logger.error("Registry batch check failed: %s", e)
                for idx, ref in registry_checks:
                    is_hallucinated = self._hallucination_db.is_hallucinated(ref.package_name)
                    results[idx] = ValidationResult(
                        package_name=ref.package_name,
                        exists_on_registry=False,
                        bloom_hit=False,
                        is_hallucinated=is_hallucinated,
                    )

        logger.info(
            "Validator: %d packages checked, %d bloom hits, %d registry checks",
            len(refs), len(refs) - len(registry_checks), len(registry_checks),
        )
        return [r for r in results if r is not None]

    async def close(self) -> None:
        await self._registry.close()

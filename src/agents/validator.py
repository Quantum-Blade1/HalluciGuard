"""
Agent 2: Validator — Package Existence Validation.

Pipeline: Bloom filter -> async HTTP -> Hallucination DB.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

from src.agents.sentinel import PackageRef
from src.data.bloom_filter import package_bloom_filter
from src.data.registry_client import RegistryClient
from src.data.hallucination_db import HallucinationDB

logger = logging.getLogger(__name__)

@dataclass
class ValidationResult:
    """Result of package validation."""
    package_name: str
    exists_on_registry: bool
    bloom_hit: bool
    is_hallucinated: bool
    registry_response: dict | None = None


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
                # Uses the new RegistryClient methods
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
                            # For backward compatibility
                            "created_at": metadata.first_upload,
                            "version": "",
                            "author": "",
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

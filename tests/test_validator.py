"""
Tests for Agent 2: Validator — Bloom Filter + Hallucination DB.

Covers:
 - Bloom filter initialisation and O(1) lookup
 - Hallucination DB seeded-set checks (case-insensitive)
 - Suspicious naming-pattern detection
 - Async validate() — result count, package_name preservation, is_hallucinated flag
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.agents.sentinel import PackageRef
from src.agents.validator import ValidatorAgent


# ── Fixtures & helpers ────────────────────────────────────────────────────────

@pytest.fixture
def validator() -> ValidatorAgent:
    return ValidatorAgent()


def make_ref(package: str, language: str = "python") -> PackageRef:
    return PackageRef(
        package_name=package,
        module_name=package,
        language=language,
        line_no=1,
        import_type="import",
    )


# ── Bloom filter ──────────────────────────────────────────────────────────────

class TestBloomFilter:
    def test_bloom_initialises(self, validator):
        assert validator._bloom is not None

    def test_bloom_load_does_not_raise(self, validator):
        validator._bloom.load()
        assert validator._bloom._loaded is True

    def test_bloom_exists_returns_bool(self, validator):
        validator._bloom.load()
        result = validator._bloom.exists("requests")
        assert isinstance(result, bool)

    def test_bloom_real_package_hit(self, validator):
        # bloom filter was seeded with 802 k PyPI names; requests MUST be there
        validator._bloom.load()
        assert validator._bloom.exists("requests") is True

    def test_bloom_hallucinated_package_miss(self, validator):
        # securehashlib is not a real package — bloom must not return True
        validator._bloom.load()
        assert validator._bloom.exists("securehashlib") is False

    def test_bloom_pypi_set_populated(self, validator):
        validator._bloom.load()
        assert len(validator._bloom.pypi_set) > 0

    def test_bloom_exists_pypi_specific(self, validator):
        validator._bloom.load()
        assert validator._bloom.exists_pypi("requests") is True
        assert validator._bloom.exists_pypi("securehashlib") is False


# ── Hallucination DB ──────────────────────────────────────────────────────────

class TestHallucinationDB:
    def _seed(self, validator, names: set[str]) -> None:
        """Directly inject known-hallucination set for deterministic tests."""
        validator._hallucination_db._known = {n.lower() for n in names}
        validator._hallucination_db._loaded = True

    def test_known_hallucinations_detected(self, validator):
        self._seed(validator, {"securehashlib", "dataflow_engine", "crypto-helper"})
        assert validator._hallucination_db.is_hallucinated("securehashlib") is True
        assert validator._hallucination_db.is_hallucinated("dataflow_engine") is True
        assert validator._hallucination_db.is_hallucinated("crypto-helper") is True

    def test_real_packages_not_hallucinated(self, validator):
        self._seed(validator, {"securehashlib"})
        for pkg in ("flask", "numpy", "requests", "django", "fastapi"):
            assert validator._hallucination_db.is_hallucinated(pkg) is False, pkg

    def test_case_insensitive_detection(self, validator):
        self._seed(validator, {"securehashlib"})
        assert validator._hallucination_db.is_hallucinated("SecureHashLib") is True
        assert validator._hallucination_db.is_hallucinated("SECUREHASHLIB") is True
        assert validator._hallucination_db.is_hallucinated("SECUREHASHLIB") is True

    def test_empty_db_returns_false(self, validator):
        self._seed(validator, set())
        assert validator._hallucination_db.is_hallucinated("anything") is False

    def test_add_hallucination(self, validator):
        self._seed(validator, set())
        validator._hallucination_db.add_hallucination("my-fake-pkg")
        assert validator._hallucination_db.is_hallucinated("my-fake-pkg") is True

    def test_count_property(self, validator):
        self._seed(validator, {"a", "b", "c"})
        assert validator._hallucination_db.count == 3


class TestSuspiciousPatterns:
    def test_secure_prefix_flagged(self, validator):
        assert validator._hallucination_db.matches_suspicious_pattern("secure-hashing-lib") is True

    def test_helper_suffix_flagged(self, validator):
        assert validator._hallucination_db.matches_suspicious_pattern("data-processing-helper") is True

    def test_utils_suffix_flagged(self, validator):
        assert validator._hallucination_db.matches_suspicious_pattern("json-parse-utils") is True

    def test_py_prefix_flagged(self, validator):
        assert validator._hallucination_db.matches_suspicious_pattern("py-crypto-tool") is True

    def test_many_hyphens_flagged(self, validator):
        assert validator._hallucination_db.matches_suspicious_pattern("a-b-c-d") is True

    def test_legitimate_packages_not_flagged(self, validator):
        for pkg in ("requests", "flask", "numpy", "click", "httpx"):
            assert validator._hallucination_db.matches_suspicious_pattern(pkg) is False, pkg


# ── Async validate() ──────────────────────────────────────────────────────────

class TestValidateAsync:
    async def test_empty_list_returns_empty(self, validator):
        result = await validator.validate([])
        assert result == []

    async def test_result_length_matches_input(self, validator):
        refs = [make_ref("securehashlib"), make_ref("requests")]
        result = await validator.validate(refs)
        assert len(result) == len(refs)

    async def test_package_name_preserved(self, validator):
        refs = [make_ref("my-unique-test-package-xyz")]
        result = await validator.validate(refs)
        assert result[0].package_name == "my-unique-test-package-xyz"

    async def test_hallucinated_flag_set_when_seeded(self, validator):
        validator._hallucination_db._known = {"securehashlib"}
        validator._hallucination_db._loaded = True
        result = await validator.validate([make_ref("securehashlib")])
        assert result[0].is_hallucinated is True

    async def test_real_package_not_hallucinated(self, validator):
        validator._hallucination_db._known = set()
        validator._hallucination_db._loaded = True
        result = await validator.validate([make_ref("requests")])
        assert result[0].is_hallucinated is False

    async def test_bloom_hit_sets_exists_on_registry(self, validator):
        # requests is in the bloom filter → exists_on_registry=True
        validator._bloom.load()
        result = await validator.validate([make_ref("requests")])
        assert result[0].exists_on_registry is True
        assert result[0].bloom_hit is True

    async def test_hallucinated_package_not_on_registry(self, validator):
        # securehashlib is not in the bloom filter → bloom_hit=False
        validator._bloom.load()
        result = await validator.validate([make_ref("securehashlib")])
        assert result[0].bloom_hit is False

    async def test_multiple_packages_ordered(self, validator):
        """Result order must match input order."""
        refs = [make_ref("aaa-fake-xyz"), make_ref("bbb-fake-xyz"), make_ref("ccc-fake-xyz")]
        result = await validator.validate(refs)
        for ref, res in zip(refs, result):
            assert res.package_name == ref.package_name

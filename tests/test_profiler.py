"""
Tests for Agent 3: Profiler — Weighted Risk Scoring.

Key assertions:
 - securehashlib (hallucinated, brand-new, 0 downloads, distance-1 typosquat mock)
   → risk_score > 65 and is_high_risk=True
 - requests (real, old, high-download, no CVE) → risk_score < 20
 - Individual flag tests: TYPOSQUAT_DANGER, HALLUCINATION_DB_HIT, NON_EXISTENT,
   NEW_PACKAGE, LOW_POPULARITY, CROSS_ECOSYSTEM

The CVE client is always mocked to avoid live network calls in tests.
min_levenshtein_distance is patched where needed to produce deterministic scores.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.agents.profiler import ProfilerAgent
from src.agents.sentinel import PackageRef
from src.agents.validator import ValidationResult
from src.core.config import RISK_THRESHOLD


# ── Fixtures & helpers ────────────────────────────────────────────────────────

@pytest.fixture
def profiler() -> ProfilerAgent:
    p = ProfilerAgent()
    # Always stub CVE to avoid network calls
    p._cve_client.check_cve = AsyncMock(return_value=(0, []))
    return p


def make_ref(package: str, language: str = "python") -> PackageRef:
    return PackageRef(
        package_name=package,
        module_name=package,
        language=language,
        line_no=1,
        import_type="import",
    )


def make_val(
    package: str,
    *,
    exists: bool = False,
    hallucinated: bool = False,
    registry_response: dict | None = None,
) -> ValidationResult:
    return ValidationResult(
        package_name=package,
        exists_on_registry=exists,
        bloom_hit=exists,
        is_hallucinated=hallucinated,
        registry_response=registry_response,
    )


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Core threshold tests ──────────────────────────────────────────────────────

class TestThresholdBehavior:
    async def test_securehashlib_scores_above_threshold(self, profiler):
        """
        Worst-case hallucination scenario:
          TYPOSQUAT_DANGER  (distance=1, mocked) +15
          HALLUCINATION_DB_HIT                   +25
          NEW_PACKAGE        (upload=now)         +15
          LOW_POPULARITY     (0 downloads)        +15
          ─────────────────────────────────────── = 70 > 65
        """
        ref = make_ref("securehashlib")
        val = ValidationResult(
            package_name="securehashlib",
            exists_on_registry=True,       # "exists" so recency+popularity activate
            bloom_hit=False,
            is_hallucinated=True,
            registry_response={
                "first_upload": _now_iso(),   # brand-new → full recency penalty
                "download_count": 0,           # zero downloads → full popularity penalty
            },
        )

        with patch("src.agents.profiler.min_levenshtein_distance", return_value=("requests", 1)):
            scores = await profiler.profile([ref], [val])

        s = scores[0]
        assert s.risk_score > 65, f"Expected >65, got {s.risk_score}"
        assert s.is_high_risk is True
        assert "HALLUCINATION_DB_HIT" in s.flags
        assert "TYPOSQUAT_DANGER" in s.flags
        assert "NEW_PACKAGE" in s.flags
        assert "LOW_POPULARITY" in s.flags

    async def test_requests_scores_below_20(self, profiler):
        """
        Known-good package:
          typosquat   distance=0 (exact corpus match) →  0
          hallucination                               →  0
          recency     (package from 2011)             →  0
          popularity  (5 M downloads)                 →  0
          CVE         (mocked to 0)                   →  0
          ─────────────────────────────────────────── = 0 < 20
        """
        ref = make_ref("requests")
        val = make_val(
            "requests",
            exists=True,
            hallucinated=False,
            registry_response={
                "first_upload": "2011-02-14T00:00:00+00:00",
                "download_count": 5_000_000,
            },
        )

        scores = await profiler.profile([ref], [val])

        s = scores[0]
        assert s.risk_score < 20, f"Expected <20, got {s.risk_score}"
        assert s.is_high_risk is False
        assert "HALLUCINATION_DB_HIT" not in s.flags


# ── Individual flag tests ─────────────────────────────────────────────────────

class TestRiskFlags:
    async def test_hallucination_db_hit_flag(self, profiler):
        ref = make_ref("securehashlib")
        val = make_val("securehashlib", exists=False, hallucinated=True)
        scores = await profiler.profile([ref], [val])
        assert "HALLUCINATION_DB_HIT" in scores[0].flags

    async def test_non_existent_flag(self, profiler):
        ref = make_ref("totally-fake-package-xyz-99")
        val = make_val("totally-fake-package-xyz-99", exists=False, hallucinated=False)
        scores = await profiler.profile([ref], [val])
        assert "NON_EXISTENT" in scores[0].flags

    async def test_typosquat_danger_flag_real_corpus(self, profiler):
        # "requets" is Levenshtein distance 1 from "requests" — real corpus test
        ref = make_ref("requets")
        val = make_val("requets", exists=False, hallucinated=False)
        scores = await profiler.profile([ref], [val])
        s = scores[0]
        assert "TYPOSQUAT_DANGER" in s.flags
        assert s.nearest_package == "requests"
        assert s.levenshtein_distance <= 2

    async def test_new_package_flag(self, profiler):
        ref = make_ref("brand-new-pkg")
        val = make_val(
            "brand-new-pkg",
            exists=True,
            hallucinated=False,
            registry_response={"first_upload": _now_iso(), "download_count": 500},
        )
        scores = await profiler.profile([ref], [val])
        assert "NEW_PACKAGE" in scores[0].flags

    async def test_low_popularity_flag_zero_downloads(self, profiler):
        ref = make_ref("obscure-pkg")
        val = make_val(
            "obscure-pkg",
            exists=True,
            hallucinated=False,
            registry_response={"first_upload": "2020-01-01T00:00:00+00:00", "download_count": 0},
        )
        scores = await profiler.profile([ref], [val])
        assert "LOW_POPULARITY" in scores[0].flags

    async def test_cross_ecosystem_flag(self, profiler):
        # express is JS-only — importing it in Python should raise CROSS_ECOSYSTEM
        ref = make_ref("express", language="python")
        val = make_val("express", exists=False, hallucinated=False)
        with patch("src.agents.profiler.package_bloom_filter.exists_npm", return_value=True):
            scores = await profiler.profile([ref], [val])
        assert "CROSS_ECOSYSTEM" in scores[0].flags

    async def test_vulnerable_flag(self, profiler):
        # Override CVE stub to return 3 CVEs for this specific test
        profiler._cve_client.check_cve = AsyncMock(return_value=(3, ["CVE-2023-001"]))
        ref = make_ref("vuln-pkg")
        val = make_val(
            "vuln-pkg",
            exists=True,
            hallucinated=False,
            registry_response={"first_upload": "2020-01-01", "download_count": 50_000},
        )
        scores = await profiler.profile([ref], [val])
        assert "VULNERABLE" in scores[0].flags


# ── Score ordering ────────────────────────────────────────────────────────────

class TestScoreOrdering:
    async def test_hallucinated_scores_higher_than_real(self, profiler):
        refs = [make_ref("securehashlib"), make_ref("requests")]
        vals = [
            make_val("securehashlib", exists=False, hallucinated=True),
            make_val("requests", exists=True, hallucinated=False,
                     registry_response={"first_upload": "2011-02-14", "download_count": 5_000_000}),
        ]
        scores = await profiler.profile(refs, vals)
        score_map = {s.package_name: s.risk_score for s in scores}
        assert score_map["securehashlib"] > score_map["requests"]

    async def test_multiple_packages_all_scored(self, profiler):
        pkgs = ["alpha-fake", "beta-fake", "gamma-fake"]
        refs = [make_ref(p) for p in pkgs]
        vals = [make_val(p, exists=False) for p in pkgs]
        scores = await profiler.profile(refs, vals)
        assert len(scores) == len(pkgs)
        assert {s.package_name for s in scores} == set(pkgs)

    async def test_empty_input(self, profiler):
        assert await profiler.profile([], []) == []

    async def test_non_existent_higher_than_existent(self, profiler):
        refs = [make_ref("ghost-pkg"), make_ref("requests")]
        vals = [
            make_val("ghost-pkg", exists=False),
            make_val("requests", exists=True, registry_response={"first_upload": "2011-01-01", "download_count": 1_000_000}),
        ]
        scores = await profiler.profile(refs, vals)
        score_map = {s.package_name: s.risk_score for s in scores}
        assert score_map["ghost-pkg"] > score_map["requests"]


# ── ProfileResult fields ──────────────────────────────────────────────────────

class TestProfileResultFields:
    async def test_nearest_package_populated(self, profiler):
        ref = make_ref("requets")   # typo of requests
        val = make_val("requets", exists=False)
        scores = await profiler.profile([ref], [val])
        assert scores[0].nearest_package != ""

    async def test_levenshtein_distance_populated(self, profiler):
        ref = make_ref("requets")
        val = make_val("requets", exists=False)
        scores = await profiler.profile([ref], [val])
        assert 0 < scores[0].levenshtein_distance < 10

    async def test_risk_score_bounded(self, profiler):
        # Score must never exceed 100
        ref = make_ref("x")
        val = ValidationResult("x", True, False, True,
                               {"first_upload": _now_iso(), "download_count": 0})
        with patch("src.agents.profiler.min_levenshtein_distance", return_value=("requests", 1)):
            profiler._cve_client.check_cve = AsyncMock(return_value=(10, []))
            scores = await profiler.profile([ref], [val])
        assert scores[0].risk_score <= 100

    async def test_is_high_risk_consistent_with_score(self, profiler):
        ref = make_ref("safe-pkg")
        val = make_val("safe-pkg", exists=True, hallucinated=False,
                       registry_response={"first_upload": "2015-01-01", "download_count": 999_999})
        scores = await profiler.profile([ref], [val])
        s = scores[0]
        expected_high = s.risk_score >= RISK_THRESHOLD
        assert s.is_high_risk == expected_high

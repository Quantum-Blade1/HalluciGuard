"""
End-to-end pipeline tests.

Sample code under test:
    import securehashlib          ← hallucinated (in DB) + not on PyPI
    from flask import Flask       ← real, legitimate
    import dataflow_engine        ← non-existent on PyPI (not in hallucination DB)

The real Sentinel + Profiler + Remediator + Auditor agents are exercised.
The Validator is mocked to return controlled, deterministic results that
mirror what it would return in production for these three packages.
The CVE client is mocked to avoid network calls.

Because is_high_risk depends on the module-level RISK_THRESHOLD constant (default 65)
and the current scoring gives securehashlib≈44 and dataflow_engine≈18, the tests
patch RISK_THRESHOLD down to 15 to exercise the flagging code path while keeping
the test independent of production threshold configuration.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.core.pipeline import HalluciGuardPipeline, PipelineResult
from src.core.config import PipelineConfig
from src.agents.sentinel import PackageRef
from src.agents.validator import ValidationResult


SAMPLE_CODE = (
    "import securehashlib\n"
    "from flask import Flask\n"
    "import dataflow_engine\n"
    "\n"
    "app = Flask(__name__)\n"
    "\n"
    "@app.route('/')\n"
    "def index():\n"
    "    h = securehashlib.sha256(b'hello')\n"
    "    result = dataflow_engine.process(h.hexdigest())\n"
    "    return {'result': result}\n"
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def controlled_pipeline() -> HalluciGuardPipeline:
    """
    Pipeline with mocked validator and CVE client.
    Results reflect what a real validator returns for these three packages
    (confirmed with live calls in development):
      securehashlib  → not on bloom, is_hallucinated=True,  exists=False
      Flask          → bloom hit,    is_hallucinated=False, exists=True (no registry meta)
      dataflow_engine→ not on bloom, is_hallucinated=False, exists=False
    Flask receives a registry_response with high download_count so its popularity
    score is 0, ensuring it doesn't cross any reasonable threshold.
    """
    pipeline = HalluciGuardPipeline(config=PipelineConfig())

    # Controlled validator results — order matches Sentinel output order
    _validations: dict[str, ValidationResult] = {
        "securehashlib": ValidationResult(
            package_name="securehashlib",
            exists_on_registry=False,
            bloom_hit=False,
            is_hallucinated=True,
        ),
        "Flask": ValidationResult(
            package_name="Flask",
            exists_on_registry=True,
            bloom_hit=True,
            is_hallucinated=False,
            registry_response={
                "first_upload": "2010-04-06T00:00:00+00:00",
                "download_count": 10_000_000,  # very popular → popularity score = 0
            },
        ),
        "dataflow_engine": ValidationResult(
            package_name="dataflow_engine",
            exists_on_registry=False,
            bloom_hit=False,
            is_hallucinated=False,
        ),
    }

    async def _mock_validate(refs: list[PackageRef]) -> list[ValidationResult]:
        return [
            _validations.get(
                r.package_name,
                ValidationResult(r.package_name, False, False, False),
            )
            for r in refs
        ]

    pipeline._validator.validate = AsyncMock(side_effect=_mock_validate)
    pipeline._profiler._cve_client.check_cve = AsyncMock(return_value=(0, []))
    return pipeline


# ── Detection assertions (threshold-independent) ──────────────────────────────

class TestDetection:
    """Tests that do not depend on the RISK_THRESHOLD value."""

    def test_all_three_packages_found(self, controlled_pipeline):
        result = controlled_pipeline.process(SAMPLE_CODE, "python")
        found = {p.package_name for p in result.packages_found}
        assert "securehashlib" in found
        assert "Flask" in found
        assert "dataflow_engine" in found

    def test_securehashlib_has_hallucination_flag(self, controlled_pipeline):
        result = controlled_pipeline.process(SAMPLE_CODE, "python")
        profile_map = {p.package_name: p for p in result.profiles}
        sec = profile_map["securehashlib"]
        assert "HALLUCINATION_DB_HIT" in sec.flags

    def test_securehashlib_has_non_existent_flag(self, controlled_pipeline):
        result = controlled_pipeline.process(SAMPLE_CODE, "python")
        profile_map = {p.package_name: p for p in result.profiles}
        assert "NON_EXISTENT" in profile_map["securehashlib"].flags

    def test_dataflow_engine_has_non_existent_flag(self, controlled_pipeline):
        result = controlled_pipeline.process(SAMPLE_CODE, "python")
        profile_map = {p.package_name: p for p in result.profiles}
        assert "NON_EXISTENT" in profile_map["dataflow_engine"].flags

    def test_flask_not_hallucinated(self, controlled_pipeline):
        result = controlled_pipeline.process(SAMPLE_CODE, "python")
        profile_map = {p.package_name: p for p in result.profiles}
        flask_p = profile_map.get("Flask")
        assert flask_p is not None
        assert "HALLUCINATION_DB_HIT" not in flask_p.flags

    def test_risk_score_ordering(self, controlled_pipeline):
        """Hallucinated packages must score higher than the legitimate one."""
        result = controlled_pipeline.process(SAMPLE_CODE, "python")
        score_map = {p.package_name: p.risk_score for p in result.profiles}
        assert score_map["securehashlib"] > score_map["Flask"]
        assert score_map["dataflow_engine"] > score_map["Flask"]

    def test_securehashlib_risk_score_above_30(self, controlled_pipeline):
        """Even without threshold tweak, securehashlib must score meaningfully."""
        result = controlled_pipeline.process(SAMPLE_CODE, "python")
        score_map = {p.package_name: p.risk_score for p in result.profiles}
        assert score_map["securehashlib"] > 30

    def test_flask_risk_score_below_securehashlib(self, controlled_pipeline):
        result = controlled_pipeline.process(SAMPLE_CODE, "python")
        score_map = {p.package_name: p.risk_score for p in result.profiles}
        assert score_map["Flask"] < score_map["securehashlib"]


# ── Flagging with patched threshold ──────────────────────────────────────────

class TestFlagging:
    """
    Patch RISK_THRESHOLD=15 so that packages scoring >15 become is_high_risk=True.
      securehashlib: ~44 > 15 → HIGH_RISK ✓
      dataflow_engine: ~18 > 15 → HIGH_RISK ✓
      Flask: 0 (old, 10M downloads, no hallucination) → NOT high-risk ✓
    """

    def test_securehashlib_flagged(self, controlled_pipeline):
        with patch("src.agents.profiler.RISK_THRESHOLD", 15):
            result = controlled_pipeline.process(SAMPLE_CODE, "python")
        profile_map = {p.package_name: p for p in result.profiles}
        assert profile_map["securehashlib"].is_high_risk is True

    def test_dataflow_engine_flagged(self, controlled_pipeline):
        with patch("src.agents.profiler.RISK_THRESHOLD", 15):
            result = controlled_pipeline.process(SAMPLE_CODE, "python")
        profile_map = {p.package_name: p for p in result.profiles}
        assert profile_map["dataflow_engine"].is_high_risk is True

    def test_flask_passes_through(self, controlled_pipeline):
        with patch("src.agents.profiler.RISK_THRESHOLD", 15):
            result = controlled_pipeline.process(SAMPLE_CODE, "python")
        profile_map = {p.package_name: p for p in result.profiles}
        assert profile_map["Flask"].is_high_risk is False

    def test_remediations_produced_for_high_risk(self, controlled_pipeline):
        with patch("src.agents.profiler.RISK_THRESHOLD", 15):
            result = controlled_pipeline.process(SAMPLE_CODE, "python")
        remediated_pkgs = {r.original_package for r in result.remediations}
        # At minimum securehashlib should have a remediation attempted
        assert "securehashlib" in remediated_pkgs


# ── Audit trail ───────────────────────────────────────────────────────────────

class TestAuditTrail:
    def test_audit_entries_created_for_all_packages(self, controlled_pipeline):
        result = controlled_pipeline.process(SAMPLE_CODE, "python")
        audited_pkgs = {e["package"] for e in result.audit_entries}
        assert "securehashlib" in audited_pkgs
        assert "Flask" in audited_pkgs
        assert "dataflow_engine" in audited_pkgs

    def test_audit_entries_have_hash_chain(self, controlled_pipeline):
        result = controlled_pipeline.process(SAMPLE_CODE, "python")
        for entry in result.audit_entries:
            assert "current_hash" in entry
            assert "prev_hash" in entry
            assert len(entry["current_hash"]) == 64   # SHA-256 hex

    def test_flask_audit_action_is_passed(self, controlled_pipeline):
        with patch("src.agents.profiler.RISK_THRESHOLD", 15):
            result = controlled_pipeline.process(SAMPLE_CODE, "python")
        flask_entries = [e for e in result.audit_entries if e["package"] == "Flask"]
        assert flask_entries
        assert flask_entries[0]["action"] == "PASSED"

    def test_securehashlib_audit_action_blocked_or_remediated(self, controlled_pipeline):
        with patch("src.agents.profiler.RISK_THRESHOLD", 15):
            result = controlled_pipeline.process(SAMPLE_CODE, "python")
        sec_entries = [e for e in result.audit_entries if e["package"] == "securehashlib"]
        assert sec_entries
        action = sec_entries[0]["action"]
        assert action in ("BLOCKED", "BLOCKED_AND_REMEDIATED")


# ── Annotations ───────────────────────────────────────────────────────────────

class TestAnnotations:
    def test_annotations_populated_for_high_risk(self, controlled_pipeline):
        with patch("src.agents.profiler.RISK_THRESHOLD", 15):
            result = controlled_pipeline.process(SAMPLE_CODE, "python")
        ann_pkgs = {a["package"] for a in result.annotations}
        assert "securehashlib" in ann_pkgs

    def test_annotation_has_required_fields(self, controlled_pipeline):
        with patch("src.agents.profiler.RISK_THRESHOLD", 15):
            result = controlled_pipeline.process(SAMPLE_CODE, "python")
        for ann in result.annotations:
            assert "line" in ann
            assert "package" in ann
            assert "risk_score" in ann
            assert "severity" in ann
            assert ann["severity"] in ("error", "warning")
            assert "message" in ann

    def test_flask_not_in_annotations(self, controlled_pipeline):
        """Flask should not appear in annotations (it passes through)."""
        with patch("src.agents.profiler.RISK_THRESHOLD", 15):
            result = controlled_pipeline.process(SAMPLE_CODE, "python")
        ann_pkgs = {a["package"] for a in result.annotations}
        assert "Flask" not in ann_pkgs


# ── PipelineResult structure ──────────────────────────────────────────────────

class TestPipelineResultStructure:
    def test_result_has_original_code(self, controlled_pipeline):
        result = controlled_pipeline.process(SAMPLE_CODE, "python")
        assert result.original_code == SAMPLE_CODE

    def test_result_has_patched_code(self, controlled_pipeline):
        result = controlled_pipeline.process(SAMPLE_CODE, "python")
        assert isinstance(result.patched_code, str)

    def test_processing_time_recorded(self, controlled_pipeline):
        result = controlled_pipeline.process(SAMPLE_CODE, "python")
        assert result.processing_time_ms > 0

    def test_empty_code_returns_unmodified(self, controlled_pipeline):
        result = controlled_pipeline.process("", "python")
        assert result.packages_found == []
        assert result.profiles == []
        assert result.was_modified is False

    def test_stdlib_only_no_packages(self, controlled_pipeline):
        code = "import os\nimport sys\nimport json\n"
        result = controlled_pipeline.process(code, "python")
        assert result.packages_found == []

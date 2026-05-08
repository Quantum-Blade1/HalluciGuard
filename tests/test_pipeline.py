"""Tests for the full HalluciGuard Pipeline."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.core.pipeline import HalluciGuardPipeline
from src.core.config import PipelineConfig


@pytest.fixture
def pipeline():
    config = PipelineConfig(enable_remediation=False)
    return HalluciGuardPipeline(config=config)


@pytest.mark.asyncio
class TestPipelineEndToEnd:
    """End-to-end pipeline tests."""

    async def test_hallucinated_packages_detected(self, pipeline):
        """Known hallucinated packages should be flagged."""
        code = """
import securehashlib
from dataflow_engine import Pipeline
import crypto_helper
"""
        result = await pipeline.run(code, "test.py")
        assert len(result.packages_found) > 0
        # At least one should be found
        assert len(result.packages_found) >= 1

    async def test_safe_packages_pass(self, pipeline):
        """Known good packages should pass through unflagged."""
        code = """
import os
import json
import sys
"""
        result = await pipeline.run(code, "test.py")
        # All are stdlib, should be filtered by Sentinel
        assert result.packages_found == []

    async def test_empty_code(self, pipeline):
        result = await pipeline.run("", "test.py")
        assert result.packages_found == []
        assert result.profiles == []

    async def test_pipeline_result_structure(self, pipeline):
        code = "import requests\n"
        result = await pipeline.run(code, "test.py")
        assert hasattr(result, "packages_found")
        assert hasattr(result, "profiles")
        assert hasattr(result, "audit_entries")
        assert result.processing_time_ms >= 0

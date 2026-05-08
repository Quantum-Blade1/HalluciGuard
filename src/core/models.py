"""
HalluciGuard Data Models.

All shared data structures used across the 5-agent pipeline.
Uses dataclasses exclusively (no raw dicts) per project conventions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ImportInfo:
    """Represents a single import extracted from source code."""

    module_name: str
    package_name: str  # Mapped via module_to_package
    language: str      # "python" | "javascript"
    line_number: int
    source_file: str


@dataclass
class ValidationResult:
    """Result of validating a package against registries and hallucination DB."""

    package_name: str
    exists_on_registry: bool
    bloom_hit: bool
    is_hallucinated: bool  # Present in hallucination DB
    registry_response: dict[str, Any] | None = None


@dataclass
class RiskScore:
    """Weighted risk assessment for a package (0–100 scale)."""

    package_name: str
    total_score: int  # 0-100 composite score
    typosquat_score: float
    hallucination_db_score: float
    recency_score: float
    popularity_score: float
    cve_score: float
    cross_lang_score: float
    flagged: bool  # total_score >= RISK_THRESHOLD
    typosquat_candidates: list[str] = field(default_factory=list)


@dataclass
class Remediation:
    """A suggested remediation for a flagged import."""

    original_import: str
    suggested_package: str
    rewritten_code: str
    confidence: float  # 0.0 – 1.0
    source: str  # "chromadb" | "gemini" | "levenshtein"


@dataclass
class AuditEntry:
    """Tamper-evident audit log entry with SHA-256 hash chain."""

    timestamp: str
    event_type: str  # "scan" | "flag" | "remediate" | "pass"
    import_info: ImportInfo
    risk_score: RiskScore | None = None
    remediation: Remediation | None = None
    prev_hash: str = ""
    current_hash: str = ""


@dataclass
class PipelineResult:
    """Aggregated result from a full pipeline run."""

    imports: list[ImportInfo] = field(default_factory=list)
    validations: list[ValidationResult] = field(default_factory=list)
    risk_scores: list[RiskScore] = field(default_factory=list)
    remediations: list[Remediation] = field(default_factory=list)
    audit_entries: list[AuditEntry] = field(default_factory=list)
    flagged_count: int = 0
    total_count: int = 0
    source_file: str = ""
    processing_time_ms: float = 0.0


@dataclass
class DashboardEvent:
    """Event payload sent to the real-time dashboard."""

    event_type: str  # "pipeline_start" | "agent_complete" | "risk_alert" | "remediation"
    agent_name: str
    data: dict[str, Any] = field(default_factory=dict)
    timestamp: str = ""

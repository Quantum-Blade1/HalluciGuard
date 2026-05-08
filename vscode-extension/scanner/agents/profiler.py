"""
Agent 3: Profiler — Weighted Risk Scoring.

Computes a 0-100 risk score using 6 weighted factors based on academic research.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

from scanner.config import DEFAULT_RISK_THRESHOLD, RISK_WEIGHTS, REMEDIATION_MAP
from scanner.agents.sentinel import PackageRef
from scanner.agents.validator import ValidationResult
from scanner.data.bloom_filter import package_bloom_filter
from scanner.data.cve_client import CVEClient
from scanner.utils.levenshtein import min_levenshtein_distance, typosquat_score
from scanner.utils.pattern_detector import detect_hallucination_pattern, stdlib_proximity_score

logger = logging.getLogger(__name__)


@dataclass
class ProfileResult:
    """Result of risk profiling for a package."""
    package_name: str
    risk_score: float
    flags: list[str] = field(default_factory=list)
    nearest_package: str = ""
    levenshtein_distance: int = 999
    is_high_risk: bool = False
    suggested: str = ""  # curated safe replacement from REMEDIATION_MAP


class ProfilerAgent:
    """Agent 3: Computes weighted risk scores for imported packages."""

    def __init__(self, risk_threshold: int = DEFAULT_RISK_THRESHOLD) -> None:
        self._cve_client = CVEClient()
        self._risk_threshold = risk_threshold

    async def profile(self, refs: list[PackageRef], validations: list[ValidationResult]) -> list[ProfileResult]:
        """Compute risk scores for each package.

        Args:
            refs: PackageRef list from Sentinel.
            validations: ValidationResult list from Validator.

        Returns:
            List of ProfileResult.
        """
        results: list[ProfileResult] = []

        for ref, val in zip(refs, validations):
            flags: list[str] = []
            score = 0.0

            # 1. TyposquatScore (w=30)
            # Distance=1 gets full weight — a 1-char diff from a popular package is
            # almost certainly intentional squatting (e.g. "requets" → "requests").
            nearest, distance = min_levenshtein_distance(ref.package_name, ref.language)
            typosquat_w = RISK_WEIGHTS.get("typosquat", 30)
            t_score = 0.0
            if distance > 0:
                if distance == 1:
                    t_score = float(typosquat_w)          # full weight
                elif distance == 2:
                    t_score = typosquat_w * 0.7           # 70%
                else:
                    raw_typo = typosquat_score(distance)  # formula for distance ≥ 3
                    t_score = (raw_typo / 100.0) * typosquat_w
                score += t_score
                if distance <= 2:
                    flags.append("TYPOSQUAT_DANGER")
            
            # 1b. Pattern-based hallucination detection (w up to 25)
            # Catches LLM naming patterns like `requests-helper`, `secure-fetch-utils`
            # without needing them in the manual hallucination DB.
            is_pattern, pattern_label, pattern_base = detect_hallucination_pattern(ref.package_name)
            if is_pattern and not val.exists_on_registry:
                pattern_score = 25.0
                score += pattern_score
                flags.append(f"HALLUCINATION_PATTERN:{pattern_label}")

            # 1c. Stdlib proximity (w up to 30)
            # Catches `import hash` (close to `hashlib`), `import jsons` (close to `json`)
            # — stdlib modules don't need pip install; anything close to them is suspicious.
            if ref.language == "python" and not val.exists_on_registry:
                stdlib_score, stdlib_match = stdlib_proximity_score(ref.package_name)
                if stdlib_score > 0:
                    score += stdlib_score
                    flags.append(f"STDLIB_PROXIMITY:{stdlib_match}")

            # 2. HallucinationDBHit (w=25)
            hallucination_w = RISK_WEIGHTS.get("hallucination_db", 25)
            if val.is_hallucinated:
                score += hallucination_w
                flags.append("HALLUCINATION_DB_HIT")

            # 3. RecencyPenalty (w=15)
            recency_w = RISK_WEIGHTS.get("recency", 15)
            if val.exists_on_registry and val.registry_response:
                created_at = val.registry_response.get("first_upload", "")
                if created_at:
                    try:
                        created = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                        now = datetime.now(timezone.utc)
                        days_old = (now - created).days
                        if days_old < 90:
                            r_score = ((90 - days_old) / 90.0) * recency_w
                            score += r_score
                            flags.append("NEW_PACKAGE")
                    except (ValueError, TypeError):
                        pass

            # 4a. NonExistentPenalty (w=25) — package absent from all registries
            non_existent_w = RISK_WEIGHTS.get("non_existent", 25)
            popularity_w = RISK_WEIGHTS.get("popularity", 15)
            if not val.exists_on_registry:
                p_score = non_existent_w + popularity_w  # 25 + 15 = 40
                score += p_score
                flags.append("NOT_IN_REGISTRY")
            else:
                # 4b. LowPopularityPenalty — only when we have actual registry metadata
                if val.registry_response:
                    downloads = val.registry_response.get("download_count", 0)
                    if downloads < 1000:
                        p_score = (1.0 - (downloads / 1000.0)) * popularity_w
                        score += p_score
                        flags.append("LOW_POPULARITY")

            # 5. CVEScore (w=10)
            cve_w = RISK_WEIGHTS.get("cve", 10)
            if val.exists_on_registry:
                ecosystem = "PyPI" if ref.language == "python" else "npm"
                cve_count, cve_ids = await self._cve_client.check_cve(ref.package_name, ecosystem)
                if cve_count > 0:
                    cve_score = min(cve_count / 5.0, 1.0) * cve_w
                    score += cve_score
                    flags.append("VULNERABLE")

            # 6. CrossLangFlag (w=5)
            cross_w = RISK_WEIGHTS.get("cross_lang", 5)
            if ref.language == "python" and not val.exists_on_registry:
                if package_bloom_filter.exists_npm(ref.package_name):
                    score += cross_w
                    flags.append("CROSS_ECOSYSTEM")
            elif ref.language == "javascript" and not val.exists_on_registry:
                if package_bloom_filter.exists_pypi(ref.package_name):
                    score += cross_w
                    flags.append("CROSS_ECOSYSTEM")

            total_risk = min(score, 100.0)

            # Curated replacement: remediation map takes priority over Levenshtein nearest
            suggested = REMEDIATION_MAP.get(ref.package_name.lower(), "")
            if not suggested and distance <= 2:
                suggested = nearest  # close typosquat — Levenshtein nearest is reliable

            results.append(
                ProfileResult(
                    package_name=ref.package_name,
                    risk_score=total_risk,
                    flags=flags,
                    nearest_package=nearest,
                    levenshtein_distance=distance,
                    is_high_risk=total_risk >= self._risk_threshold,
                    suggested=suggested,
                )
            )

        flagged = sum(1 for r in results if r.is_high_risk)
        logger.info(
            "Profiler: %d packages scored, %d high risk (threshold=%d)",
            len(results), flagged, self._risk_threshold,
        )
        return results

    async def close(self) -> None:
        await self._cve_client.close()

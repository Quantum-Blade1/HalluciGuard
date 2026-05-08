"""
Agent 4: Remediator — AI-Driven Code Rewriting.

Given a single ProfileResult and source code, finds a safe alternative package
and rewrites the code using Gemini Flash (with regex fallback).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

from src.core.config import GEMINI_API_KEY, GEMINI_MODEL
from src.agents.profiler import ProfileResult
from src.data.chroma_manager import ChromaManager
from src.utils.levenshtein import min_levenshtein_distance

logger = logging.getLogger(__name__)


@dataclass
class RemediationResult:
    """Result of remediating a single hallucinated package in source code."""

    original_package: str
    suggested_package: str
    rewritten_code: str
    source: str          # "chromadb" | "levenshtein" | "gemini" | "regex"
    confidence: float    # 0.0 – 1.0
    alternatives: list[str] = field(default_factory=list)  # top candidates from ChromaDB


class RemediatorAgent:
    """Agent 4: Rewrites source code replacing hallucinated packages with safe alternatives."""

    def __init__(self) -> None:
        self._chroma = ChromaManager()
        self._genai_client = None
        self._init_gemini()

    def _init_gemini(self) -> None:
        if not GEMINI_API_KEY:
            logger.warning("GEMINI_API_KEY not set; LLM rewriting disabled, will use regex fallback")
            return
        try:
            from google import genai
            self._genai_client = genai.Client(api_key=GEMINI_API_KEY)
        except ImportError:
            logger.warning("google-genai not installed; LLM rewriting disabled")

    def remediate(self, profile: ProfileResult, code: str) -> RemediationResult:
        """Find a safe alternative and rewrite code replacing the hallucinated package.

        Strategy order:
          1. ChromaDB semantic search (top 3) — pick highest-confidence match
          2. Levenshtein nearest match if ChromaDB is empty
          3. Gemini Flash to rewrite the code with the chosen alternative
          4. Regex replacement if Gemini fails or is unavailable

        Args:
            profile: ProfileResult for the hallucinated package.
            code: Full source code string containing the import.

        Returns:
            RemediationResult with rewritten code and metadata.
        """
        hallucinated = profile.package_name

        language = self._infer_language(code, hallucinated)

        alternatives: list[str] = []
        suggested: str = ""
        source: str = "regex"
        confidence: float = 0.0

        # ── Step 1: Levenshtein for close typosquats (distance ≤ 2) ────────────
        # Semantic similarity (ChromaDB) is unreliable when the package name is
        # only 1-2 characters away from a real one — Levenshtein is authoritative
        # in that range (e.g. "pydantics" → "pydantic", "requets" → "requests").
        nearest, lev_dist = (profile.nearest_package, profile.levenshtein_distance) \
            if profile.nearest_package \
            else min_levenshtein_distance(hallucinated, language)

        if nearest and lev_dist <= 2:
            suggested = nearest
            alternatives = [nearest]
            confidence = 1.0 - (lev_dist * 0.15)   # dist=1 → 0.85, dist=2 → 0.70
            source = "levenshtein"
            logger.info(
                "Levenshtein (distance=%d): '%s' → '%s'",
                lev_dist, hallucinated, suggested,
            )

        # ── Step 2: ChromaDB semantic search for everything else ─────────────
        if not suggested:
            chroma_results = self._chroma.query_similar(hallucinated, n_results=3, language=language)

            if chroma_results:
                alternatives = [name for name, _desc, _dist in chroma_results]
                best_name, _best_desc, best_dist = chroma_results[0]
                suggested = best_name
                confidence = max(0.0, 1.0 - best_dist)
                source = "chromadb"
                logger.info(
                    "ChromaDB: '%s' → '%s' (cosine=%.3f)",
                    hallucinated, suggested, best_dist,
                )

        # ── Step 3: Levenshtein fallback when ChromaDB also empty ────────────
        if not suggested:
            if nearest and lev_dist < 999:
                suggested = nearest
                alternatives = [nearest]
                confidence = max(0.0, 1.0 - (lev_dist / 6.0))
                source = "levenshtein"
            else:
                return RemediationResult(
                    original_package=hallucinated,
                    suggested_package="",
                    rewritten_code=code,
                    source="none",
                    confidence=0.0,
                    alternatives=[],
                )

        # ── Step 3: Gemini Flash rewrites the full code ──
        rewritten = self._rewrite_with_gemini(code, hallucinated, suggested, language)

        if rewritten:
            return RemediationResult(
                original_package=hallucinated,
                suggested_package=suggested,
                rewritten_code=rewritten,
                source=f"{source}+gemini",
                confidence=confidence,
                alternatives=alternatives,
            )

        # ── Step 4: Regex replacement fallback ──
        rewritten = self._regex_replace(code, hallucinated, suggested)
        return RemediationResult(
            original_package=hallucinated,
            suggested_package=suggested,
            rewritten_code=rewritten,
            source=source,  # chromadb or levenshtein, no gemini suffix
            confidence=confidence * 0.7,  # lower confidence for mechanical replace
            alternatives=alternatives,
        )

    # ── private helpers ──────────────────────────────────────────────────────

    def _rewrite_with_gemini(
        self,
        code: str,
        hallucinated: str,
        replacement: str,
        language: str,
    ) -> str | None:
        """Ask Gemini Flash to rewrite the code replacing the hallucinated package."""
        if not self._genai_client:
            return None

        prompt = (
            f"You are a secure code rewriter. The {language} package '{hallucinated}' "
            f"is hallucinated and does not exist. Replace ALL uses of '{hallucinated}' "
            f"with the verified safe alternative '{replacement}'. "
            "Preserve all function signatures, logic, and formatting exactly. "
            "Return ONLY the rewritten source code with no explanation, no markdown fences, "
            "no commentary — just the raw source code.\n\n"
            f"```\n{code}\n```"
        )

        try:
            response = self._genai_client.models.generate_content(
                model=GEMINI_MODEL,
                contents=prompt,
            )
            text = response.text.strip()
            # Strip markdown fences if the model added them anyway
            text = re.sub(r"^```[a-z]*\n?", "", text)
            text = re.sub(r"\n?```$", "", text)
            if text:
                return text
        except Exception as e:
            logger.error("Gemini rewrite failed: %s", e)

        return None

    def _regex_replace(self, code: str, hallucinated: str, replacement: str) -> str:
        """Replace package name in import statements and usage via regex."""
        # Handle both hyphen and underscore variants
        alt_form = hallucinated.replace("-", "_")

        # Replace in import statements: import X, from X import ...
        pattern = re.compile(
            r'\b' + re.escape(alt_form) + r'\b',
            re.IGNORECASE,
        )
        replacement_norm = replacement.replace("-", "_")
        rewritten = pattern.sub(replacement_norm, code)

        # Also replace the hyphenated form in strings/comments (e.g. pip install X)
        if alt_form != hallucinated:
            rewritten = rewritten.replace(hallucinated, replacement)

        return rewritten

    def _infer_language(self, code: str, package_name: str) -> str:
        """Heuristically determine language from code content."""
        if "import " in code or "from " in code:
            if "require(" in code or "import {" in code or "from '" in code:
                return "javascript"
            return "python"
        return "python"

"""
Agent 1: Sentinel — Import Extraction.

Extracts imports, filters out stdlib/builtins, and maps module names.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from src.core.config import PYTHON_STDLIB, JS_BUILTINS
from src.utils.ast_parser import ASTParser
from src.utils.module_to_package import module_to_package, is_relative_import

logger = logging.getLogger(__name__)

@dataclass
class PackageRef:
    """Reference to an imported package."""
    package_name: str
    module_name: str
    language: str
    line_no: int
    import_type: str

    # Backwards compatibility
    @property
    def line_number(self) -> int:
        return self.line_no
    @property
    def source_file(self) -> str:
        return "unknown"


class SentinelAgent:
    """Agent 1: Extracts and filters imports from source code."""

    def __init__(self) -> None:
        self._parser = ASTParser()

    def analyze(self, code: str, language_or_filename: str | None = None) -> list[PackageRef]:
        """Extract non-stdlib imports from source code.

        Args:
            code: Source code string.
            language_or_filename: 'python', 'javascript', or a filename (e.g. 'test.py').

        Returns:
            List of PackageRef.
        """
        language = None
        if language_or_filename:
            if language_or_filename in ("python", "javascript"):
                language = language_or_filename
            elif language_or_filename.endswith((".js", ".jsx", ".ts")):
                language = "javascript"
            elif language_or_filename.endswith(".py"):
                language = "python"
        
        if not language:
            language = self.detect_language(code)

        raw_imports = self._parser.extract_imports(code, language)

        stdlib = PYTHON_STDLIB if language == "python" else JS_BUILTINS
        results: list[PackageRef] = []

        for imp in raw_imports:
            if is_relative_import(imp.module_name):
                continue

            top_module = imp.module_name.split(".")[0]

            if top_module in stdlib or imp.module_name in stdlib:
                continue

            package_name = module_to_package(imp.module_name)

            results.append(
                PackageRef(
                    package_name=package_name,
                    module_name=imp.module_name,
                    language=language,
                    line_no=imp.line_no,
                    import_type=imp.import_type,
                )
            )

        logger.info(
            "Sentinel: %d imports found, %d after stdlib filter",
            len(raw_imports), len(results),
        )
        return results

    def detect_language(self, code: str) -> str:
        """Simple heuristic to detect Python vs JS."""
        # Check for common JS tokens
        js_tokens = ["import {", "import *", "require(", "const ", "let ", "=>", "export default", "from '", 'from "']
        js_score = sum(1 for t in js_tokens if t in code)
        
        # Check for common Python tokens
        py_tokens = ["def ", "class ", "import ", "from ", "async def ", "print("]
        py_score = sum(1 for t in py_tokens if t in code)

        return "javascript" if js_score > 0 and js_score >= py_score else "python"

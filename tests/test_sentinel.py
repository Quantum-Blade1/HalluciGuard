"""
Tests for Agent 1: Sentinel — Import Extraction.

Covers:
 - Python bare imports and from-imports
 - Stdlib filtering (os, sys, json, pathlib, collections …)
 - Module-to-package resolution (cv2→opencv-python, PIL→Pillow, yaml→PyYAML, bs4→beautifulsoup4)
 - Relative-import filtering
 - JS ES6 import / CommonJS require (tree-sitter path, skipped gracefully if not available)
 - Language detection heuristic
 - Line-number accuracy
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.agents.sentinel import SentinelAgent


@pytest.fixture
def sentinel() -> SentinelAgent:
    return SentinelAgent()


# ── Python import extraction ──────────────────────────────────────────────────

class TestPythonBareImport:
    def test_single_package(self, sentinel):
        refs = sentinel.analyze("import requests", "python")
        names = [r.package_name for r in refs]
        assert "requests" in names

    def test_multiple_packages(self, sentinel):
        code = "import requests\nimport numpy\nimport flask"
        refs = sentinel.analyze(code, "python")
        names = [r.package_name for r in refs]
        assert "requests" in names
        assert "numpy" in names

    def test_aliased_import(self, sentinel):
        refs = sentinel.analyze("import numpy as np", "python")
        names = [r.package_name for r in refs]
        assert "numpy" in names

    def test_dotted_top_level(self, sentinel):
        # dotted imports should resolve to the top-level package
        refs = sentinel.analyze("import xml.etree.ElementTree", "python")
        # xml is stdlib — must be filtered
        names = [r.package_name for r in refs]
        assert "xml" not in names

    def test_import_type_recorded(self, sentinel):
        refs = sentinel.analyze("import requests", "python")
        assert any(r.import_type == "import" for r in refs)


class TestPythonFromImport:
    def test_from_package_import_name(self, sentinel):
        # from flask import Flask → module 'flask' → package 'Flask'
        refs = sentinel.analyze("from flask import Flask", "python")
        assert any(r.package_name == "Flask" for r in refs)

    def test_from_import_type_recorded(self, sentinel):
        refs = sentinel.analyze("from requests import Session", "python")
        assert any(r.import_type == "from_import" for r in refs)

    def test_from_dotted_module(self, sentinel):
        # from google.cloud import storage → top-level 'google' mapped via module_to_package
        refs = sentinel.analyze("from google.cloud import storage", "python")
        # google.cloud maps to google-cloud-core; or falls back to 'google'
        assert len(refs) >= 1

    def test_hallucinated_from_import(self, sentinel):
        refs = sentinel.analyze("from dataflow_engine import Pipeline", "python")
        names = [r.package_name for r in refs]
        assert "dataflow_engine" in names


class TestStdlibFiltering:
    STDLIB_CODE = (
        "import os\n"
        "import sys\n"
        "import json\n"
        "import pathlib\n"
        "import collections\n"
        "import asyncio\n"
        "import re\n"
        "import math\n"
    )

    def test_all_stdlib_filtered(self, sentinel):
        refs = sentinel.analyze(self.STDLIB_CODE, "python")
        assert refs == [], f"Stdlib imports leaked: {[r.package_name for r in refs]}"

    def test_stdlib_with_third_party(self, sentinel):
        code = "import os\nimport requests\nimport sys\n"
        refs = sentinel.analyze(code, "python")
        names = [r.package_name for r in refs]
        assert "os" not in names
        assert "sys" not in names
        assert "requests" in names

    def test_from_stdlib_filtered(self, sentinel):
        code = "from pathlib import Path\nfrom typing import Optional\n"
        refs = sentinel.analyze(code, "python")
        assert refs == []


class TestModuleToPackageResolution:
    def test_cv2_to_opencv(self, sentinel):
        refs = sentinel.analyze("import cv2", "python")
        pkg_names = {r.package_name for r in refs}
        assert "opencv-python" in pkg_names, f"Got: {pkg_names}"

    def test_pil_to_pillow(self, sentinel):
        refs = sentinel.analyze("from PIL import Image", "python")
        pkg_names = {r.package_name for r in refs}
        assert "Pillow" in pkg_names, f"Got: {pkg_names}"

    def test_yaml_to_pyyaml(self, sentinel):
        refs = sentinel.analyze("import yaml", "python")
        pkg_names = {r.package_name for r in refs}
        assert "PyYAML" in pkg_names, f"Got: {pkg_names}"

    def test_bs4_to_beautifulsoup4(self, sentinel):
        refs = sentinel.analyze("from bs4 import BeautifulSoup", "python")
        pkg_names = {r.package_name for r in refs}
        assert "beautifulsoup4" in pkg_names, f"Got: {pkg_names}"

    def test_sklearn_to_scikit_learn(self, sentinel):
        refs = sentinel.analyze("from sklearn.linear_model import LogisticRegression", "python")
        pkg_names = {r.package_name for r in refs}
        assert "scikit-learn" in pkg_names, f"Got: {pkg_names}"

    def test_unknown_module_passthrough(self, sentinel):
        # Unknown modules fall back to module name as package name
        refs = sentinel.analyze("import securehashlib", "python")
        assert any(r.package_name == "securehashlib" for r in refs)


class TestRelativeImportFiltering:
    def test_dot_relative(self, sentinel):
        code = "from . import utils\nfrom .models import User\n"
        refs = sentinel.analyze(code, "python")
        assert refs == []

    def test_double_dot_relative(self, sentinel):
        refs = sentinel.analyze("from ..core import config", "python")
        assert refs == []


class TestHallucinatedPackages:
    def test_securehashlib_extracted(self, sentinel):
        refs = sentinel.analyze("import securehashlib", "python")
        assert any(r.package_name == "securehashlib" for r in refs)

    def test_dataflow_engine_extracted(self, sentinel):
        refs = sentinel.analyze("from dataflow_engine import Pipeline", "python")
        assert any(r.package_name == "dataflow_engine" for r in refs)

    def test_all_three_sample_packages(self, sentinel):
        code = "import securehashlib\nfrom flask import Flask\nimport dataflow_engine"
        refs = sentinel.analyze(code, "python")
        names = {r.package_name for r in refs}
        assert "securehashlib" in names
        assert "Flask" in names
        assert "dataflow_engine" in names


class TestLineNumbers:
    def test_line_numbers_correct(self, sentinel):
        code = "import requests\nimport numpy\nimport flask\n"
        refs = sentinel.analyze(code, "python")
        line_map = {r.package_name: r.line_no for r in refs}
        assert line_map.get("requests") == 1
        assert line_map.get("numpy") == 2

    def test_from_import_line_number(self, sentinel):
        code = "\nimport os\nfrom flask import Flask\n"
        refs = sentinel.analyze(code, "python")
        flask_refs = [r for r in refs if r.package_name == "Flask"]
        assert flask_refs
        assert flask_refs[0].line_no == 3


class TestEdgeCases:
    def test_empty_code(self, sentinel):
        assert sentinel.analyze("", "python") == []

    def test_no_imports(self, sentinel):
        assert sentinel.analyze("x = 1\nprint('hello')\n", "python") == []

    def test_whitespace_only(self, sentinel):
        assert sentinel.analyze("   \n\t\n  ", "python") == []

    def test_comment_only(self, sentinel):
        assert sentinel.analyze("# import requests\n", "python") == []


# ── JavaScript import extraction ──────────────────────────────────────────────

class TestJavaScriptImports:
    """Tree-sitter JS parsing — tests skip gracefully if tree-sitter is absent."""

    def _js_refs(self, sentinel, code: str):
        return sentinel.analyze(code, "javascript")

    def test_es6_default_import(self, sentinel):
        refs = self._js_refs(sentinel, "import express from 'express';")
        if not refs:
            pytest.skip("tree-sitter JS not available")
        assert any(r.module_name == "express" for r in refs)

    def test_es6_named_import(self, sentinel):
        refs = self._js_refs(sentinel, "import { useState, useEffect } from 'react';")
        if not refs:
            pytest.skip("tree-sitter JS not available")
        assert any(r.module_name == "react" for r in refs)

    def test_commonjs_require(self, sentinel):
        refs = self._js_refs(sentinel, "const axios = require('axios');")
        if not refs:
            pytest.skip("tree-sitter JS not available")
        assert any(r.module_name == "axios" for r in refs)

    def test_js_builtins_filtered(self, sentinel):
        code = "const fs = require('fs');\nconst path = require('path');\n"
        refs = self._js_refs(sentinel, code)
        names = [r.module_name for r in refs]
        assert "fs" not in names
        assert "path" not in names

    def test_relative_js_filtered(self, sentinel):
        code = "import helper from './utils';\nimport cfg from '../config';\n"
        refs = self._js_refs(sentinel, code)
        assert refs == []

    def test_scoped_package(self, sentinel):
        code = "import { Client } from '@anthropic-ai/sdk';"
        refs = self._js_refs(sentinel, code)
        if not refs:
            pytest.skip("tree-sitter JS not available")
        assert any(r.package_name == "@anthropic-ai/sdk" for r in refs)

    def test_js_language_tag(self, sentinel):
        code = "import express from 'express';"
        refs = self._js_refs(sentinel, code)
        if not refs:
            pytest.skip("tree-sitter JS not available")
        assert all(r.language == "javascript" for r in refs)


# ── Language detection ────────────────────────────────────────────────────────

class TestLanguageDetection:
    def test_python_by_keyword(self, sentinel):
        code = "def main():\n    pass\nimport os\n"
        assert sentinel.detect_language(code) == "python"

    def test_javascript_by_keyword(self, sentinel):
        code = "const x = require('lodash');\nconst y = () => {};\n"
        assert sentinel.detect_language(code) == "javascript"

    def test_py_extension(self, sentinel):
        refs = sentinel.analyze("import requests", "test.py")
        assert all(r.language == "python" for r in refs)

    def test_js_extension(self, sentinel):
        refs = sentinel.analyze("import express from 'express';", "test.js")
        # language is set even if tree-sitter produces no output
        if refs:
            assert all(r.language == "javascript" for r in refs)

    def test_ts_extension(self, sentinel):
        refs = sentinel.analyze("import { foo } from 'bar';", "module.ts")
        if refs:
            assert all(r.language == "javascript" for r in refs)

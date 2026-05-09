"""
HalluciGuard Scanner Configuration.

Pure constants — no dotenv, no env vars, no API keys.
All paths are relative to the scanner/ directory so it works when bundled
inside the VS Code extension.
"""

from __future__ import annotations

from pathlib import Path

# ---------------------------------------------------------------------------
# Path constants — all relative to THIS file (scanner/config.py)
# ---------------------------------------------------------------------------
SCANNER_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = SCANNER_ROOT.parent
DATA_DIR = PROJECT_ROOT / "data"
BLOOM_DIR = DATA_DIR / "bloom"
HALLUCINATION_DB_DIR = DATA_DIR / "hallucination_db"
CVE_CACHE_DIR = DATA_DIR / "cve_cache"
AUDIT_LOG_PATH = DATA_DIR / "audit_log.jsonl"

# ---------------------------------------------------------------------------
# Directories to skip when walking a workspace
# ---------------------------------------------------------------------------
SKIP_DIRS: frozenset[str] = frozenset({
    "node_modules", ".venv", "venv", "__pycache__", ".git",
    "dist", "build", ".tox", ".nox", ".mypy_cache", ".pytest_cache",
    ".eggs", "*.egg-info", ".hg", ".svn",
})

# Supported file extensions (v1)
SUPPORTED_EXTENSIONS: frozenset[str] = frozenset({".py", ".js"})

# ---------------------------------------------------------------------------
# Bloom filter
# ---------------------------------------------------------------------------
BLOOM_CAPACITY: int = 700_000
BLOOM_FP_RATE: float = 0.001

# ---------------------------------------------------------------------------
# Risk scoring weights (0-100 total)
# ---------------------------------------------------------------------------
DEFAULT_RISK_THRESHOLD: int = 65

RISK_WEIGHTS: dict[str, int] = {
    # ── Typosquat (w=30) ────────────────────────────────────────────────────
    # Levenshtein distance ≤ 1 from a top-200 package = full weight (30 pts).
    # Distance 2 = 70% weight. Distance ≥ 3 = diminishing formula.
    # Highest weight because typosquatting is the most common and
    # immediately actionable attack vector in supply chain attacks.
    # Ref: Ohm et al., "Backstabber's Knife Collection: A Large-Scale Analysis
    #      of Malicious Packages in npm and PyPI" (DIMVA 2020)
    # Ref: Spracklen et al., "Automated Hallucination Detection" (USENIX 2025)
    "typosquat": 30,

    # ── Hallucination DB (w=25) ─────────────────────────────────────────────
    # Binary match against 150+ names curated from prompting GPT-4, Claude,
    # and GitHub Copilot across 50+ real coding tasks. A name in this DB was
    # never a real package — any match is near-certain hallucination.
    # Ref: Lanyado et al., "Can You Trust ChatGPT's Package Recommendations?
    #      Investigating Misinformation in Software Dev" (Vulcan Cyber, 2023)
    "hallucination_db": 25,

    # ── Non-existent (w=25) ─────────────────────────────────────────────────
    # Package absent from both bloom filter (800k names) and live registry.
    # Combined with popularity penalty (w=15) when not on registry = 40 pts
    # baseline for any invented package name.
    # Separate from hallucination_db: catches novel hallucinations not yet
    # in the curated list.
    "non_existent": 25,

    # ── Recency (w=15) ──────────────────────────────────────────────────────
    # Packages uploaded < 90 days ago are riskier — attackers register names
    # reactively after LLMs are observed hallucinating them.
    # Score scales linearly: 0 days old = full 15 pts, 90 days = 0 pts.
    # Ref: Vu et al., "Typosquatting and Combosquatting Attacks on the
    #      Python Ecosystem" (ACSAC 2020)
    "recency": 15,

    # ── Popularity (w=15) ───────────────────────────────────────────────────
    # Packages with < 1000 weekly downloads are suspicious when they exist.
    # Legitimate packages suggested by LLMs almost always have high download
    # counts. A real-but-obscure package warrants investigation.
    # Ref: Zimmermann et al., "Small World with High Risks: A Study of Security
    #      Threats in the npm Ecosystem" (USENIX Security 2019)
    "popularity": 15,

    # ── CVE (w=10) ──────────────────────────────────────────────────────────
    # Known vulnerabilities from OSV.dev. Score = min(cve_count/5, 1) × 10.
    # Lower weight than existence signals — a vulnerable package is a
    # dependency risk but not necessarily a hallucination.
    # Ref: OSV.dev open vulnerability database (google.github.io/osv.dev)
    "cve": 10,

    # ── Cross-ecosystem (w=5) ───────────────────────────────────────────────
    # Package appears in the wrong ecosystem (e.g. JS package imported in
    # Python file). Additive signal on top of others.
    # Ref: Ladisa et al., "Taxonomy of Attacks on Open-Source Supply Chains"
    #      (IEEE S&P 2023)
    "cross_lang": 5,
}

# ---------------------------------------------------------------------------
# Registry URLs
# ---------------------------------------------------------------------------
PYPI_JSON_URL = "https://pypi.org/pypi/{package}/json"
NPM_REGISTRY_URL = "https://registry.npmjs.org/"

# ---------------------------------------------------------------------------
# Python 3.11 standard library modules (frozen set for O(1) lookup)
# ---------------------------------------------------------------------------
PYTHON_STDLIB: frozenset[str] = frozenset({
    "__future__", "_thread", "abc", "aifc", "argparse", "array", "ast",
    "asynchat", "asyncio", "asyncore", "atexit", "audioop", "base64",
    "bdb", "binascii", "binhex", "bisect", "builtins", "bz2", "calendar",
    "cgi", "cgitb", "chunk", "cmath", "cmd", "code", "codecs", "codeop",
    "collections", "colorsys", "compileall", "concurrent", "configparser",
    "contextlib", "contextvars", "copy", "copyreg", "cProfile", "crypt",
    "csv", "ctypes", "curses", "dataclasses", "datetime", "dbm", "decimal",
    "difflib", "dis", "distutils", "doctest", "email", "encodings",
    "enum", "errno", "faulthandler", "fcntl", "filecmp", "fileinput",
    "fnmatch", "fractions", "ftplib", "functools", "gc", "getopt",
    "getpass", "gettext", "glob", "graphlib", "grp", "gzip", "hashlib",
    "heapq", "hmac", "html", "http", "idlelib", "imaplib", "imghdr",
    "imp", "importlib", "inspect", "io", "ipaddress", "itertools", "json",
    "keyword", "lib2to3", "linecache", "locale", "logging", "lzma",
    "mailbox", "mailcap", "marshal", "math", "mimetypes", "mmap",
    "modulefinder", "multiprocessing", "netrc", "nis", "nntplib",
    "numbers", "operator", "optparse", "os", "ossaudiodev", "pathlib",
    "pdb", "pickle", "pickletools", "pipes", "pkgutil", "platform",
    "plistlib", "poplib", "posix", "posixpath", "pprint", "profile",
    "pstats", "pty", "pwd", "py_compile", "pyclbr", "pydoc", "queue",
    "quopri", "random", "re", "readline", "reprlib", "resource",
    "rlcompleter", "runpy", "sched", "secrets", "select", "selectors",
    "shelve", "shlex", "shutil", "signal", "site", "smtpd", "smtplib",
    "sndhdr", "socket", "socketserver", "spwd", "sqlite3", "sre_compile",
    "sre_constants", "sre_parse", "ssl", "stat", "statistics", "string",
    "stringprep", "struct", "subprocess", "sunau", "symtable", "sys",
    "sysconfig", "syslog", "tabnanny", "tarfile", "telnetlib", "tempfile",
    "termios", "test", "textwrap", "threading", "time", "timeit",
    "tkinter", "token", "tokenize", "tomllib", "trace", "traceback",
    "tracemalloc", "tty", "turtle", "turtledemo", "types", "typing",
    "unicodedata", "unittest", "urllib", "uu", "uuid", "venv", "warnings",
    "wave", "weakref", "webbrowser", "winreg", "winsound", "wsgiref",
    "xdrlib", "xml", "xmlrpc", "zipapp", "zipfile", "zipimport", "zlib",
    "_frozen_importlib", "_frozen_importlib_external",
})

# ---------------------------------------------------------------------------
# JavaScript / Node.js built-in modules (frozen set)
# ---------------------------------------------------------------------------
JS_BUILTINS: frozenset[str] = frozenset({
    "assert", "buffer", "child_process", "cluster", "console", "constants",
    "crypto", "dgram", "dns", "domain", "events", "fs", "http", "http2",
    "https", "inspector", "module", "net", "os", "path", "perf_hooks",
    "process", "punycode", "querystring", "readline", "repl", "stream",
    "string_decoder", "timers", "tls", "trace_events", "tty", "url",
    "util", "v8", "vm", "wasi", "worker_threads", "zlib",
    "node:assert", "node:buffer", "node:child_process", "node:cluster",
    "node:console", "node:crypto", "node:dgram", "node:dns", "node:events",
    "node:fs", "node:http", "node:http2", "node:https", "node:inspector",
    "node:module", "node:net", "node:os", "node:path", "node:perf_hooks",
    "node:process", "node:punycode", "node:querystring", "node:readline",
    "node:repl", "node:stream", "node:string_decoder", "node:timers",
    "node:tls", "node:trace_events", "node:tty", "node:url", "node:util",
    "node:v8", "node:vm", "node:wasi", "node:worker_threads", "node:zlib",
})

# ---------------------------------------------------------------------------
# Popular packages for typosquat detection (top ~200)
# ---------------------------------------------------------------------------
POPULAR_PYPI_PACKAGES: list[str] = [
    "requests", "flask", "django", "numpy", "pandas", "scipy", "matplotlib",
    "tensorflow", "torch", "keras", "scikit-learn", "pillow", "opencv-python",
    "beautifulsoup4", "sqlalchemy", "celery", "redis", "boto3", "pytest",
    "click", "fastapi", "uvicorn", "pydantic", "httpx", "aiohttp", "grpcio",
    "protobuf", "cryptography", "paramiko", "fabric", "ansible", "scrapy",
    "selenium", "playwright", "lxml", "jinja2", "markupsafe", "werkzeug",
    "gunicorn", "gevent", "eventlet", "twisted", "tornado", "pyramid",
    "bottle", "falcon", "sanic", "starlette", "black", "isort", "flake8",
    "mypy", "pylint", "bandit", "coverage", "tox", "nox", "sphinx",
    "mkdocs", "setuptools", "wheel", "twine", "pip", "virtualenv",
    "ipython", "jupyter", "notebook", "rich", "typer", "arrow", "pendulum",
    "python-dateutil", "pytz", "orjson", "ujson", "msgpack", "pyyaml",
    "toml", "attrs", "cattrs", "marshmallow", "cerberus", "voluptuous",
    "jsonschema", "python-dotenv", "decouple", "dynaconf", "pydantic-settings",
    "alembic", "psycopg2", "pymysql", "pymongo", "motor", "elasticsearch",
    "opensearch-py", "minio", "google-cloud-storage", "azure-storage-blob",
    "stripe", "twilio", "sendgrid", "sentry-sdk", "datadog", "prometheus-client",
    "opentelemetry-api", "structlog", "loguru", "colorama", "tqdm",
    "tabulate", "prettytable", "fire", "docopt", "argcomplete",
    "apache-beam", "apache-airflow", "dask", "pyspark", "ray",
    "transformers", "diffusers", "langchain", "openai", "anthropic",
    "xgboost", "lightgbm", "catboost", "statsmodels", "nltk", "spacy",
    "fasttext", "gensim", "networkx", "sympy", "pyarrow", "polars",
]

POPULAR_NPM_PACKAGES: list[str] = [
    "express", "react", "vue", "angular", "next", "nuxt", "svelte",
    "typescript", "webpack", "vite", "esbuild", "rollup", "parcel",
    "babel", "eslint", "prettier", "jest", "mocha", "chai", "vitest",
    "lodash", "underscore", "ramda", "axios", "node-fetch", "got",
    "moment", "dayjs", "date-fns", "luxon", "uuid", "nanoid", "chalk",
    "commander", "yargs", "inquirer", "ora", "debug", "winston",
    "pino", "dotenv", "cors", "helmet", "morgan", "passport",
    "jsonwebtoken", "bcrypt", "mongoose", "sequelize", "knex",
    "prisma", "typeorm", "socket.io", "ws", "graphql", "apollo-server",
    "redis", "ioredis", "bull", "agenda", "node-cron",
]

# ---------------------------------------------------------------------------
# Remediation map — curated safe replacements for known hallucinations
# Keys are hallucinated package names; values are the correct replacement.
# Used by the Remediator to offer Quick Fix code actions in VS Code.
# ---------------------------------------------------------------------------
REMEDIATION_MAP: dict[str, str] = {
    # Demo workspace packages
    "securehashlib": "cryptography",
    "dataflow_engine": "apache-beam",
    "crypto_helper": "cryptography",
    "logmanager": "loguru",
    "secure-fetch-utils": "axios",

    # Python hallucinations → real replacements
    "safe-crypto": "cryptography",
    "torch-utils": "torch",
    "flask-utils": "flask",
    "api-client": "httpx",
    "openai-wrapper": "openai",
    "pandas-extensions": "pandas",
    "numpy-helpers": "numpy",
    "scipy-extras": "scipy",
    "beautifulsoup-utils": "beautifulsoup4",
    "requests-async": "httpx",
    "aio-requests": "aiohttp",
    "django-rest-utils": "djangorestframework",
    "fastapi-auth": "python-jose",
    "jwt-secure": "python-jose",
    "aws-lambda-helpers": "boto3",
    "s3-boto-wrapper": "boto3",
    "google-cloud-extras": "google-cloud-storage",
    "azure-storage-helpers": "azure-storage-blob",
    "matplotlib-styles": "matplotlib",
    "seaborn-utils": "seaborn",
    "plotly-dash-components": "dash",
    "sqlalchemy-helpers": "sqlalchemy",
    "pymongo-utils": "pymongo",
    "redis-async": "redis",
    "celery-helpers": "celery",
    "pytest-mocks": "pytest-mock",
    "logging-utils": "loguru",
    "config-parser-plus": "python-dotenv",
    "yaml-utils": "pyyaml",
    "json-helpers": "orjson",
    "csv-writer": "csv",
    "datetime-utils": "arrow",
    "time-helpers": "pendulum",
    "math-extras": "numpy",
    "string-utils": "inflect",
    "regex-helpers": "re",
    "os-utils": "pathlib",
    "sys-helpers": "psutil",
    "pathlib-extras": "pathlib",
    "typing-extensions-plus": "typing-extensions",
    "collections-helpers": "more-itertools",
    "itertools-extras": "more-itertools",
    "functools-plus": "toolz",
    "threading-utils": "concurrent.futures",
    "multiprocessing-helpers": "multiprocess",
    "asyncio-utils": "anyio",
    "subprocess-helpers": "sh",
    "socket-utils": "websockets",
    "http-helpers": "httpx",
    "url-utils": "yarl",

    # JS/npm hallucinations → real replacements
    "react-utils": "react",
    "vue-helpers": "vue",
    "angular-extras": "@angular/core",
    "node-fetch-wrapper": "node-fetch",
    "axios-helpers": "axios",
    "express-utils": "express",
    "mongoose-helpers": "mongoose",
    "sequelize-utils": "sequelize",
    "lodash-plus": "lodash",
    "underscore-extras": "lodash",
    "moment-helpers": "dayjs",
    "date-fns-utils": "date-fns",
    "jest-mocks": "jest-mock",
    "mocha-helpers": "mocha",
    "chai-utils": "chai",
    "webpack-helpers": "webpack",
    "babel-utils": "@babel/core",
    "eslint-extras": "eslint",
    "prettier-helpers": "prettier",
    "typescript-utils": "typescript",
}

# ---------------------------------------------------------------------------
# Common cross-language packages (exist in one ecosystem, not the other)
# ---------------------------------------------------------------------------
JS_ONLY_PACKAGES: frozenset[str] = frozenset({
    "lodash", "express", "react", "vue", "angular", "webpack", "babel",
    "eslint", "prettier", "jest", "mocha", "chai", "axios", "moment",
    "chalk", "commander", "yargs", "inquirer", "passport", "mongoose",
    "sequelize", "socket.io", "graphql",
})

PYTHON_ONLY_PACKAGES: frozenset[str] = frozenset({
    "numpy", "pandas", "scipy", "matplotlib", "tensorflow", "torch",
    "scikit-learn", "pillow", "beautifulsoup4", "sqlalchemy", "celery",
    "scrapy", "selenium", "lxml", "gunicorn", "gevent", "twisted",
    "pyramid", "sphinx", "ipython", "jupyter",
})

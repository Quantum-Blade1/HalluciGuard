# HalluciGuard

Self-contained VS Code marketplace extension that detects hallucinated package imports in AI-generated code. Users install from the marketplace, trigger a workspace or file scan, and see results inline (squiggly lines) and in a sidebar TreeView — no external server needed.

## Stack

### VS Code Extension (TypeScript)
- VS Code Extension API (vscode ^1.85.0)
- Node.js child_process for spawning the bundled Python scanner
- NDJSON stream parser for reading scanner output
- TreeDataProvider for sidebar results
- DiagnosticCollection for inline squiggly lines

### Python Scanner (bundled inside extension)
- Python 3.11+ (user's local install, configurable via `halluciguard.pythonPath`)
- tree-sitter (0.22.3) + tree-sitter-python + tree-sitter-javascript for AST parsing
- httpx[http2] for async registry lookups (PyPI + npm)
- rapidfuzz for Levenshtein distance computation
- pybloom-live for bloom filter (PyPI 600k packages, 0.1% FP rate)
- OSV.dev API for CVE lookup, cached in SQLite with 24h TTL

### Data (shipped in extension)
- Bloom filter JSON lists (PyPI + npm package names)
- Known hallucination database
- No ChromaDB, no Gemini, no external LLM calls in v1

## Architecture

```
User installs extension from marketplace
         ↓
VS Code Extension (TypeScript)
  - Activity Bar icon + Sidebar panel (TreeView) showing scan results
  - Status bar item: "🛡️ HalluciGuard: N issues"
  - Commands: "Scan Workspace", "Scan Current File", "Clear Results"
         ↓
Extension spawns Python subprocess (bundled)
  - python scanner/halluciguard_scanner.py --workspace /path/to/project
  - Streams NDJSON results via stdout, errors to stderr
         ↓
Python Scanner — 3-agent pipeline per file
  1. Sentinel — AST parse → extract imports → filter stdlib → map module→package
  2. Validator — Bloom filter check (O(1)) → async HTTP to PyPI/npm → hallucination DB
  3. Profiler — Weighted risk score (0-100):
     typosquat(30) + hallucination_db(25) + recency(15) + popularity(15) + cve(10) + cross_lang(5)
         ↓
Extension renders results
  - Sidebar TreeView: file → package → risk details
  - Inline diagnostics (yellow warning / red error squiggly lines)
  - Click to jump to exact import line
```

**v1 scope:** Detect + report only. No Remediator, no Auditor, no auto-fix.

## Project Structure

```
halluciguard/
├── scanner/                            # Bundled Python scanner (shipped inside extension)
│   ├── halluciguard_scanner.py         # CLI entry point — streams NDJSON results
│   ├── agents/                         # Sentinel, Validator, Profiler (from src/agents/)
│   │   ├── sentinel.py                 # Agent 1: AST → imports
│   │   ├── validator.py                # Agent 2: Bloom + registry + hallucination DB
│   │   └── profiler.py                 # Agent 3: Risk scoring
│   ├── data/                           # Bloom filter, registry client, CVE client
│   │   ├── bloom_filter.py
│   │   ├── registry_client.py
│   │   └── cve_client.py
│   ├── utils/                          # AST parser, levenshtein, module_to_package
│   │   ├── ast_parser.py
│   │   ├── levenshtein.py
│   │   └── module_to_package.py
│   ├── config.py                       # Minimal config (constants only, no dotenv)
│   └── requirements.txt                # Pinned deps for bundled Python
├── vscode-extension/
│   ├── package.json                    # Extension manifest + marketplace metadata
│   ├── src/
│   │   ├── extension.ts                # activate/deactivate, register commands
│   │   ├── scanner_bridge.ts           # Spawns Python subprocess, parses NDJSON stream
│   │   ├── results_provider.ts         # TreeDataProvider for sidebar
│   │   ├── diagnostics.ts              # DiagnosticCollection for squiggly lines
│   │   └── webview_panel.ts            # Rich results WebView (optional, v2)
│   └── tsconfig.json
├── data/                               # Seeded package databases (shipped in extension)
│   ├── bloom/
│   │   ├── pypi_packages.json
│   │   └── npm_packages.json
│   └── hallucination_db/
│       └── known_hallucinations.json
├── scripts/                            # Dev scripts (NOT shipped in extension)
│   ├── seed_bloom.py
│   └── seed_hallucination_db.py
└── tests/
```

## Python Scanner CLI Contract

### Invocation
```bash
# Full workspace scan
python scanner/halluciguard_scanner.py --workspace /path/to/project --mode full

# Single/multi file scan
python scanner/halluciguard_scanner.py --workspace /path/to/project --mode file --files src/app.py src/utils.py
```

### NDJSON Output (stdout only — all errors to stderr)

Per-finding line:
```json
{"file": "path/to/file.py", "package": "securehashlib", "line": 3, "risk_score": 87, "action": "BLOCK", "flags": ["typosquat", "hallucination_db"], "nearest": "hashlib", "distance": 6}
```

Final summary line:
```json
{"type": "summary", "files_scanned": 42, "packages_found": 5, "high_risk": 2, "duration_ms": 1200}
```

### Rules
- One JSON object per line, no pretty-printing
- `file` paths are relative to `--workspace`
- `action` is one of: `BLOCK` (score ≥ 80), `WARN` (score ≥ 65), `ALLOW` (score < 65)
- All log/error output goes to **stderr**, never stdout
- Exit code 0 on success, 1 on fatal error

## VS Code Extension Behavior

### Activity Bar & Sidebar
- Custom icon in Activity Bar opens HalluciGuard sidebar
- TreeView hierarchy: File → Package → Risk details (score, flags, nearest match)
- Click any node to jump to the exact line in the editor

### Inline Diagnostics
- `DiagnosticSeverity.Error` for BLOCK (risk ≥ 80)
- `DiagnosticSeverity.Warning` for WARN (risk ≥ 65)
- Squiggly lines on the import statement line

### Status Bar
- `🛡️ HalluciGuard: N issues` — click to open sidebar
- Spinner animation during scan

### Commands (Command Palette)
- `HalluciGuard: Scan Workspace` — full workspace scan
- `HalluciGuard: Scan Current File` — scan active editor file only
- `HalluciGuard: Clear Results` — clear all diagnostics and sidebar

### Extension Settings
| Setting | Type | Default | Description |
|---|---|---|---|
| `halluciguard.riskThreshold` | number | `65` | Minimum risk score to flag |
| `halluciguard.autoScanOnSave` | boolean | `false` | Auto-scan file on save |
| `halluciguard.pythonPath` | string | `"python3"` | Path to Python interpreter |

### First Activation
- Extension checks for Python availability at `halluciguard.pythonPath`
- Runs `pip install -r scanner/requirements.txt` if deps missing
- Shows progress notification during setup

## Conventions
- **TypeScript (extension):** Strict mode, async/await, no `any` types
- **Python (scanner):** Dataclasses for all data structures, type hints everywhere
- All agents are classes with a single main method (`analyze` / `validate` / `profile`)
- Async only where needed (registry HTTP calls) — rest is sync
- Config in `scanner/config.py` — plain constants, no dotenv, no env vars
- Risk score weights have paper citations in comments
- Never use `sudo` for pip

## Key Constants
- Risk threshold: 65 (configurable via extension setting)
- Bloom filter FP rate: 0.001
- Scanner walks `.py` and `.js` files only (v1)
- Python stdlib and JS builtins are in `scanner/config.py` (skip these in Sentinel)
- **No ports** — no LSP server, no dashboard server, no network listeners

## Testing
- **Python scanner:** pytest + pytest-asyncio
  - Test with known hallucinated packages: `securehashlib`, `dataflow_engine`, `crypto-helper`
  - Test with known good packages: `flask`, `numpy`, `requests`
  - Test NDJSON output format
- **Extension:** VS Code Extension Test framework (`@vscode/test-electron`)

## Environment
- Mac M5 (Apple Silicon)
- Python 3.11 via brew
- Node.js 20+ for extension development
- No `.env` file needed — no API keys in v1 (no Gemini, no external LLM)

## What's Removed (vs LSP version)
- ~~LSP proxy server (pygls, port 7777)~~
- ~~Dashboard (Flask, port 5050)~~
- ~~Remediator agent (Gemini Flash, ChromaDB)~~
- ~~Auditor agent (SHA-256 chain)~~
- ~~python-dotenv, rich, flask, flask-socketio, chromadb, sentence-transformers~~
- ~~google-adk / Gemini dependency~~
- ~~`.env` file with API keys~~

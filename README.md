# HalluciGuard — AI Package Hallucination Detector

> **Google India Hackathon 2025 Project**

A VS Code extension that detects hallucinated Python and JavaScript package references in AI-generated code — before they compromise your supply chain.

When LLMs (Copilot, Cursor, ChatGPT) generate import statements, they sometimes invent package names that don't exist on PyPI or npm. Attackers register those names with malicious payloads. HalluciGuard catches this in your editor before the code ever runs.

---

## How It Works

```
You open a .py / .js file
        ↓
HalluciGuard spawns bundled Python scanner
        ↓
3-agent pipeline per file:
  1. Sentinel   — AST parse → extract imports → filter stdlib
  2. Validator  — Bloom filter (802k packages) + PyPI/npm API + hallucination DB
  3. Profiler   — Weighted risk score (0–100)
        ↓
Results appear inline (squiggly lines) + sidebar TreeView
```

**No external server. No API keys. No network login.** The bloom filter and hallucination database ship inside the extension.

---

## Features

- **Inline diagnostics** — red/yellow squiggly lines on the import statement
- **Sidebar panel** — hierarchical view: File → Package → Risk details
- **Risk scoring** — weighted 0–100 score across 6 signals:
  | Signal | Weight | Source |
  |---|---|---|
  | Typosquat distance | 30 | Levenshtein vs 600+ popular packages |
  | Hallucination DB | 25 | Curated list of known fake packages |
  | Not on any registry | 25 | PyPI + npm API check |
  | Package age (recency) | 15 | Packages < 90 days old are penalised |
  | Low popularity | 15 | Download count heuristic |
  | CVE vulnerabilities | 10 | OSV.dev API |
- **Quick fixes** — one-click "Replace with `requests`" code action
- **Auto-scan on save** — optional, disabled by default
- **Works offline** — bloom filter check requires no network; registry check is best-effort

---

## Installation

### From Source (dev)

```bash
git clone https://github.com/Quantum-Blade1/HalluciGuard.git
cd HalluciGuard/vscode-extension
npm install
npm run compile
# Press F5 in VS Code to launch Extension Development Host
```

### Requirements

- VS Code 1.85+
- Python 3.9+ on your PATH (`python3` or configured via setting)
- pip (for first-run dependency install)

On first activation the extension runs:
```bash
pip install -r scanner/requirements.txt
```
Dependencies: `tree-sitter`, `httpx[http2]`, `rapidfuzz`, `pybloom-live`

---

## Usage

| Action | How |
|---|---|
| Scan workspace | Activity Bar shield icon → click **Scan Workspace** |
| Scan current file | Command Palette → `HalluciGuard: Scan Current File` |
| View results | Activity Bar → HalluciGuard sidebar |
| Rich panel | Command Palette → `HalluciGuard: Show Results Panel` |
| Clear all results | Command Palette → `HalluciGuard: Clear Results` |

### Settings

| Setting | Default | Description |
|---|---|---|
| `halluciguard.riskThreshold` | `65` | Minimum score to flag a package |
| `halluciguard.autoScanOnSave` | `false` | Auto-scan on file save |
| `halluciguard.pythonPath` | `python3` | Path to Python interpreter |
| `halluciguard.showPassedPackages` | `false` | Show safe packages in sidebar |

---

## Architecture

```
HalluciGuard/
├── vscode-extension/          # TypeScript VS Code extension
│   ├── src/
│   │   ├── extension.ts       # Activate/deactivate, commands, status bar
│   │   ├── scanner_bridge.ts  # Spawns Python subprocess, parses NDJSON stream
│   │   ├── results_provider.ts # Sidebar TreeView (File → Package → Flags)
│   │   ├── diagnostics.ts     # Inline squiggly lines + Quick Fix actions
│   │   └── webview_panel.ts   # Rich results WebView with risk gauge
│   ├── scanner/               # Bundled Python scanner (shipped in .vsix)
│   │   ├── halluciguard_scanner.py  # CLI entry — streams NDJSON to stdout
│   │   ├── agents/
│   │   │   ├── sentinel.py    # AST → imports
│   │   │   ├── validator.py   # Bloom + registry + hallucination DB
│   │   │   └── profiler.py    # Weighted risk scoring
│   │   ├── data/
│   │   │   ├── bloom_filter.py
│   │   │   ├── registry_client.py  # httpx async PyPI + npm checks
│   │   │   ├── hallucination_db.py
│   │   │   └── cve_client.py  # OSV.dev + SQLite cache
│   │   └── utils/
│   │       ├── ast_parser.py  # tree-sitter (Python + JS)
│   │       ├── levenshtein.py # rapidfuzz wrapper
│   │       └── module_to_package.py
│   └── data/                  # Package databases (shipped in .vsix)
│       ├── bloom/             # 802k PyPI + npm package names
│       └── hallucination_db/  # Known fake package names
├── scanner/                   # Source copy of bundled scanner (dev reference)
├── scripts/                   # Seed scripts for bloom filter + hallucination DB
├── tests/                     # pytest test suite
└── dashboard/                 # Standalone Flask demo dashboard (optional)
```

---

## Scanner NDJSON Protocol

The Python scanner streams one JSON object per line to stdout:

```jsonc
// Per finding
{"type": "finding", "file": "src/app.py", "package": "requets", "line": 3,
 "risk_score": 85, "action": "BLOCK", "flags": ["typosquat"], "nearest": "requests", "distance": 1}

// Progress
{"type": "progress", "file": "src/app.py", "status": "scanning"}

// Final summary
{"type": "summary", "files_scanned": 12, "packages_found": 3, "high_risk": 1, "duration_ms": 420}
```

`action` values: `BLOCK` (score ≥ 80) · `WARN` (score ≥ 65) · `ALLOW` (score < 65)

---

## Research Basis

Risk weights are derived from:
- Spracklen et al., *"We Have a Package for You!"* — USENIX Security 2025
- Vu et al., *MalOSS* — ICSE 2020 (typosquatting distance thresholds)
- OSV.dev open vulnerability database

---

## License

MIT © 2025 Krish Kumar Sharma

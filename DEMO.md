# HalluciGuard — Demo Walkthrough

This document covers the full demo flow using the bundled `demo_workspace/` directory,
which contains realistic AI-generated code seeded with hallucinated package imports.

---

## Demo Workspace Layout

```
demo_workspace/
├── src/
│   ├── auth.py       ← Python: 2 hallucinations (securehashlib, dataflow_engine)
│   └── utils.py      ← Python: 2 hallucinations (crypto_helper, logmanager)
└── frontend/
    └── index.js      ← JavaScript: 1 hallucination (secure-fetch-utils)
```

### Expected Results

| File | Package | Real? | Expected Action |
|---|---|---|---|
| `src/auth.py` | `securehashlib` | ✗ hallucinated | WARN (risk ≈ 68) |
| `src/auth.py` | `flask` | ✓ real | PASS |
| `src/auth.py` | `dataflow_engine` | ✗ hallucinated | WARN (risk ≈ 68) |
| `src/auth.py` | `requests` | ✓ real | PASS |
| `src/utils.py` | `crypto_helper` | ✗ hallucinated | WARN (risk ≈ 69) |
| `src/utils.py` | `logmanager` | ✗ hallucinated | WARN (risk ≈ 69) |
| `src/utils.py` | `json` | ✓ stdlib | filtered |
| `src/utils.py` | `numpy` | ✓ real | PASS |
| `frontend/index.js` | `express` | ✓ real | PASS |
| `frontend/index.js` | `secure-fetch-utils` | ✗ hallucinated | WARN (risk ≈ 68) |
| `frontend/index.js` | `axios` | ✓ real | PASS |
| `frontend/index.js` | `lodash` | ✓ real | PASS |

**Summary: 5 hallucinated · 6 real/stdlib · 0 false positives**

---

## Method 1 — CLI Scanner (fastest)

Run from the project root with the virtual environment active:

```bash
cd HalluciGuard
source .venv/bin/activate

python scanner/halluciguard_scanner.py --workspace demo_workspace/
```

### Expected stdout (NDJSON)

```json
{"type": "progress", "file": "frontend/index.js", "status": "scanning"}
{"type": "finding", "file": "frontend/index.js", "package": "secure-fetch-utils", "line": 2, "risk_score": 67.5, "action": "WARN", "flags": ["HALLUCINATION_DB_HIT", "NOT_IN_REGISTRY"], "nearest": "node-fetch", "distance": 11, "language": "javascript"}
{"type": "progress", "file": "src/auth.py", "status": "scanning"}
{"type": "finding", "file": "src/auth.py", "package": "securehashlib", "line": 2, "risk_score": 68.0, "action": "WARN", "flags": ["HALLUCINATION_DB_HIT", "NOT_IN_REGISTRY"], "nearest": "requests", "distance": 9, "language": "python"}
{"type": "finding", "file": "src/auth.py", "package": "dataflow_engine", "line": 4, "risk_score": 68.0, "action": "WARN", "flags": ["HALLUCINATION_DB_HIT", "NOT_IN_REGISTRY"], "nearest": "datadog", "distance": 9, "language": "python"}
{"type": "progress", "file": "src/utils.py", "status": "scanning"}
{"type": "finding", "file": "src/utils.py", "package": "crypto_helper", "line": 1, "risk_score": 69.3, "action": "WARN", "flags": ["HALLUCINATION_DB_HIT", "NOT_IN_REGISTRY"], "nearest": "cryptography", "distance": 6, "language": "python"}
{"type": "finding", "file": "src/utils.py", "package": "logmanager", "line": 2, "risk_score": 69.3, "action": "WARN", "flags": ["HALLUCINATION_DB_HIT", "NOT_IN_REGISTRY"], "nearest": "coverage", "distance": 6, "language": "python"}
{"type": "summary", "files_scanned": 3, "packages_found": 11, "high_risk": 5, "passed": 6, "duration_ms": 1887}
```

### Pretty-print with jq

```bash
python scanner/halluciguard_scanner.py --workspace demo_workspace/ 2>/dev/null \
  | jq 'select(.type == "finding") | {pkg: .package, score: .risk_score, file: .file, flags: .flags}'
```

### Scan a single file

```bash
python scanner/halluciguard_scanner.py \
  --workspace demo_workspace/ \
  --files src/auth.py
```

### Lower threshold to catch medium-risk packages

```bash
python scanner/halluciguard_scanner.py --workspace demo_workspace/ --threshold 40
```

---

## Method 2 — VS Code Extension

### Prerequisites

1. Install the extension from source:
   ```bash
   cd vscode-extension
   npm install
   npm run compile
   ```
2. Press **F5** in VS Code → opens Extension Development Host
3. In the new window: **File → Open Folder → select `demo_workspace/`**

### Running the scan

**Option A — Activity Bar:**
1. Click the **shield icon** in the left Activity Bar
2. In the HalluciGuard panel, click **Scan Workspace** (magnifying glass icon)

**Option B — Command Palette:**
1. `Cmd+Shift+P` → `HalluciGuard: Scan Workspace`

**Option C — File scan:**
1. Open `src/auth.py`
2. `Cmd+Shift+P` → `HalluciGuard: Scan Current File`
   — or click the file-code icon in the editor title bar

### What you'll see

**Status bar** (bottom-right):
```
🛡 5 issues
```

**Sidebar TreeView:**
```
HALLUCIGUARD: SCAN RESULTS
├── 📁 src/auth.py  (2 issues)
│   ├── 🔴 securehashlib  risk: 68  line 2
│   │   ├── Flags: HALLUCINATION_DB_HIT, NOT_IN_REGISTRY
│   │   └── Nearest real package: requests (distance 9)
│   └── 🔴 dataflow_engine  risk: 68  line 4
│       ├── Flags: HALLUCINATION_DB_HIT, NOT_IN_REGISTRY
│       └── Nearest real package: datadog (distance 9)
├── 📁 src/utils.py  (2 issues)
│   ├── 🔴 crypto_helper  risk: 69  line 1
│   │   ├── Flags: HALLUCINATION_DB_HIT, NOT_IN_REGISTRY
│   │   └── Nearest real package: cryptography (distance 6)
│   └── 🔴 logmanager  risk: 69  line 2
│       ├── Flags: HALLUCINATION_DB_HIT, NOT_IN_REGISTRY
│       └── Nearest real package: coverage (distance 6)
└── 📁 frontend/index.js  (1 issue)
    └── 🔴 secure-fetch-utils  risk: 68  line 2
        ├── Flags: HALLUCINATION_DB_HIT, NOT_IN_REGISTRY
        └── Nearest real package: node-fetch (distance 11)
```

**Inline diagnostics** — yellow squiggly lines under each flagged import:
- Open `src/auth.py` — squiggly on lines 2 (`securehashlib`) and 4 (`dataflow_engine`)
- Open `src/utils.py` — squiggly on lines 1 (`crypto_helper`) and 2 (`logmanager`)
- Open `frontend/index.js` — squiggly on line 2 (`secure-fetch-utils`)

**Hover a squiggly line:**
```
⚠ HalluciGuard [WARN]
securehashlib — risk score 68/100
Signals: HALLUCINATION_DB_HIT, NOT_IN_REGISTRY
Nearest real package: requests (edit distance 9)
```

**Rich Results Panel:**
1. Click **Show Results Panel** in the sidebar title bar (browser icon)
2. Shows card-per-package with animated risk gauge (0–100 arc), flags, and nearest real package

**Quick Fix:**
1. Hover a squiggly import line → click the lightbulb 💡
2. Actions offered:
   - `Replace 'crypto_helper' with 'cryptography'`
   - `Search 'crypto_helper' on PyPI`

---

## Risk Score Breakdown

Each flagged package scores against 6 weighted signals:

| Signal | Weight | Why it fires for demo packages |
|---|---|---|
| Hallucination DB hit | 25 | All 5 are in `known_hallucinations.json` |
| Not in any registry | 25 | None exist on PyPI or npm |
| Low/no popularity | 15 | Absent packages get full weight |
| Typosquat distance | 30 | None are close typos of popular packages (distance > 5) |
| Recency (new package) | 15 | N/A — absent packages |
| CVE vulnerabilities | 10 | N/A — not on any registry |

**Result: 25 + 25 + 15 = 65 minimum for all demo packages** → all hit the WARN threshold.

Real packages (`flask`, `requests`, `numpy`, `axios`, `lodash`, `express`) score 0 — they are in
the bloom filter (802k packages), exist on registry, and have no hallucination DB match.

`json` is Python stdlib — filtered by Sentinel before scoring.

---

## Adjusting Sensitivity

To flag **any unknown package** (even outside the hallucination DB):

```bash
# CLI: lower threshold to 40 (catches non_existent=25+popularity=15)
python scanner/halluciguard_scanner.py --workspace demo_workspace/ --threshold 40
```

In VS Code settings:
```json
"halluciguard.riskThreshold": 40
```

---

## Preload Warm-up (used internally by VS Code extension)

```bash
python scanner/halluciguard_scanner.py --preload-only
```

Output:
```json
{"type": "ready", "pypi_count": 802360, "npm_count": 1, "hallucination_count": 77, "load_time_ms": 312}
```

The extension calls this on activation to warm up the bloom filter so the first scan is instant.

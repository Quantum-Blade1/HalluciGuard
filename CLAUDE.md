# HalluciGuard

Real-time LSP middleware that intercepts AI-generated code completions, detects hallucinated package references via a 5-agent pipeline, and remediates them before code touches disk.

## Stack
- Python 3.11+ (Apple Silicon native)
- pygls 1.3.1 for LSP server on port 7777
- tree-sitter (0.22.3) + tree-sitter-python + tree-sitter-javascript for AST parsing
- Google ADK (google-adk) + Gemini 2.0 Flash for agent orchestration + remediation
- httpx[http2] for async registry lookups (PyPI + npm)
- rapidfuzz for Levenshtein distance computation
- chromadb + sentence-transformers/all-MiniLM-L6-v2 for safe-package RAG
- pybloom-live for bloom filter (PyPI 600k packages, 0.1% FP rate)
- OSV.dev API for CVE lookup, cached in SQLite with 24h TTL
- canonicaljson + hashlib for SHA-256 chained audit trail
- Flask + flask-socketio for demo dashboard
- python-dotenv, rich for utilities

## Architecture
5-agent sequential pipeline:
1. **Sentinel** — AST parse code → extract imports → filter stdlib → map module→package names
2. **Validator** — Bloom filter check (O(1)) → async HTTP to PyPI/npm for misses → hallucination DB check
3. **Profiler** — Weighted risk score (0-100): typosquat(30) + hallucination_db(25) + recency(15) + popularity(15) + cve(10) + cross_lang(5)
4. **Remediator** — Query ChromaDB for safe alternatives → Gemini Flash rewrites imports → AST patch
5. **Auditor** — SHA-256 chained JSONL log, tamper-evident

## Project Structure
src/
  main.py                  # Entry point — starts LSP proxy + optional dashboard
  core/
    config.py              # Constants, API keys, risk weights, stdlib sets
    lsp_proxy.py           # pygls LSP server (port 7777)
    pipeline.py            # Orchestrates 5-agent chain
  agents/
    sentinel.py            # Agent 1
    validator.py           # Agent 2
    profiler.py            # Agent 3
    remediator.py          # Agent 4
    auditor.py             # Agent 5
  data/
    bloom_filter.py        # Bloom filter for package existence
    registry_client.py     # Async PyPI + npm HTTP lookups
    chroma_manager.py      # ChromaDB vector store
    cve_client.py          # OSV.dev + SQLite cache
  utils/
    ast_parser.py          # tree-sitter + ast wrappers
    levenshtein.py         # rapidfuzz wrapper
    module_to_package.py   # Python module→PyPI package mapping
    hash_chain.py          # SHA-256 chain utility
data/
  bloom/                   # PyPI/npm package name JSON lists
  hallucination_db/        # Known hallucinated package names
  chroma_store/            # ChromaDB persistent storage
  cve_cache/               # SQLite CVE cache
scripts/
  seed_bloom.py            # Downloads PyPI/npm package lists
  seed_chroma.py           # Seeds ChromaDB with top packages
  seed_hallucination_db.py # Seeds known hallucination patterns
dashboard/
  app.py                   # Flask dashboard
  templates/index.html     # Dark-theme demo UI
vscode-extension/          # VS Code extension (TypeScript)
tests/

## Conventions
- Use dataclasses for all data structures, not dicts
- Type hints everywhere
- All agents are classes with a single main method (analyze/validate/profile/remediate/log_event)
- Async only where needed (registry HTTP calls) — rest is sync for simplicity
- Config in src/core/config.py via python-dotenv
- Risk score weights have paper citations in comments
- Never use sudo for pip

## Key Constants
- Risk threshold: 65 (configurable via RISK_THRESHOLD env var)
- LSP port: 7777
- Dashboard port: 5050
- Bloom filter FP rate: 0.001
- Gemini model: gemini-2.0-flash
- Python stdlib and JS builtins are in config.py (skip these in Sentinel)

## Testing
- pytest + pytest-asyncio
- Test with known hallucinated packages: securehashlib, dataflow_engine, crypto-helper
- Test with known good packages: flask, numpy, requests

## Environment
- Mac M5 (Apple Silicon)
- Python 3.11 via brew
- Venv at .venv/
- .env file with GEMINI_API_KEY

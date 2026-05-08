"""
HalluciGuard Dashboard — Flask + Flask-SocketIO.

Routes:
  GET  /              → demo UI
  POST /api/scan      → run pipeline on {code, language}, return JSON
  GET  /api/audit     → last 50 audit entries from the JSONL log
  GET  /api/stats     → running counters (for websocket-driven view)

The create_dashboard_app() factory is also called by main.py when
--dashboard is passed; it returns (app, socketio, emit_fn) so the
LSP proxy can push real-time events to connected browsers.
"""

from __future__ import annotations

import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any, Callable

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.core.config import AUDIT_LOG_PATH, DASHBOARD_PORT
from src.core.models import DashboardEvent


def create_dashboard_app() -> tuple[Flask, SocketIO, Callable]:
    """Create and return (app, socketio, emit_fn)."""

    app = Flask(__name__)
    app.config["SECRET_KEY"] = "halluciguard-dashboard-2024"
    socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

    # ── Lazy pipeline singleton ──────────────────────────────────────────────
    # Created on first /api/scan request so startup stays fast.
    _pipeline_holder: list = []

    def _get_pipeline():
        if not _pipeline_holder:
            from src.core.pipeline import HalluciGuardPipeline
            _pipeline_holder.append(HalluciGuardPipeline())
        return _pipeline_holder[0]

    # ── Running stats (updated by emit_fn, read by /api/stats) ──────────────
    stats: dict[str, Any] = {
        "total_scans": 0,
        "packages_flagged": 0,
        "remediations_applied": 0,
        "total_imports": 0,
        "avg_risk_score": 0.0,
        "risk_scores": [],
    }

    # ── Routes ───────────────────────────────────────────────────────────────

    @app.route("/")
    def index():
        from flask import make_response
        resp = make_response(render_template("index.html"))
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
        return resp

    @app.route("/api/scan", methods=["POST"])
    def api_scan():
        """Run the 5-agent pipeline on submitted code.

        Request JSON: { "code": "...", "language": "python" | "javascript" }

        Response JSON:
        {
          "profiles":          [...],   # one per package
          "remediations":      [...],   # one per high-risk package
          "annotations":       [...],   # line-level diagnostics
          "patched_code":      "...",
          "was_modified":      bool,
          "packages_found":    [...],
          "processing_time_ms": float
        }
        """
        body = request.get_json(force=True, silent=True) or {}
        code: str = body.get("code", "").strip()
        language: str = body.get("language", "python")

        if not code:
            return jsonify({"error": "No code provided"}), 400
        if language not in ("python", "javascript"):
            return jsonify({"error": "language must be 'python' or 'javascript'"}), 400

        try:
            pipeline = _get_pipeline()
            result = pipeline.process(code, language)
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

        profiles = [
            {
                "package_name": p.package_name,
                "risk_score": round(p.risk_score, 1),
                "flags": p.flags,
                "nearest_package": p.nearest_package,
                "levenshtein_distance": p.levenshtein_distance,
                "is_high_risk": p.is_high_risk,
            }
            for p in result.profiles
        ]

        remediations = [
            {
                "original_package": r.original_package,
                "suggested_package": r.suggested_package,
                "source": r.source,
                "confidence": round(r.confidence, 3),
                "alternatives": r.alternatives,
            }
            for r in result.remediations
        ]

        # Update running stats
        stats["total_scans"] += 1
        stats["total_imports"] += len(result.packages_found)
        high_risk = [p for p in result.profiles if p.is_high_risk]
        stats["packages_flagged"] += len(high_risk)
        stats["remediations_applied"] += len(result.remediations)
        for p in high_risk:
            stats["risk_scores"].append(p.risk_score)
        stats["risk_scores"] = stats["risk_scores"][-100:]
        if stats["risk_scores"]:
            stats["avg_risk_score"] = round(
                sum(stats["risk_scores"]) / len(stats["risk_scores"]), 1
            )

        return jsonify({
            "profiles": profiles,
            "remediations": remediations,
            "annotations": result.annotations,
            "patched_code": result.patched_code,
            "was_modified": result.was_modified,
            "packages_found": [p.package_name for p in result.packages_found],
            "processing_time_ms": round(result.processing_time_ms, 1),
        })

    @app.route("/api/audit")
    def api_audit():
        """Return the last 50 audit entries from the JSONL audit log."""
        entries: list[dict] = []
        if AUDIT_LOG_PATH.exists():
            try:
                with open(AUDIT_LOG_PATH, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                entries.append(json.loads(line))
                            except json.JSONDecodeError:
                                continue
            except OSError:
                pass
        return jsonify(entries[-50:])

    @app.route("/api/stats")
    def api_stats():
        return jsonify(stats)

    # kept for backward-compat with existing LSP integration
    @app.route("/api/audit-log")
    def api_audit_log():
        return api_audit()

    # ── SocketIO (real-time LSP events) ──────────────────────────────────────

    def emit_event(event: DashboardEvent) -> None:
        """Called by the LSP proxy to push pipeline events to the browser."""
        data = asdict(event)

        if event.event_type == "pipeline_complete":
            stats["total_scans"] += 1
            stats["total_imports"] += event.data.get("total_imports", 0)
            stats["packages_flagged"] += event.data.get("flagged", 0)
            stats["remediations_applied"] += event.data.get("remediations", 0)

        if event.event_type == "risk_alert":
            score = event.data.get("score", 0)
            stats["risk_scores"].append(score)
            stats["risk_scores"] = stats["risk_scores"][-100:]
            if stats["risk_scores"]:
                stats["avg_risk_score"] = round(
                    sum(stats["risk_scores"]) / len(stats["risk_scores"]), 1
                )

        socketio.emit(event.event_type, data)
        socketio.emit("stats_update", stats)

    @socketio.on("connect")
    def handle_connect():
        socketio.emit("stats_update", stats)

    return app, socketio, emit_event


# ── Standalone entry point ────────────────────────────────────────────────────

if __name__ == "__main__":
    app, socketio, _ = create_dashboard_app()
    socketio.run(app, host="0.0.0.0", port=DASHBOARD_PORT, debug=False,
                 allow_unsafe_werkzeug=True)

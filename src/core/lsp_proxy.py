"""
LSP Proxy Server — pygls 1.3.1 Language Server on TCP.

Intercepts textDocument/didOpen, textDocument/didChange, textDocument/didSave,
runs the HalluciGuard 5-agent pipeline, and publishes squiggly-line diagnostics
for every hallucinated import found in the document.
"""

from __future__ import annotations

import logging
from pathlib import PurePosixPath
from typing import Callable, Any
from urllib.parse import unquote, urlparse

from lsprotocol import types
from pygls.server import LanguageServer

from src.core.config import LSP_PORT, PipelineConfig
from src.core.models import DashboardEvent
from src.core.pipeline import HalluciGuardPipeline, PipelineResult

logger = logging.getLogger(__name__)


def _uri_to_path(uri: str) -> str:
    """Convert a file:// URI to a plain filesystem path."""
    parsed = urlparse(uri)
    return unquote(parsed.path)


def _detect_language(uri: str) -> str:
    """Infer language from file extension."""
    suffix = PurePosixPath(unquote(urlparse(uri).path)).suffix.lower()
    if suffix in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
        return "javascript"
    return "python"


class HalluciGuardServer(LanguageServer):
    """LSP server that runs HalluciGuard pipeline on every document event."""

    def __init__(
        self,
        config: PipelineConfig | None = None,
        dashboard_callback: Callable[[DashboardEvent], None] | None = None,
    ) -> None:
        super().__init__("halluciguard", "v1.0.0")
        self._pipeline = HalluciGuardPipeline(
            config=config or PipelineConfig(),
            dashboard_callback=dashboard_callback,
        )
        # Cache last scan result per URI so other features can inspect it
        self._results: dict[str, PipelineResult] = {}
        self._register_handlers()

    # ── Handler registration ─────────────────────────────────────────────────

    def _register_handlers(self) -> None:

        @self.feature(types.TEXT_DOCUMENT_DID_OPEN)
        async def did_open(params: types.DidOpenTextDocumentParams) -> None:
            uri = params.text_document.uri
            code = params.text_document.text
            logger.debug("didOpen: %s", _uri_to_path(uri))
            await self._scan_document(uri, code)

        @self.feature(types.TEXT_DOCUMENT_DID_CHANGE)
        async def did_change(params: types.DidChangeTextDocumentParams) -> None:
            uri = params.text_document.uri
            # Use the latest full-text snapshot held by pygls workspace
            doc = self.workspace.get_text_document(uri)
            code = doc.source
            logger.debug("didChange: %s", _uri_to_path(uri))
            await self._scan_document(uri, code)

        @self.feature(types.TEXT_DOCUMENT_DID_SAVE)
        async def did_save(params: types.DidSaveTextDocumentParams) -> None:
            uri = params.text_document.uri
            # params.text is present only when the client declares includeText;
            # fall back to the workspace snapshot so this always works.
            if params.text is not None:
                code = params.text
            else:
                doc = self.workspace.get_text_document(uri)
                code = doc.source
            logger.debug("didSave: %s", _uri_to_path(uri))
            await self._scan_document(uri, code)

    # ── Core scan ────────────────────────────────────────────────────────────

    async def _scan_document(self, uri: str, code: str) -> None:
        """Run the pipeline, cache the result, and publish LSP diagnostics.

        Diagnostic message format (per spec):
            ⚠️ Hallucinated package 'X' (risk: Y/100). Nearest real: 'Z' (distance: D)
        """
        if not code or not code.strip():
            self.publish_diagnostics(uri, [])
            return

        language = _detect_language(uri)

        try:
            result = await self._pipeline.run(code, _uri_to_path(uri))
        except Exception as exc:
            logger.error("Pipeline error for %s: %s", uri, exc, exc_info=True)
            return

        self._results[uri] = result

        # Index profiles and remediations for O(1) lookup
        profile_map = {p.package_name: p for p in result.profiles}
        remediation_map = {r.original_package: r for r in result.remediations}

        lines = code.splitlines()
        diagnostics: list[types.Diagnostic] = []

        for ref in result.packages_found:
            profile = profile_map.get(ref.package_name)
            if not profile or not profile.is_high_risk:
                continue

            nearest = profile.nearest_package or "unknown"
            distance = profile.levenshtein_distance
            rem = remediation_map.get(ref.package_name)

            message = (
                f"⚠️ Hallucinated package '{ref.package_name}' "
                f"(risk: {profile.risk_score:.0f}/100). "
                f"Nearest real: '{nearest}' (distance: {distance})"
            )
            if rem and rem.suggested_package:
                message += f". Suggested fix: '{rem.suggested_package}'"

            severity = (
                types.DiagnosticSeverity.Error
                if profile.risk_score >= 80
                else types.DiagnosticSeverity.Warning
            )

            # LSP lines are 0-indexed; Sentinel stores 1-indexed line numbers
            line = max(0, ref.line_no - 1)
            end_char = len(lines[line]) if line < len(lines) else 100

            diagnostics.append(
                types.Diagnostic(
                    range=types.Range(
                        start=types.Position(line=line, character=0),
                        end=types.Position(line=line, character=end_char),
                    ),
                    message=message,
                    severity=severity,
                    source="HalluciGuard",
                    code="HALLUCINATED-PKG",
                )
            )

        self.publish_diagnostics(uri, diagnostics)

        if diagnostics:
            logger.info(
                "Published %d diagnostic(s) for %s (%.0fms)",
                len(diagnostics),
                _uri_to_path(uri),
                result.processing_time_ms,
            )
        else:
            logger.debug(
                "No hallucinations in %s (%.0fms)",
                _uri_to_path(uri),
                result.processing_time_ms,
            )


# ── Module-level factory ─────────────────────────────────────────────────────

def create_server(
    config: PipelineConfig | None = None,
    dashboard_callback: Callable[[DashboardEvent], None] | None = None,
) -> HalluciGuardServer:
    """Construct and return a configured HalluciGuardServer."""
    return HalluciGuardServer(config=config, dashboard_callback=dashboard_callback)


def start_lsp_server(
    port: int | None = None,
    host: str = "localhost",
    config: PipelineConfig | None = None,
    dashboard_callback: Callable[[DashboardEvent], None] | None = None,
) -> None:
    """Start the HalluciGuard LSP server on TCP (blocking)."""
    server_port = port or LSP_PORT
    server = create_server(config=config, dashboard_callback=dashboard_callback)
    logger.info("HalluciGuard LSP listening on %s:%d", host, server_port)
    server.start_tcp(host, server_port)

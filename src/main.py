"""
HalluciGuard — Entry Point.

Usage:
    python -m src.main [--port PORT] [--dashboard] [--dashboard-port PORT] [--verbose]
"""

from __future__ import annotations

import argparse
import logging
import sys
import threading
import time

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from src.core.config import LSP_PORT, DASHBOARD_PORT, PipelineConfig, GEMINI_MODEL, GEMINI_API_KEY

console = Console()


# ── Logging ──────────────────────────────────────────────────────────────────

def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s  %(name)-28s  %(levelname)-7s  %(message)s",
        datefmt="%H:%M:%S",
    )
    # Quieten noisy third-party loggers unless verbose
    if not verbose:
        for noisy in ("pygls", "asyncio", "urllib3", "httpx", "httpcore"):
            logging.getLogger(noisy).setLevel(logging.WARNING)


# ── Startup panel ─────────────────────────────────────────────────────────────

def _print_startup_panel(
    lsp_port: int,
    dashboard_enabled: bool,
    dashboard_port: int,
    verbose: bool,
) -> None:
    """Print a rich startup panel with configuration summary."""
    # Info table inside the panel
    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    table.add_column("key", style="dim cyan", no_wrap=True)
    table.add_column("value", style="bold white")

    table.add_row("LSP server", f"tcp://localhost:{lsp_port}")
    table.add_row(
        "Dashboard",
        f"http://localhost:{dashboard_port}" if dashboard_enabled else "[dim]disabled[/dim]",
    )
    table.add_row(
        "Gemini model",
        GEMINI_MODEL if GEMINI_API_KEY else f"{GEMINI_MODEL} [dim](no API key — regex fallback)[/dim]",
    )
    table.add_row("Verbose logging", "[green]on[/green]" if verbose else "[dim]off[/dim]")

    panel = Panel(
        table,
        title="[bold cyan]🛡  HalluciGuard LSP Proxy[/bold cyan]",
        subtitle="[dim]AI Package Hallucination Detector[/dim]",
        border_style="cyan",
        padding=(1, 3),
    )
    console.print()
    console.print(panel)
    console.print()


# ── Audit log reset ──────────────────────────────────────────────────────────

def _clear_audit_log() -> None:
    """Truncate the audit log so each server session starts with a clean trail."""
    try:
        from src.core.config import AUDIT_LOG_PATH
        if AUDIT_LOG_PATH.exists():
            AUDIT_LOG_PATH.write_text("")
    except Exception:
        pass


# ── Bloom filter pre-load ────────────────────────────────────────────────────

def _load_bloom_filter() -> None:
    """Pre-load the bloom filter so the first scan isn't cold."""
    console.print("  [cyan]Loading package bloom filter…[/cyan]", end=" ")
    try:
        from src.data.bloom_filter import package_bloom_filter
        package_bloom_filter.load()
        pypi_count = len(package_bloom_filter.pypi_set)
        npm_count = len(package_bloom_filter.npm_set)
        console.print(
            f"[green]✓[/green]  "
            f"[dim]{pypi_count:,} PyPI + {npm_count:,} npm packages indexed[/dim]"
        )
    except Exception as exc:
        console.print(f"[yellow]⚠[/yellow]  [dim]Bloom filter unavailable: {exc}[/dim]")


# ── Dashboard thread ──────────────────────────────────────────────────────────

def _start_dashboard_thread(port: int, callback_slot: list) -> threading.Thread:
    """Start the Flask dashboard in a daemon thread.

    callback_slot is a one-element list; the dashboard emitter is appended
    to it once Flask is ready, so the caller can wire it into the pipeline.
    """
    def _run() -> None:
        try:
            from dashboard.app import create_dashboard_app
            app, socketio, emit_fn = create_dashboard_app()
            callback_slot.append(emit_fn)
            socketio.run(
                app,
                host="0.0.0.0",
                port=port,
                allow_unsafe_werkzeug=True,
                log_output=False,
            )
        except ImportError as exc:
            console.print(f"  [red]✗[/red]  Dashboard import error: {exc}")
        except Exception as exc:
            console.print(f"  [red]✗[/red]  Dashboard crashed: {exc}")

    thread = threading.Thread(target=_run, name="halluciguard-dashboard", daemon=True)
    thread.start()
    return thread


# ── Argument parsing ──────────────────────────────────────────────────────────

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="halluciguard",
        description="HalluciGuard — real-time AI package hallucination detector (LSP)",
    )
    parser.add_argument(
        "--port", type=int, default=LSP_PORT,
        metavar="PORT",
        help=f"LSP server TCP port (default: {LSP_PORT})",
    )
    parser.add_argument(
        "--dashboard", action="store_true",
        help="Start the real-time monitoring dashboard",
    )
    parser.add_argument(
        "--dashboard-port", type=int, default=DASHBOARD_PORT,
        metavar="PORT",
        dest="dashboard_port",
        help=f"Dashboard HTTP port (default: {DASHBOARD_PORT})",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable DEBUG logging",
    )
    return parser.parse_args()


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    args = _parse_args()
    _setup_logging(args.verbose)

    _print_startup_panel(
        lsp_port=args.port,
        dashboard_enabled=args.dashboard,
        dashboard_port=args.dashboard_port,
        verbose=args.verbose,
    )

    # Clear audit log from previous sessions so trail starts fresh
    _clear_audit_log()

    # Pre-load bloom filter (blocking, fast — reads local JSON)
    _load_bloom_filter()

    # Optionally start the Flask dashboard in a background daemon thread
    dashboard_callback = None
    if args.dashboard:
        console.print(f"  [cyan]Starting dashboard…[/cyan]", end=" ")
        slot: list = []
        _start_dashboard_thread(args.dashboard_port, slot)
        time.sleep(1.5)  # give Flask a moment to bind before printing status
        if slot:
            dashboard_callback = slot[0]
            console.print(
                f"[green]✓[/green]  "
                f"[dim]http://localhost:{args.dashboard_port}[/dim]"
            )
        else:
            console.print("[yellow]⚠[/yellow]  [dim]Dashboard not ready yet — continuing[/dim]")

    # Build pipeline config
    config = PipelineConfig(
        lsp_port=args.port,
        dashboard_port=args.dashboard_port,
        enable_dashboard=args.dashboard,
    )

    # Start LSP server (blocking — runs the asyncio event loop internally)
    console.print(
        f"\n  [green]✓[/green]  LSP server listening on "
        f"[bold]tcp://localhost:{args.port}[/bold]"
    )
    console.print("  [dim]Connect your editor and open a .py / .js / .ts file.[/dim]")
    console.print("  [dim]Press Ctrl+C to stop.[/dim]\n")

    try:
        from src.core.lsp_proxy import start_lsp_server
        start_lsp_server(
            port=args.port,
            host="localhost",
            config=config,
            dashboard_callback=dashboard_callback,
        )
    except KeyboardInterrupt:
        console.print("\n  [yellow]Shutting down — goodbye.[/yellow]\n")
    except Exception as exc:
        console.print(f"\n  [red bold]Fatal:[/red bold] {exc}\n")
        logging.exception("Unhandled error in LSP server")
        sys.exit(1)


if __name__ == "__main__":
    main()

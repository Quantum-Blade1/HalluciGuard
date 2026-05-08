import * as vscode from 'vscode';
import { ScanFinding, ScanSummary } from './scanner_bridge';

type JumpMessage = {
    command: 'jumpTo';
    file: string;
    line: number;
};

function escapeHtml(input: string): string {
    return input
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function nonce(): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let out = '';
    for (let i = 0; i < 32; i++) {
        out += chars[Math.floor(Math.random() * chars.length)];
    }
    return out;
}

function gaugeColor(score: number): string {
    if (score >= 65) {
        return 'var(--halluciguard-risk-high)';
    }
    if (score >= 40) {
        return 'var(--halluciguard-risk-med)';
    }
    return 'var(--halluciguard-risk-low)';
}

function flagChipColor(flag: string): string {
    if (flag.includes('HALLUCINATION')) { return 'var(--halluciguard-risk-high)'; }
    if (flag.includes('NOT_IN_REGISTRY')) { return 'var(--halluciguard-risk-high)'; }
    if (flag.includes('TYPOSQUAT')) { return 'var(--halluciguard-risk-med)'; }
    if (flag.includes('VULNERABLE')) { return 'var(--halluciguard-risk-med)'; }
    return 'var(--vscode-badge-background)';
}

export class HalluciGuardPanel {
    public static currentPanel: HalluciGuardPanel | undefined;

    private readonly panel: vscode.WebviewPanel;
    private readonly extensionUri: vscode.Uri;
    private workspaceRoot: vscode.Uri | null = null;

    private findings: ScanFinding[] = [];
    private summary: ScanSummary | null = null;

    private disposables: vscode.Disposable[] = [];

    private constructor(panel: vscode.WebviewPanel, extensionUri: vscode.Uri) {
        this.panel = panel;
        this.extensionUri = extensionUri;

        this.panel.onDidDispose(() => this.dispose(), null, this.disposables);
        this.panel.webview.onDidReceiveMessage((msg: unknown) => this.onMessage(msg), null, this.disposables);
    }

    static createOrShow(
        context: vscode.ExtensionContext,
        args?: { findings: ScanFinding[]; summary: ScanSummary; workspaceRoot: string },
    ): HalluciGuardPanel {
        const column = vscode.window.activeTextEditor?.viewColumn ?? vscode.ViewColumn.Beside;

        if (HalluciGuardPanel.currentPanel) {
            HalluciGuardPanel.currentPanel.panel.reveal(column);
            if (args) {
                HalluciGuardPanel.currentPanel.setResults(args.findings, args.summary, args.workspaceRoot);
            }
            return HalluciGuardPanel.currentPanel;
        }

        const panel = vscode.window.createWebviewPanel(
            'halluciguardPanel',
            'HalluciGuard Results',
            column,
            {
                enableScripts: true,
                retainContextWhenHidden: true,
            },
        );

        const instance = new HalluciGuardPanel(panel, context.extensionUri);
        HalluciGuardPanel.currentPanel = instance;

        if (args) {
            instance.setResults(args.findings, args.summary, args.workspaceRoot);
        } else {
            instance.render();
        }

        return instance;
    }

    setResults(findings: ScanFinding[], summary: ScanSummary, workspaceRoot: string): void {
        this.findings = findings;
        this.summary = summary;
        this.workspaceRoot = vscode.Uri.file(workspaceRoot);
        this.render();
    }

    dispose(): void {
        HalluciGuardPanel.currentPanel = undefined;
        while (this.disposables.length) {
            this.disposables.pop()?.dispose();
        }
    }

    private async onMessage(msg: unknown): Promise<void> {
        const m = msg as Partial<JumpMessage>;
        if (m.command !== 'jumpTo' || !m.file || typeof m.line !== 'number') {
            return;
        }
        if (!this.workspaceRoot) {
            return;
        }

        const uri = vscode.Uri.joinPath(this.workspaceRoot, m.file);
        const doc = await vscode.workspace.openTextDocument(uri);
        const editor = await vscode.window.showTextDocument(doc, { preview: true });
        const pos = new vscode.Position(Math.max(0, m.line - 1), 0);
        editor.selection = new vscode.Selection(pos, pos);
        editor.revealRange(new vscode.Range(pos, pos), vscode.TextEditorRevealType.InCenter);
    }

    private render(): void {
        const webview = this.panel.webview;
        const n = nonce();
        this.panel.webview.html = HalluciGuardPanel.getHtmlContent(this.findings, this.summary, n);
    }

    static getHtmlContent(findings: ScanFinding[], summary: ScanSummary | null, n: string): string {
        const byFile = new Map<string, ScanFinding[]>();
        for (const f of findings) {
            const list = byFile.get(f.file) ?? [];
            list.push(f);
            byFile.set(f.file, list);
        }
        for (const list of byFile.values()) {
            list.sort((a, b) => a.line - b.line);
        }

        const summaryHtml = summary
            ? `
                <div class="summaryBar">
                    <div class="summaryItem"><span class="k">Files</span><span class="v">${summary.filesScanned}</span></div>
                    <div class="summaryItem"><span class="k">Issues</span><span class="v">${summary.highRisk}</span></div>
                    <div class="summaryItem"><span class="k">Duration</span><span class="v">${summary.durationMs}ms</span></div>
                </div>
            `
            : `
                <div class="summaryBar">
                    <div class="summaryItem"><span class="k">HalluciGuard</span><span class="v">Run a scan to view results</span></div>
                </div>
            `;

        const fileSections = [...byFile.entries()]
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([file, fileFindings]) => {
                const cards = fileFindings.map((f, idx) => {
                    const safePkg = escapeHtml(f.package);
                    const safeNearest = escapeHtml(f.nearest ?? '');
                    const safeFlags = (f.flags ?? []).map(flag => {
                        const safeFlag = escapeHtml(flag);
                        return `<span class="chip" style="--chipBg:${flagChipColor(flag)}">${safeFlag}</span>`;
                    }).join('');

                    const score = Math.round(f.riskScore);
                    const arcColor = gaugeColor(score);

                    return `
                        <details class="card" ${idx === 0 ? 'open' : ''}>
                            <summary class="cardHeader">
                                <div class="pkgTitle">${safePkg}</div>
                                <div class="meta">
                                    <span class="riskPill">${score}/100 · ${escapeHtml(f.action)}</span>
                                </div>
                            </summary>

                            <div class="cardBody">
                                <div class="row">
                                    <div class="gaugeWrap">
                                        ${HalluciGuardPanel.renderGaugeSvg(score, arcColor)}
                                        <div class="gaugeLabel">Risk score</div>
                                    </div>

                                    <div class="details">
                                        <div class="flags">
                                            <div class="sectionTitle">Signals</div>
                                            <div class="chipRow">${safeFlags || '<span class=\"muted\">None</span>'}</div>
                                        </div>

                                        <div class="nearest">
                                            <div class="sectionTitle">Nearest real package</div>
                                            <div class="diff" data-a="${safePkg}" data-b="${safeNearest}"></div>
                                            <div class="muted">Edit distance: ${escapeHtml(String(f.distance))}</div>
                                        </div>

                                        <div class="actions">
                                            <button class="btn" data-jump="1" data-file="${escapeHtml(f.file)}" data-line="${escapeHtml(String(f.line))}">
                                                Jump to line ${escapeHtml(String(f.line))}
                                            </button>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </details>
                    `;
                }).join('');

                return `
                    <section class="fileSection">
                        <h2 class="fileTitle">${escapeHtml(file)} <span class="badge">${fileFindings.length} issues</span></h2>
                        <div class="cards">${cards}</div>
                    </section>
                `;
            })
            .join('');

        const empty = findings.length === 0 && summary ? `<div class="empty">No issues found.</div>` : '';

        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src ${'vscode-resource:'} https:; style-src 'unsafe-inline'; script-src 'nonce-${n}';" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>HalluciGuard Results</title>
    <style>
        :root {
            --bg: var(--vscode-editor-background);
            --fg: var(--vscode-editor-foreground);
            --muted: var(--vscode-descriptionForeground);
            --border: var(--vscode-panel-border);
            --cardBg: color-mix(in srgb, var(--bg) 92%, #ffffff 8%);
            --halluciguard-risk-high: #f14c4c;
            --halluciguard-risk-med: #cca700;
            --halluciguard-risk-low: #3fb950;
        }
        body {
            margin: 0;
            padding: 0;
            background: var(--bg);
            color: var(--fg);
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
        }
        .container { padding: 14px 16px 40px; max-width: 980px; margin: 0 auto; }
        .summaryBar {
            position: sticky;
            top: 0;
            background: color-mix(in srgb, var(--bg) 90%, #000 10%);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 10px 12px;
            display: flex;
            gap: 16px;
            align-items: center;
            z-index: 10;
            backdrop-filter: blur(10px);
        }
        .summaryItem { display: flex; gap: 8px; align-items: baseline; }
        .summaryItem .k { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; }
        .summaryItem .v { font-weight: 650; }

        .fileSection { margin-top: 18px; }
        .fileTitle { font-size: 14px; font-weight: 700; margin: 10px 0; display: flex; gap: 10px; align-items: center; }
        .badge {
            font-size: 12px;
            padding: 2px 8px;
            border-radius: 999px;
            background: var(--vscode-badge-background);
            color: var(--vscode-badge-foreground);
        }

        details.card {
            border: 1px solid var(--border);
            border-radius: 12px;
            background: var(--cardBg);
            overflow: hidden;
            margin-bottom: 10px;
        }
        summary.cardHeader {
            list-style: none;
            cursor: pointer;
            padding: 12px 12px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 12px;
            user-select: none;
        }
        summary.cardHeader::-webkit-details-marker { display:none; }
        .pkgTitle { font-size: 16px; font-weight: 750; }
        .riskPill {
            font-size: 12px;
            padding: 4px 8px;
            border-radius: 999px;
            border: 1px solid var(--border);
            color: var(--fg);
            opacity: 0.95;
        }
        .cardBody { padding: 12px; border-top: 1px solid var(--border); }
        .row { display: grid; grid-template-columns: 170px 1fr; gap: 14px; align-items: start; }
        .gaugeWrap { display: grid; gap: 6px; justify-items: center; }
        .gaugeLabel { font-size: 12px; color: var(--muted); }
        .sectionTitle { font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 6px; }
        .chipRow { display: flex; flex-wrap: wrap; gap: 6px; }
        .chip {
            font-size: 12px;
            padding: 3px 8px;
            border-radius: 999px;
            background: var(--chipBg, var(--vscode-badge-background));
            color: #111;
            border: 1px solid color-mix(in srgb, var(--chipBg, #888) 70%, #000 30%);
        }
        .muted { color: var(--muted); font-size: 12px; margin-top: 6px; }
        .diff { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 12px; padding: 8px 10px; border: 1px solid var(--border); border-radius: 10px; background: color-mix(in srgb, var(--bg) 85%, #000 15%); }
        .diff .line { display: flex; gap: 10px; align-items: baseline; }
        .diff .tag { width: 62px; color: var(--muted); text-transform: uppercase; font-size: 11px; letter-spacing: 0.08em; }
        .diff .s { overflow-wrap: anywhere; }
        .diff .hl { background: color-mix(in srgb, var(--halluciguard-risk-high) 35%, transparent); border-radius: 4px; padding: 0 2px; }

        .actions { margin-top: 10px; }
        .btn {
            background: var(--vscode-button-background);
            color: var(--vscode-button-foreground);
            border: 1px solid var(--vscode-button-border, transparent);
            border-radius: 8px;
            padding: 8px 10px;
            cursor: pointer;
        }
        .btn:hover { background: var(--vscode-button-hoverBackground); }
        .empty { margin-top: 18px; color: var(--muted); }
    </style>
</head>
<body>
    <div class="container">
        ${summaryHtml}
        ${empty}
        ${fileSections}
    </div>

    <script nonce="${n}">
        const vscode = acquireVsCodeApi();

        function renderDiff(a, b) {
            const maxLen = Math.max(a.length, b.length);
            let outA = '';
            let outB = '';
            for (let i = 0; i < maxLen; i++) {
                const ca = a[i] ?? '';
                const cb = b[i] ?? '';
                const diff = ca !== cb;
                outA += diff && ca ? '<span class=\"hl\">' + escapeHtml(ca) + '</span>' : escapeHtml(ca);
                outB += diff && cb ? '<span class=\"hl\">' + escapeHtml(cb) + '</span>' : escapeHtml(cb);
            }
            return '<div class=\"line\"><span class=\"tag\">given</span><span class=\"s\">' + outA + '</span></div>' +
                   '<div class=\"line\"><span class=\"tag\">nearest</span><span class=\"s\">' + outB + '</span></div>';
        }

        function escapeHtml(s) {
            return String(s)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/\"/g, '&quot;')
                .replace(/'/g, '&#039;');
        }

        document.querySelectorAll('.diff').forEach((el) => {
            const a = el.getAttribute('data-a') || '';
            const b = el.getAttribute('data-b') || '';
            el.innerHTML = renderDiff(a, b);
        });

        document.querySelectorAll('button[data-jump=\"1\"]').forEach((btn) => {
            btn.addEventListener('click', () => {
                const file = btn.getAttribute('data-file');
                const line = Number(btn.getAttribute('data-line'));
                if (!file || !Number.isFinite(line)) return;
                vscode.postMessage({ command: 'jumpTo', file, line });
            });
        });
    </script>
</body>
</html>`;
    }

    private static renderGaugeSvg(score: number, arcColor: string): string {
        const clamped = Math.max(0, Math.min(100, score));
        const radius = 46;
        const cx = 52;
        const cy = 52;

        const startAngle = -210;
        const endAngle = 30;
        const totalSpan = endAngle - startAngle;
        const span = (clamped / 100) * totalSpan;

        const start = HalluciGuardPanel.polarToCartesian(cx, cy, radius, endAngle);
        const end = HalluciGuardPanel.polarToCartesian(cx, cy, radius, startAngle + span);
        const largeArc = span > 180 ? 1 : 0;

        const bgStart = HalluciGuardPanel.polarToCartesian(cx, cy, radius, endAngle);
        const bgEnd = HalluciGuardPanel.polarToCartesian(cx, cy, radius, startAngle);

        const pathBg = `M ${bgStart.x} ${bgStart.y} A ${radius} ${radius} 0 1 0 ${bgEnd.x} ${bgEnd.y}`;
        const pathFg = `M ${start.x} ${start.y} A ${radius} ${radius} 0 ${largeArc} 0 ${end.x} ${end.y}`;

        return `
            <svg width="104" height="104" viewBox="0 0 104 104" role="img" aria-label="Risk score ${clamped}">
                <path d="${pathBg}" stroke="color-mix(in srgb, var(--vscode-panel-border) 70%, transparent)" stroke-width="10" fill="none" stroke-linecap="round"></path>
                <path d="${pathFg}" stroke="${arcColor}" stroke-width="10" fill="none" stroke-linecap="round"></path>
                <text x="52" y="58" text-anchor="middle" font-size="18" font-weight="750" fill="var(--vscode-editor-foreground)">${clamped}</text>
            </svg>
        `;
    }

    private static polarToCartesian(cx: number, cy: number, r: number, angleDeg: number): { x: number; y: number } {
        const angleRad = (Math.PI / 180) * angleDeg;
        return {
            x: cx + r * Math.cos(angleRad),
            y: cy + r * Math.sin(angleRad),
        };
    }
}


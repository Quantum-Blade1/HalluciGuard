/**
 * HalluciGuard Diagnostics — Inline squiggly lines + Quick Fix code actions.
 *
 * This module owns the VS Code DiagnosticCollection and a CodeActionProvider.
 * It converts ScanFinding[] into inline diagnostics (yellow/red underlines)
 * and offers "Replace with nearest package" quick fixes for typosquat findings.
 */

import * as vscode from 'vscode';
import * as path from 'path';
import { ScanFinding } from './scanner_bridge';

// ── Constants ───────────────────────────────────────────────────────────────

/** Diagnostic source identifier shown in the Problems panel. */
const DIAGNOSTIC_SOURCE = 'HalluciGuard';

/** Diagnostics with this code prefix are eligible for quick fixes. */
const CODE_PREFIX = 'HALLUCIGUARD';

/** Maximum Levenshtein distance for which we offer a "Replace with X" fix. */
const MAX_FIX_DISTANCE = 3;

// ── Custom diagnostic data ──────────────────────────────────────────────────

/**
 * Extra metadata attached to each diagnostic via Diagnostic.code.
 * We use a compound code object so VS Code shows the flag name in the UI
 * while we stash the full finding for the CodeActionProvider.
 */
interface DiagnosticData {
    finding: ScanFinding;
}

// ── HalluciGuardDiagnostics ─────────────────────────────────────────────────

export class HalluciGuardDiagnostics implements vscode.Disposable {
    private readonly collection: vscode.DiagnosticCollection;

    /**
     * Map from file URI string → ScanFinding[] so the CodeActionProvider
     * can look up findings for a given document without re-parsing.
     */
    private readonly findingsByFile = new Map<string, ScanFinding[]>();

    constructor() {
        this.collection = vscode.languages.createDiagnosticCollection('halluciguard');
    }

    // ── Public API ──────────────────────────────────────────────────────────

    /**
     * Replace all diagnostics with a new set of findings.
     *
     * Groups findings by file, creates one Diagnostic per finding,
     * and sets the appropriate severity based on risk score.
     *
     * @param findings - Array of ScanFinding from the scanner bridge.
     * @param workspacePath - Workspace root for resolving relative file paths.
     */
    update(findings: ScanFinding[], workspacePath: string): void {
        // Clear previous results
        this.collection.clear();
        this.findingsByFile.clear();

        // Group findings by file
        const grouped = new Map<string, ScanFinding[]>();
        for (const finding of findings) {
            const existing = grouped.get(finding.file) ?? [];
            existing.push(finding);
            grouped.set(finding.file, existing);
        }

        // Create diagnostics per file
        for (const [relPath, fileFindings] of grouped) {
            const uri = vscode.Uri.file(
                vscode.Uri.joinPath(vscode.Uri.file(workspacePath), relPath).fsPath
            );
            const diagnostics = fileFindings.map(f => this.createDiagnostic(f));
            this.collection.set(uri, diagnostics);
            this.findingsByFile.set(uri.toString(), fileFindings);
        }
    }

    /**
     * Update diagnostics for a single file only (keeps other files intact).
     */
    updateFile(uri: vscode.Uri, findings: ScanFinding[], workspacePath: string): void {
        const relPath = path.relative(workspacePath, uri.fsPath);
        const fileFindings = findings.filter(f => f.file === relPath);
        const diagnostics = fileFindings.map(f => this.createDiagnostic(f));

        this.collection.set(uri, diagnostics);
        if (fileFindings.length > 0) {
            this.findingsByFile.set(uri.toString(), fileFindings);
        } else {
            this.findingsByFile.delete(uri.toString());
        }
    }

    /**
     * Clear all diagnostics across all files.
     */
    clear(): void {
        this.collection.clear();
        this.findingsByFile.clear();
    }

    /**
     * Clear diagnostics for a single file.
     */
    clearFile(uri: vscode.Uri): void {
        this.collection.delete(uri);
        this.findingsByFile.delete(uri.toString());
    }

    /**
     * Get findings associated with a specific document URI.
     */
    getFindingsForUri(uri: vscode.Uri): ScanFinding[] {
        return this.findingsByFile.get(uri.toString()) ?? [];
    }

    /**
     * Get total number of active diagnostics.
     */
    get count(): number {
        let total = 0;
        this.collection.forEach((_, diagnostics) => {
            total += diagnostics.length;
        });
        return total;
    }

    dispose(): void {
        this.collection.dispose();
        this.findingsByFile.clear();
    }

    // ── Private helpers ─────────────────────────────────────────────────────

    /**
     * Create a single VS Code Diagnostic from a ScanFinding.
     */
    private createDiagnostic(finding: ScanFinding): vscode.Diagnostic {
        // Line numbers from the scanner are 1-based; VS Code is 0-based
        const line = Math.max(0, finding.line - 1);
        const range = new vscode.Range(line, 0, line, 999);

        // Build human-readable message
        const message = this.buildMessage(finding);

        // Determine severity from risk score
        const severity = this.getSeverity(finding);

        const diagnostic = new vscode.Diagnostic(range, message, severity);
        diagnostic.source = DIAGNOSTIC_SOURCE;

        // Use the top flag as the diagnostic code for filtering in Problems panel
        const topFlag = finding.flags[0] ?? 'SUSPICIOUS';
        diagnostic.code = `${CODE_PREFIX}_${topFlag}`;

        // Tag with "Unnecessary" for low-confidence findings, "Deprecated" for high
        if (finding.action === 'BLOCK') {
            diagnostic.tags = [vscode.DiagnosticTag.Deprecated];
        }

        // Attach related information showing nearest real package
        if (finding.nearest && finding.distance > 0) {
            diagnostic.relatedInformation = [
                new vscode.DiagnosticRelatedInformation(
                    new vscode.Location(
                        vscode.Uri.parse('https://pypi.org/project/' + finding.nearest),
                        new vscode.Position(0, 0)
                    ),
                    `Nearest real package: '${finding.nearest}' (Levenshtein distance: ${finding.distance})`
                ),
            ];
        }

        return diagnostic;
    }

    /**
     * Build the diagnostic message string.
     */
    private buildMessage(finding: ScanFinding): string {
        const icon = finding.action === 'BLOCK' ? '🚫' : '⚠️';
        let msg = `${icon} HalluciGuard: Hallucinated package '${finding.package}' ` +
                  `(risk: ${finding.riskScore}/100)`;

        if (finding.nearest && finding.distance > 0) {
            msg += `. Nearest real package: '${finding.nearest}' (distance: ${finding.distance})`;
        }

        if (finding.flags.length > 0) {
            msg += ` [${finding.flags.join(', ')}]`;
        }

        return msg;
    }

    /**
     * Map risk score to VS Code diagnostic severity.
     *
     * - BLOCK (score >= 80): Error (red squiggly)
     * - WARN  (score >= threshold): Warning (yellow squiggly)
     * - Below threshold but still flagged: Information (blue squiggly)
     */
    private getSeverity(finding: ScanFinding): vscode.DiagnosticSeverity {
        if (finding.action === 'BLOCK') {
            return vscode.DiagnosticSeverity.Error;
        }
        if (finding.action === 'WARN') {
            return vscode.DiagnosticSeverity.Warning;
        }
        return vscode.DiagnosticSeverity.Information;
    }
}

// ── HalluciGuardCodeActionProvider ──────────────────────────────────────────

/**
 * Provides Quick Fix code actions for hallucinated package imports.
 *
 * When the nearest real package is within Levenshtein distance <= 3,
 * offers "Replace '${pkg}' with '${nearest}'" as a preferred fix.
 */
export class HalluciGuardCodeActionProvider implements vscode.CodeActionProvider {
    static readonly providedCodeActionKinds = [
        vscode.CodeActionKind.QuickFix,
    ];

    private readonly diagnostics: HalluciGuardDiagnostics;

    constructor(diagnostics: HalluciGuardDiagnostics) {
        this.diagnostics = diagnostics;
    }

    provideCodeActions(
        document: vscode.TextDocument,
        range: vscode.Range | vscode.Selection,
        context: vscode.CodeActionContext,
        _token: vscode.CancellationToken,
    ): vscode.CodeAction[] {
        const actions: vscode.CodeAction[] = [];

        // Only process our own diagnostics
        const ourDiagnostics = context.diagnostics.filter(
            d => d.source === DIAGNOSTIC_SOURCE
        );

        const findings = this.diagnostics.getFindingsForUri(document.uri);

        for (const diagnostic of ourDiagnostics) {
            // Find the matching ScanFinding for this diagnostic line
            const finding = findings.find(
                f => (f.line - 1) === diagnostic.range.start.line
            );

            if (!finding) {
                continue;
            }

            // Offer replacement fix if we have a curated suggestion OR a close typosquat
            const hasSuggestion = finding.suggested && finding.suggested.length > 0;
            const isCloseTypo = finding.nearest && finding.distance > 0 && finding.distance <= MAX_FIX_DISTANCE;
            if (hasSuggestion || isCloseTypo) {
                const replaceAction = this.createReplaceAction(document, diagnostic, finding);
                if (replaceAction) {
                    actions.push(replaceAction);
                }
            }

            // Always offer "Learn more" action that opens the package on PyPI/npm
            const learnMoreAction = this.createLearnMoreAction(finding);
            actions.push(learnMoreAction);
        }

        return actions;
    }

    /**
     * Create a Quick Fix that replaces the hallucinated package name
     * with the nearest real package in the import statement.
     */
    private createReplaceAction(
        document: vscode.TextDocument,
        diagnostic: vscode.Diagnostic,
        finding: ScanFinding,
    ): vscode.CodeAction | null {
        const line = document.lineAt(diagnostic.range.start.line);
        const lineText = line.text;

        // Find the hallucinated package name in the import line
        const pkgIndex = lineText.indexOf(finding.package);
        if (pkgIndex === -1) {
            // Package name not found literally — try with underscores/hyphens swapped
            const variants = [
                finding.package,
                finding.package.replace(/-/g, '_'),
                finding.package.replace(/_/g, '-'),
            ];

            for (const variant of variants) {
                const idx = lineText.indexOf(variant);
                if (idx !== -1) {
                    return this.buildReplaceAction(document, line, idx, variant, finding);
                }
            }

            return null;
        }

        return this.buildReplaceAction(document, line, pkgIndex, finding.package, finding);
    }

    private buildReplaceAction(
        document: vscode.TextDocument,
        line: vscode.TextLine,
        startCol: number,
        oldText: string,
        finding: ScanFinding,
    ): vscode.CodeAction {
        // Prefer curated suggestion over Levenshtein nearest
        const fixTarget = (finding.suggested && finding.suggested.length > 0)
            ? finding.suggested
            : finding.nearest;

        const action = new vscode.CodeAction(
            `Replace '${finding.package}' with '${fixTarget}'`,
            vscode.CodeActionKind.QuickFix,
        );

        // Determine the replacement text, preserving underscore/hyphen convention
        let replacement = fixTarget;
        if (oldText.includes('_') && !replacement.includes('_')) {
            replacement = replacement.replace(/-/g, '_');
        }

        const replaceRange = new vscode.Range(
            line.lineNumber, startCol,
            line.lineNumber, startCol + oldText.length,
        );

        const edit = new vscode.WorkspaceEdit();
        edit.replace(document.uri, replaceRange, replacement);
        action.edit = edit;

        action.isPreferred = true;
        action.diagnostics = [
            // Re-find the diagnostic from the collection to link properly
            ...this.findDiagnosticsAtLine(document.uri, line.lineNumber),
        ];

        return action;
    }

    /**
     * Create an informational action that opens the nearest package's registry page.
     */
    private createLearnMoreAction(finding: ScanFinding): vscode.CodeAction {
        const registryUrl = finding.language === 'javascript'
            ? `https://www.npmjs.com/package/${finding.nearest || finding.package}`
            : `https://pypi.org/project/${finding.nearest || finding.package}/`;

        const action = new vscode.CodeAction(
            `Search for '${finding.nearest || finding.package}' on ${finding.language === 'javascript' ? 'npm' : 'PyPI'}`,
            vscode.CodeActionKind.QuickFix,
        );

        action.command = {
            command: 'vscode.open',
            title: 'Open Registry',
            arguments: [vscode.Uri.parse(registryUrl)],
        };

        return action;
    }

    /**
     * Find all HalluciGuard diagnostics at a given line in a document.
     */
    private findDiagnosticsAtLine(uri: vscode.Uri, line: number): vscode.Diagnostic[] {
        const allDiagnostics = vscode.languages.getDiagnostics(uri);
        return allDiagnostics.filter(
            d => d.source === DIAGNOSTIC_SOURCE && d.range.start.line === line
        );
    }
}

// ── Registration helper ─────────────────────────────────────────────────────

/**
 * Register the CodeActionProvider for Python and JavaScript files.
 * Call this from extension.ts activate().
 *
 * @returns Disposable to add to context.subscriptions.
 */
export function registerCodeActionProvider(
    diagnostics: HalluciGuardDiagnostics,
): vscode.Disposable {
    return vscode.languages.registerCodeActionsProvider(
        [
            { scheme: 'file', language: 'python' },
            { scheme: 'file', language: 'javascript' },
            { scheme: 'file', language: 'typescript' },
        ],
        new HalluciGuardCodeActionProvider(diagnostics),
        {
            providedCodeActionKinds: HalluciGuardCodeActionProvider.providedCodeActionKinds,
        },
    );
}

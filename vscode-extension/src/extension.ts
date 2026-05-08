import * as vscode from 'vscode';
import { ScannerBridge } from './scanner_bridge';
import { HalluciGuardDiagnostics, registerCodeActionProvider } from './diagnostics';
import { ScanResultsProvider } from './results_provider';
import * as path from 'path';
import { HalluciGuardPanel } from './webview_panel';

let scanner: ScannerBridge | undefined;
let diagnostics: HalluciGuardDiagnostics | undefined;
let resultsProvider: ScanResultsProvider | undefined;
let statusBarItem: vscode.StatusBarItem | undefined;
let extensionContext: vscode.ExtensionContext | undefined;

let lastFindings: import('./scanner_bridge').ScanFinding[] = [];
let lastSummary: import('./scanner_bridge').ScanSummary | null = null;
let lastWorkspaceRoot: string | null = null;

export async function activate(context: vscode.ExtensionContext): Promise<void> {
    extensionContext = context;
    // 1. Initialize components
    scanner = new ScannerBridge(context.extensionPath);
    diagnostics = new HalluciGuardDiagnostics();
    resultsProvider = new ScanResultsProvider();

    // 2. Register UI elements
    vscode.window.registerTreeDataProvider('halluciguardResults', resultsProvider);
    context.subscriptions.push(diagnostics, registerCodeActionProvider(diagnostics));

    // 3. Status bar
    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    statusBarItem.text = '$(shield) HalluciGuard';
    statusBarItem.command = 'halluciguard.scanWorkspace';
    statusBarItem.show();
    context.subscriptions.push(statusBarItem);

    // 4. Register Commands
    context.subscriptions.push(
        vscode.commands.registerCommand('halluciguard.scanWorkspace', () => scanWorkspace()),
        vscode.commands.registerCommand('halluciguard.scanCurrentFile', () => scanCurrentFile()),
        vscode.commands.registerCommand('halluciguard.clearResults', () => clearResults()),
        vscode.commands.registerCommand('halluciguard.showPanel', () => showPanel()),
    );

    // 5. Setup Auto-Scan on Save
    context.subscriptions.push(
        vscode.workspace.onDidSaveTextDocument((document) => {
            const config = vscode.workspace.getConfiguration('halluciguard');
            const autoScan = config.get<boolean>('autoScanOnSave', false);

            if (autoScan && isSupportedLanguage(document.languageId)) {
                void scanFile(document.uri);
            }
        })
    );

    // 6. Ensure dependencies in background (with progress)
    void vscode.window.withProgress(
        {
            location: vscode.ProgressLocation.Notification,
            title: 'HalluciGuard: Preparing scanner…',
        },
        async () => {
            try {
                if (statusBarItem) {
                    statusBarItem.text = '$(shield~spin) HalluciGuard';
                    statusBarItem.tooltip = 'HalluciGuard is initializing…';
                }
                await scanner!.ensureDependencies();
                if (statusBarItem) {
                    statusBarItem.text = '$(shield) HalluciGuard';
                    statusBarItem.tooltip = 'HalluciGuard is ready. Click to scan workspace.';
                }
            } catch (err) {
                if (statusBarItem) {
                    statusBarItem.text = '$(shield) HalluciGuard';
                    statusBarItem.tooltip = `Initialization failed: ${err instanceof Error ? err.message : String(err)}`;
                }
                void vscode.window.showErrorMessage(
                    `HalluciGuard failed to initialize. ${err instanceof Error ? err.message : String(err)}`
                );
            }
        }
    );

    // 7. First activation: auto-scan workspace (non-blocking)
    void vscode.window.withProgress(
        {
            location: vscode.ProgressLocation.Notification,
            title: 'HalluciGuard: Initial scan…',
            cancellable: false,
        },
        async () => {
            await scanWorkspace();
        }
    );
}

export function deactivate(): void {
    if (diagnostics) {
        diagnostics.dispose();
    }
    if (scanner) {
        scanner.dispose();
    }
}

// ── Command Handlers ────────────────────────────────────────────────────────

async function scanWorkspace(): Promise<void> {
    if (!scanner || !resultsProvider || !diagnostics || !statusBarItem) { return; }
    const scannerLocal = scanner;
    const resultsLocal = resultsProvider;
    const diagnosticsLocal = diagnostics;
    const statusLocal = statusBarItem;

    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders || workspaceFolders.length === 0) {
        vscode.window.showInformationMessage('HalluciGuard: Please open a workspace to scan.');
        return;
    }

    const workspacePath = workspaceFolders[0].uri.fsPath;
    resultsLocal.setWorkspaceRoot(workspacePath);
    void vscode.commands.executeCommand('halluciguardResults.focus');

    await vscode.window.withProgress(
        {
            location: vscode.ProgressLocation.Notification,
            title: 'HalluciGuard: Scanning workspace...',
            cancellable: true
        },
        async (_progress, token) => {
            resultsLocal.setScanning(true);
            diagnosticsLocal.clear();
            statusLocal.text = '$(shield~spin) HalluciGuard';

            try {
                const result = await scannerLocal.scan(workspacePath, { token });
                resultsLocal.refresh(result.findings, result.summary);
                diagnosticsLocal.update(result.findings, workspacePath);
                statusLocal.text = `$(shield) ${result.summary.highRisk} issues`;

                lastFindings = result.findings;
                lastSummary = result.summary;
                lastWorkspaceRoot = workspacePath;

                if (result.summary.highRisk > 0) {
                    if (extensionContext) {
                        HalluciGuardPanel.createOrShow(extensionContext, {
                            findings: result.findings,
                            summary: result.summary,
                            workspaceRoot: workspacePath,
                        });
                    }
                }
            } catch (err) {
                if (err instanceof Error && err.message.includes('cancelled')) {
                    vscode.window.showInformationMessage('HalluciGuard: Scan cancelled.');
                } else {
                    vscode.window.showErrorMessage(`HalluciGuard Scan Error: ${err instanceof Error ? err.message : String(err)}`);
                }
                resultsLocal.clear();
                statusLocal.text = '$(shield) HalluciGuard';
            }
        }
    );
}

async function scanCurrentFile(): Promise<void> {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showInformationMessage('HalluciGuard: Open a Python or JavaScript file to scan.');
        return;
    }

    if (!isSupportedLanguage(editor.document.languageId)) {
        vscode.window.showInformationMessage('HalluciGuard: Only Python and JavaScript/TypeScript files are supported.');
        return;
    }

    await scanFile(editor.document.uri);
}

async function scanFile(uri: vscode.Uri): Promise<void> {
    if (!scanner || !resultsProvider || !diagnostics || !statusBarItem) { return; }
    const scannerLocal = scanner;
    const resultsLocal = resultsProvider;
    const diagnosticsLocal = diagnostics;
    const statusLocal = statusBarItem;

    const workspaceFolders = vscode.workspace.workspaceFolders;
    const workspacePath = (workspaceFolders && workspaceFolders.length > 0)
        ? workspaceFolders[0].uri.fsPath
        : path.dirname(uri.fsPath);

    resultsLocal.setWorkspaceRoot(workspacePath);
    resultsLocal.setScanning(true);
    diagnosticsLocal.clearFile(uri);

    try {
        const result = await scannerLocal.scanFile(uri.fsPath, workspacePath);
        resultsLocal.refresh(result.findings, result.summary);
        diagnosticsLocal.updateFile(uri, result.findings, workspacePath);
        statusLocal.text = `$(shield) ${result.summary.highRisk} issues`;

        lastFindings = result.findings;
        lastSummary = result.summary;
        lastWorkspaceRoot = workspacePath;

    } catch (err) {
        vscode.window.showErrorMessage(`HalluciGuard File Scan Error: ${err instanceof Error ? err.message : String(err)}`);
        resultsLocal.clear();
        statusLocal.text = '$(shield) HalluciGuard';
    }
}

function clearResults(): void {
    if (resultsProvider) {
        resultsProvider.clear();
    }
    if (diagnostics) {
        diagnostics.clear();
    }
    lastFindings = [];
    lastSummary = null;
    lastWorkspaceRoot = null;
    if (statusBarItem) {
        statusBarItem.text = '$(shield) HalluciGuard';
        statusBarItem.tooltip = 'HalluciGuard is ready.';
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

function isSupportedLanguage(languageId: string): boolean {
    return ['python', 'javascript', 'typescript', 'javascriptreact', 'typescriptreact'].includes(languageId);
}

function showPanel(): void {
    if (!extensionContext) { return; }
    if (lastSummary && lastWorkspaceRoot) {
        HalluciGuardPanel.createOrShow(extensionContext, {
            findings: lastFindings,
            summary: lastSummary,
            workspaceRoot: lastWorkspaceRoot,
        });
        return;
    }
    HalluciGuardPanel.createOrShow(extensionContext);
}

import * as vscode from 'vscode';
import { ScanFinding, ScanSummary } from './scanner_bridge';

type NodeKind = 'summary' | 'file' | 'package' | 'flag' | 'message';

const FLAG_DESCRIPTIONS: Record<string, string> = {
    TYPOSQUAT_DANGER: 'very close to a popular package name (possible typosquat)',
    HALLUCINATION_DB_HIT: 'in known hallucination database',
    NEW_PACKAGE: 'recently created package (higher risk)',
    NOT_IN_REGISTRY: 'package not found in the registry',
    LOW_POPULARITY: 'low download count / low popularity',
    VULNERABLE: 'known vulnerabilities reported (OSV)',
    CROSS_ECOSYSTEM: 'exists in another ecosystem (possible confusion/typosquat)',
};

function flagDescription(flag: string): string {
    return FLAG_DESCRIPTIONS[flag] ?? 'unrecognized signal';
}

function issueCountLabel(count: number): string {
    return count === 1 ? '1 issue' : `${count} issues`;
}

function riskIcon(riskScore: number): vscode.ThemeIcon {
    if (riskScore >= 65) {
        return new vscode.ThemeIcon('warning', new vscode.ThemeColor('errorForeground'));
    }
    if (riskScore >= 40) {
        return new vscode.ThemeIcon('info', new vscode.ThemeColor('list.warningForeground'));
    }
    return new vscode.ThemeIcon('check', new vscode.ThemeColor('testing.iconPassed'));
}

function openFileCommand(uri: vscode.Uri): vscode.Command {
    return {
        command: 'vscode.open',
        title: 'Open File',
        arguments: [uri],
    };
}

function openFileAtLineCommand(uri: vscode.Uri, oneBasedLine: number): vscode.Command {
    const line = Math.max(0, oneBasedLine - 1);
    const pos = new vscode.Position(line, 0);
    return {
        command: 'vscode.open',
        title: 'Go to Location',
        arguments: [uri, { selection: new vscode.Range(pos, pos) }],
    };
}

export class ResultNode extends vscode.TreeItem {
    public readonly contextValue: string;

    constructor(args: {
        label: string;
        description?: string;
        iconPath?: vscode.ThemeIcon;
        collapsibleState: vscode.TreeItemCollapsibleState;
        command?: vscode.Command;
        contextValue: string;
    }) {
        super(args.label, args.collapsibleState);
        this.description = args.description;
        this.iconPath = args.iconPath;
        this.command = args.command;
        this.contextValue = args.contextValue;
        this.tooltip = args.description ? `${args.label}\n${args.description}` : args.label;
    }
}

export class ScanResultsProvider implements vscode.TreeDataProvider<ResultNode> {
    private readonly onDidChangeTreeDataEmitter = new vscode.EventEmitter<ResultNode | undefined | null | void>();
    readonly onDidChangeTreeData = this.onDidChangeTreeDataEmitter.event;

    private findings: ScanFinding[] = [];
    private summary: ScanSummary | null = null;

    private isScanning = false;
    private workspaceRootUri: vscode.Uri | null = null;

    private findingsByFile = new Map<string, ScanFinding[]>();
    private findingsByFileAndPackage = new Map<string, Map<string, ScanFinding[]>>();

    setWorkspaceRoot(workspacePath: string): void {
        this.workspaceRootUri = vscode.Uri.file(workspacePath);
    }

    refresh(findings: ScanFinding[], summary: ScanSummary): void {
        this.isScanning = false;
        this.findings = findings;
        this.summary = summary;
        this.rebuildIndexes();
        this.onDidChangeTreeDataEmitter.fire();
    }

    clear(): void {
        this.isScanning = false;
        this.findings = [];
        this.summary = null;
        this.findingsByFile.clear();
        this.findingsByFileAndPackage.clear();
        this.onDidChangeTreeDataEmitter.fire();
    }

    setScanning(scanning: boolean): void {
        this.isScanning = scanning;
        if (scanning) {
            this.findings = [];
            this.summary = null;
            this.findingsByFile.clear();
            this.findingsByFileAndPackage.clear();
        }
        this.onDidChangeTreeDataEmitter.fire();
    }

    getTreeItem(element: ResultNode): vscode.TreeItem {
        return element;
    }

    getChildren(element?: ResultNode): Thenable<ResultNode[]> {
        if (this.isScanning) {
            return Promise.resolve([
                new ResultNode({
                    label: 'Scanning…',
                    iconPath: new vscode.ThemeIcon('sync~spin'),
                    collapsibleState: vscode.TreeItemCollapsibleState.None,
                    contextValue: 'halluciguard.message',
                }),
            ]);
        }

        if (!this.summary) {
            return Promise.resolve([
                new ResultNode({
                    label: 'Run a scan to see results here.',
                    iconPath: new vscode.ThemeIcon('info'),
                    collapsibleState: vscode.TreeItemCollapsibleState.None,
                    contextValue: 'halluciguard.message',
                }),
            ]);
        }

        const kind = this.nodeKind(element);

        if (!element) {
            return Promise.resolve([this.buildSummaryNode(this.summary)]);
        }

        if (kind === 'summary') {
            return Promise.resolve(this.buildFileNodes());
        }

        if (kind === 'file') {
            const fileRel = this.nodeData(element, 'fileRel');
            return Promise.resolve(this.buildPackageNodesForFile(fileRel));
        }

        if (kind === 'package') {
            const fileRel = this.nodeData(element, 'fileRel');
            const pkg = this.nodeData(element, 'package');
            return Promise.resolve(this.buildFlagNodesForPackage(fileRel, pkg));
        }

        return Promise.resolve([]);
    }

    // ── Internal representation ────────────────────────────────────────────

    private rebuildIndexes(): void {
        this.findingsByFile.clear();
        this.findingsByFileAndPackage.clear();

        for (const f of this.findings) {
            const list = this.findingsByFile.get(f.file) ?? [];
            list.push(f);
            this.findingsByFile.set(f.file, list);
        }

        for (const [file, list] of this.findingsByFile) {
            list.sort((a, b) => a.line - b.line);

            const byPkg = new Map<string, ScanFinding[]>();
            for (const f of list) {
                const pkgList = byPkg.get(f.package) ?? [];
                pkgList.push(f);
                byPkg.set(f.package, pkgList);
            }
            this.findingsByFileAndPackage.set(file, byPkg);
        }
    }

    private workspaceUriForRelativePath(relPath: string): vscode.Uri | null {
        const root = this.workspaceRootUri ?? vscode.workspace.workspaceFolders?.[0]?.uri ?? null;
        return root ? vscode.Uri.joinPath(root, relPath) : null;
    }

    // ── Nodes ───────────────────────────────────────────────────────────────

    private buildSummaryNode(summary: ScanSummary): ResultNode {
        const label = `Scanned ${summary.filesScanned} files · ${summary.highRisk} issues found · ${summary.durationMs}ms`;
        const node = new ResultNode({
            label,
            iconPath: summary.highRisk > 0 ? new vscode.ThemeIcon('warning') : new vscode.ThemeIcon('check'),
            collapsibleState: vscode.TreeItemCollapsibleState.Expanded,
            contextValue: 'halluciguard.summary',
        });

        this.setNodeKind(node, 'summary');
        return node;
    }

    private buildFileNodes(): ResultNode[] {
        const files = [...this.findingsByFile.entries()].sort(([a], [b]) => a.localeCompare(b));
        if (files.length === 0) {
            return [
                new ResultNode({
                    label: 'No issues found.',
                    iconPath: new vscode.ThemeIcon('check'),
                    collapsibleState: vscode.TreeItemCollapsibleState.None,
                    contextValue: 'halluciguard.message',
                }),
            ];
        }

        return files.map(([fileRel, fileFindings]) => {
            const issuesCount = fileFindings.length;
            const label = `${fileRel}  ⚠️ ${issueCountLabel(issuesCount)}`;

            const uri = this.workspaceUriForRelativePath(fileRel);
            const node = new ResultNode({
                label,
                description: undefined,
                iconPath: new vscode.ThemeIcon('file'),
                collapsibleState: vscode.TreeItemCollapsibleState.Expanded,
                command: uri ? openFileCommand(uri) : undefined,
                contextValue: 'halluciguard.file',
            });

            this.setNodeKind(node, 'file');
            this.setNodeData(node, 'fileRel', fileRel);
            return node;
        });
    }

    private buildPackageNodesForFile(fileRel: string): ResultNode[] {
        const byPkg = this.findingsByFileAndPackage.get(fileRel);
        if (!byPkg) {
            return [];
        }

        const packages = [...byPkg.entries()].sort(([a], [b]) => a.localeCompare(b));
        return packages.map(([pkg, pkgFindings]) => {
            const representative = pkgFindings.reduce((best, cur) => (cur.riskScore > best.riskScore ? cur : best), pkgFindings[0]);
            const label = `${pkg}  Risk: ${Math.round(representative.riskScore)}/100  ${representative.action}`;

            const uri = this.workspaceUriForRelativePath(fileRel);
            const node = new ResultNode({
                label,
                iconPath: riskIcon(representative.riskScore),
                collapsibleState: vscode.TreeItemCollapsibleState.Collapsed,
                command: uri ? openFileAtLineCommand(uri, representative.line) : undefined,
                contextValue: 'halluciguard.package',
            });

            this.setNodeKind(node, 'package');
            this.setNodeData(node, 'fileRel', fileRel);
            this.setNodeData(node, 'package', pkg);
            return node;
        });
    }

    private buildFlagNodesForPackage(fileRel: string, pkg: string): ResultNode[] {
        const pkgFindings = this.findingsByFileAndPackage.get(fileRel)?.get(pkg) ?? [];
        if (pkgFindings.length === 0) {
            return [];
        }

        const flags = new Set<string>();
        for (const f of pkgFindings) {
            for (const flag of f.flags) {
                flags.add(flag);
            }
        }

        return [...flags].sort().map((flag) => {
            const desc = flagDescription(flag);
            const node = new ResultNode({
                label: `${flag} — ${desc}`,
                iconPath: new vscode.ThemeIcon('debug'),
                collapsibleState: vscode.TreeItemCollapsibleState.None,
                contextValue: 'halluciguard.flag',
            });
            this.setNodeKind(node, 'flag');
            return node;
        });
    }

    // ── Metadata helpers (avoid extra classes/interfaces) ───────────────────

    private nodeKind(node?: ResultNode): NodeKind | undefined {
        return node ? (this.getNodeMeta(node, 'kind') as NodeKind | undefined) : undefined;
    }

    private setNodeKind(node: ResultNode, kind: NodeKind): void {
        this.setNodeMeta(node, 'kind', kind);
    }

    private nodeData(node: ResultNode, key: string): string {
        const value = this.getNodeMeta(node, key);
        if (typeof value !== 'string' || value.length === 0) {
            throw new Error(`HalluciGuard: missing node metadata '${key}'`);
        }
        return value;
    }

    private setNodeData(node: ResultNode, key: string, value: string): void {
        this.setNodeMeta(node, key, value);
    }

    private setNodeMeta(node: ResultNode, key: string, value: unknown): void {
        (node as unknown as { __halluciguard?: Record<string, unknown> }).__halluciguard ??= {};
        (node as unknown as { __halluciguard: Record<string, unknown> }).__halluciguard[key] = value;
    }

    private getNodeMeta(node: ResultNode, key: string): unknown {
        return (node as unknown as { __halluciguard?: Record<string, unknown> }).__halluciguard?.[key];
    }
}

// Keep the existing export used by extension.ts
export class HalluciGuardResultsProvider extends ScanResultsProvider {}

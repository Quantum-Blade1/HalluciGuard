/**
 * ScannerBridge — Spawns the bundled Python scanner subprocess and parses NDJSON output.
 *
 * This module is the sole bridge between the VS Code extension (TypeScript)
 * and the Python scanner. It handles:
 *   - Locating a working Python interpreter
 *   - Installing scanner dependencies on first run
 *   - Spawning `halluciguard_scanner.py` as a child process
 *   - Streaming and parsing NDJSON lines from stdout
 *   - Collecting stderr for error reporting
 *   - Timeout + cancellation of running scans
 */

import { spawn, ChildProcess, execFile } from 'child_process';
import { EventEmitter } from 'events';
import * as path from 'path';
import * as fs from 'fs';
import * as vscode from 'vscode';

// ── Interfaces ──────────────────────────────────────────────────────────────

/** A single finding emitted by the Python scanner. */
export interface ScanFinding {
    type: 'finding';
    file: string;
    package: string;
    line: number;
    riskScore: number;
    action: 'BLOCK' | 'WARN' | 'ALLOW';
    flags: string[];
    nearest: string;
    distance: number;
    suggested: string;  // curated safe replacement from REMEDIATION_MAP
    language: 'python' | 'javascript';
}

/** Progress event emitted per file. */
export interface ScanProgress {
    type: 'progress';
    file: string;
    status: string;
}

/** Summary emitted as the final line of a scan. */
export interface ScanSummary {
    type: 'summary';
    filesScanned: number;
    packagesFound: number;
    highRisk: number;
    passed: number;
    durationMs: number;
}

/** Ready signal emitted by --preload-only. */
export interface ScanReady {
    type: 'ready';
    pypiCount: number;
    npmCount: number;
    hallucinationCount: number;
    loadTimeMs: number;
}

/** Aggregated result of a scan run. */
export interface ScanResult {
    findings: ScanFinding[];
    summary: ScanSummary;
}

/** Options for a scan invocation. */
export interface ScanOptions {
    /** Specific files to scan (relative to workspace). Omit for full workspace. */
    files?: string[];
    /** Risk threshold override. Uses extension setting if omitted. */
    threshold?: number;
    /** Timeout in ms. Default: 60_000 for workspace, 15_000 for single file. */
    timeoutMs?: number;
    /** Cancellation token from VS Code. */
    token?: vscode.CancellationToken;
}

// ── Raw JSON shapes from the Python scanner (snake_case) ────────────────────

interface RawFinding {
    type: 'finding';
    file: string;
    package: string;
    line: number;
    risk_score: number;
    action: string;
    flags: string[];
    nearest: string;
    distance: number;
    suggested: string;
    language: string;
}

interface RawSummary {
    type: 'summary';
    files_scanned: number;
    packages_found: number;
    high_risk: number;
    passed: number;
    duration_ms: number;
}

interface RawProgress {
    type: 'progress';
    file: string;
    status: string;
}

interface RawReady {
    type: 'ready';
    pypi_count: number;
    npm_count: number;
    hallucination_count: number;
    load_time_ms: number;
}

type RawMessage = RawFinding | RawSummary | RawProgress | RawReady;

// ── ScannerBridge ───────────────────────────────────────────────────────────

export class ScannerBridge extends EventEmitter {
    private readonly extensionPath: string;
    private readonly scannerDir: string;
    private readonly scannerScript: string;
    private resolvedPython: string | null = null;
    private activeProcess: ChildProcess | null = null;

    constructor(extensionPath: string) {
        super();
        this.extensionPath = extensionPath;
        // In packaged VSIX, scanner/ is shipped inside the extension root.
        // In this repo we also copy scanner/ into vscode-extension/scanner/ for packaging.
        this.scannerDir = path.resolve(extensionPath, 'scanner');
        this.scannerScript = path.join(this.scannerDir, 'halluciguard_scanner.py');
    }

    // ── Python discovery ────────────────────────────────────────────────────

    /**
     * Locate a working Python interpreter.
     * Priority: user setting → python3 → python
     */
    async findPython(): Promise<string> {
        if (this.resolvedPython) {
            return this.resolvedPython;
        }

        const config = vscode.workspace.getConfiguration('halluciguard');
        const userSetting = config.get<string>('pythonPath', '');
        const candidates: string[] = [
            // Venv next to extension root always wins — has all deps pre-installed
            path.resolve(this.extensionPath, '..', '.venv', 'bin', 'python'),
            path.resolve(this.extensionPath, '..', '.venv', 'bin', 'python3'),
            ...(userSetting ? [userSetting] : []),
            'python3',
            'python',
        ];

        // De-duplicate while preserving order
        const unique = [...new Set(candidates)];

        for (const candidate of unique) {
            if (await this.isPythonValid(candidate)) {
                this.resolvedPython = candidate;
                return candidate;
            }
        }

        throw new Error(
            'HalluciGuard: No working Python interpreter found. ' +
            'Install Python 3.11+ or set halluciguard.pythonPath in settings.'
        );
    }

    /**
     * Check if a Python path points to a valid Python 3.x interpreter.
     */
    private isPythonValid(pythonPath: string): Promise<boolean> {
        return new Promise((resolve) => {
            execFile(pythonPath, ['--version'], { timeout: 5000 }, (err, stdout, stderr) => {
                if (err) {
                    resolve(false);
                    return;
                }
                // "Python 3.11.x" — accept any 3.x
                const output = (stdout || stderr || '').trim();
                resolve(/^Python 3\.\d+/.test(output));
            });
        });
    }

    // ── Dependency installation ─────────────────────────────────────────────

    /**
     * Install scanner/requirements.txt on first activation.
     * Creates a `.installed` sentinel file to skip on subsequent runs.
     */
    async ensureDependencies(): Promise<void> {
        const sentinelPath = path.join(this.scannerDir, '.installed');
        const requirementsPath = path.join(this.scannerDir, 'requirements.txt');

        if (fs.existsSync(sentinelPath)) {
            return;
        }

        if (!fs.existsSync(requirementsPath)) {
            throw new Error(
                `HalluciGuard: requirements.txt not found at ${requirementsPath}. ` +
                'Extension may be corrupted.'
            );
        }

        const python = await this.findPython();

        await vscode.window.withProgress(
            {
                location: vscode.ProgressLocation.Notification,
                title: 'HalluciGuard: Installing scanner dependencies…',
                cancellable: false,
            },
            () => this.runPipInstall(python, requirementsPath)
        );

        // Write sentinel
        fs.writeFileSync(sentinelPath, new Date().toISOString(), 'utf-8');
    }

    private runPipInstall(python: string, requirementsPath: string): Promise<void> {
        return new Promise((resolve, reject) => {
            const proc = spawn(python, [
                '-m', 'pip', 'install',
                '-r', requirementsPath,
                '--quiet',
                '--disable-pip-version-check',
            ], {
                cwd: this.scannerDir,
                stdio: ['ignore', 'pipe', 'pipe'],
            });

            let stderr = '';
            proc.stderr?.on('data', (chunk: Buffer) => {
                stderr += chunk.toString();
            });

            proc.on('close', (code) => {
                if (code === 0) {
                    resolve();
                } else {
                    reject(new Error(
                        `pip install failed (exit ${code}):\n${stderr.slice(0, 500)}`
                    ));
                }
            });

            proc.on('error', (err) => {
                reject(new Error(`Failed to spawn pip: ${err.message}`));
            });
        });
    }

    // ── Preload (warm up bloom filter) ──────────────────────────────────────

    /**
     * Run --preload-only to warm up the bloom filter.
     * Returns the ready message with package counts.
     */
    async preload(): Promise<ScanReady> {
        const python = await this.findPython();

        return new Promise((resolve, reject) => {
            const proc = spawn(python, [this.scannerScript, '--preload-only'], {
                cwd: this.extensionPath,
                stdio: ['ignore', 'pipe', 'pipe'],
            });

            let stdout = '';
            let stderr = '';

            proc.stdout?.on('data', (chunk: Buffer) => {
                stdout += chunk.toString();
            });
            proc.stderr?.on('data', (chunk: Buffer) => {
                stderr += chunk.toString();
            });

            const timer = setTimeout(() => {
                proc.kill('SIGTERM');
                reject(new Error('Preload timed out after 120s'));
            }, 120_000);

            proc.on('close', (code) => {
                clearTimeout(timer);
                if (code !== 0) {
                    reject(new Error(
                        `Preload failed (exit ${code}):\n${stderr.slice(0, 500)}`
                    ));
                    return;
                }
                try {
                    const raw = JSON.parse(stdout.trim()) as RawReady;
                    resolve({
                        type: 'ready',
                        pypiCount: raw.pypi_count,
                        npmCount: raw.npm_count,
                        hallucinationCount: raw.hallucination_count,
                        loadTimeMs: raw.load_time_ms,
                    });
                } catch (e) {
                    reject(new Error(`Failed to parse preload output: ${stdout.slice(0, 200)}`));
                }
            });

            proc.on('error', (err) => {
                clearTimeout(timer);
                reject(new Error(`Failed to spawn scanner: ${err.message}`));
            });
        });
    }

    // ── Scan workspace ──────────────────────────────────────────────────────

    /**
     * Run a full workspace or filtered-file scan.
     *
     * Spawns the Python scanner, streams progress events, and resolves
     * with all findings once the summary line arrives.
     */
    async scan(workspacePath: string, options: ScanOptions = {}): Promise<ScanResult> {
        const python = await this.findPython();

        const config = vscode.workspace.getConfiguration('halluciguard');
        const threshold = options.threshold ?? config.get<number>('riskThreshold', 65);
        const isFileScan = options.files && options.files.length > 0;
        const timeoutMs = options.timeoutMs ?? (isFileScan ? 15_000 : 60_000);

        // Build argument list
        const args: string[] = [
            this.scannerScript,
            '--workspace', workspacePath,
            '--threshold', String(threshold),
        ];

        if (options.files && options.files.length > 0) {
            args.push('--files', ...options.files);
        }

        return new Promise<ScanResult>((resolve, reject) => {
            const proc = spawn(python, args, {
                cwd: this.extensionPath,
                stdio: ['ignore', 'pipe', 'pipe'],
                env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' },
            });

            this.activeProcess = proc;

            const findings: ScanFinding[] = [];
            let summary: ScanSummary | null = null;
            let stderrBuf = '';
            let stdoutBuf = '';
            let settled = false;

            const settle = (error?: Error) => {
                if (settled) { return; }
                settled = true;
                clearTimeout(timer);
                this.activeProcess = null;
                if (error) {
                    reject(error);
                } else if (summary) {
                    resolve({ findings, summary });
                } else {
                    // Process exited without a summary — synthesize one
                    resolve({
                        findings,
                        summary: {
                            type: 'summary',
                            filesScanned: 0,
                            packagesFound: findings.length,
                            highRisk: findings.filter(f => f.action !== 'ALLOW').length,
                            passed: findings.filter(f => f.action === 'ALLOW').length,
                            durationMs: 0,
                        },
                    });
                }
            };

            // Timeout
            const timer = setTimeout(() => {
                proc.kill('SIGTERM');
                settle(new Error(
                    `Scan timed out after ${timeoutMs / 1000}s. ` +
                    'Try scanning individual files or increasing the timeout.'
                ));
            }, timeoutMs);

            // Cancellation
            if (options.token) {
                options.token.onCancellationRequested(() => {
                    proc.kill('SIGTERM');
                    settle(new Error('Scan cancelled by user'));
                });
            }

            // Parse stdout line-by-line (NDJSON)
            proc.stdout?.on('data', (chunk: Buffer) => {
                stdoutBuf += chunk.toString();
                const lines = stdoutBuf.split('\n');
                // Keep the last incomplete line in the buffer
                stdoutBuf = lines.pop() ?? '';

                for (const line of lines) {
                    const trimmed = line.trim();
                    if (!trimmed) { continue; }
                    this.parseLine(trimmed, findings, (s) => { summary = s; });
                }
            });

            // Accumulate stderr
            proc.stderr?.on('data', (chunk: Buffer) => {
                stderrBuf += chunk.toString();
            });

            // Process exit
            proc.on('close', (code) => {
                // Flush any remaining stdout
                if (stdoutBuf.trim()) {
                    this.parseLine(stdoutBuf.trim(), findings, (s) => { summary = s; });
                }

                if (code !== 0 && code !== null) {
                    settle(new Error(
                        `Scanner exited with code ${code}.\n${stderrBuf.slice(0, 500)}`
                    ));
                } else {
                    settle();
                }
            });

            proc.on('error', (err) => {
                settle(new Error(`Failed to spawn scanner: ${err.message}`));
            });
        });
    }

    /**
     * Convenience method: scan a single file.
     */
    async scanFile(filePath: string, workspacePath: string, options: ScanOptions = {}): Promise<ScanResult> {
        const relative = path.relative(workspacePath, filePath);
        return this.scan(workspacePath, {
            ...options,
            files: [relative],
            timeoutMs: options.timeoutMs ?? 15_000,
        });
    }

    // ── Cancel active scan ──────────────────────────────────────────────────

    /**
     * Kill any active scanner subprocess.
     */
    cancel(): void {
        if (this.activeProcess) {
            this.activeProcess.kill('SIGTERM');
            this.activeProcess = null;
        }
    }

    // ── Dispose ─────────────────────────────────────────────────────────────

    dispose(): void {
        this.cancel();
        this.removeAllListeners();
    }

    // ── NDJSON parsing ──────────────────────────────────────────────────────

    /**
     * Parse a single NDJSON line from the scanner.
     *
     * Converts Python snake_case fields to TypeScript camelCase,
     * emits progress events, and collects findings/summary.
     */
    private parseLine(
        line: string,
        findings: ScanFinding[],
        onSummary: (s: ScanSummary) => void,
    ): void {
        let raw: RawMessage;
        try {
            raw = JSON.parse(line);
        } catch {
            // Non-JSON line — ignore (could be a Python warning on stdout)
            return;
        }

        switch (raw.type) {
            case 'progress': {
                const progress = raw as RawProgress;
                this.emit('progress', {
                    type: 'progress',
                    file: progress.file,
                    status: progress.status,
                } satisfies ScanProgress);
                break;
            }

            case 'finding': {
                const f = raw as RawFinding;
                const finding: ScanFinding = {
                    type: 'finding',
                    file: f.file,
                    package: f.package,
                    line: f.line,
                    riskScore: f.risk_score,
                    action: f.action as ScanFinding['action'],
                    flags: f.flags,
                    nearest: f.nearest,
                    distance: f.distance,
                    suggested: f.suggested ?? '',
                    language: f.language as ScanFinding['language'],
                };
                findings.push(finding);
                this.emit('finding', finding);
                break;
            }

            case 'summary': {
                const s = raw as RawSummary;
                const summary: ScanSummary = {
                    type: 'summary',
                    filesScanned: s.files_scanned,
                    packagesFound: s.packages_found,
                    highRisk: s.high_risk,
                    passed: s.passed,
                    durationMs: s.duration_ms,
                };
                onSummary(summary);
                this.emit('summary', summary);
                break;
            }

            case 'ready': {
                // Handled by preload(), but emit for any external listeners
                this.emit('ready', raw);
                break;
            }

            default:
                // Unknown message type — ignore
                break;
        }
    }
}

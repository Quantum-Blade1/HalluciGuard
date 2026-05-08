import * as vscode from 'vscode';
import * as net from 'net';
import {
    LanguageClient,
    LanguageClientOptions,
    StreamInfo,
} from 'vscode-languageclient/node';

let client: LanguageClient | undefined;
let statusBarItem: vscode.StatusBarItem;

export function activate(context: vscode.ExtensionContext): void {
    // Status bar
    statusBarItem = vscode.window.createStatusBarItem(
        vscode.StatusBarAlignment.Right,
        100
    );
    statusBarItem.text = '$(shield) HalluciGuard';
    statusBarItem.tooltip = 'HalluciGuard — Connecting...';
    statusBarItem.show();
    context.subscriptions.push(statusBarItem);

    // Config
    const config = vscode.workspace.getConfiguration('halluciguard');
    const host = config.get<string>('serverHost', 'localhost');
    const port = config.get<number>('serverPort', 7777);

    // Server options: connect via TCP
    const serverOptions = (): Promise<StreamInfo> => {
        return new Promise((resolve, reject) => {
            const socket = net.connect({ host, port }, () => {
                resolve({ reader: socket, writer: socket });
                statusBarItem.text = '$(shield) HalluciGuard ✓';
                statusBarItem.tooltip = `Connected to ${host}:${port}`;
            });
            socket.on('error', (err) => {
                statusBarItem.text = '$(shield) HalluciGuard ✗';
                statusBarItem.tooltip = `Connection failed: ${err.message}`;
                reject(err);
            });
        });
    };

    // Client options
    const clientOptions: LanguageClientOptions = {
        documentSelector: [
            { scheme: 'file', language: 'python' },
            { scheme: 'file', language: 'javascript' },
            { scheme: 'file', language: 'typescript' },
        ],
        diagnosticCollectionName: 'halluciguard',
        outputChannelName: 'HalluciGuard',
    };

    // Create and start the client
    client = new LanguageClient(
        'halluciguard',
        'HalluciGuard',
        serverOptions,
        clientOptions
    );

    client.start().catch((err) => {
        vscode.window.showWarningMessage(
            `HalluciGuard: Could not connect to LSP server at ${host}:${port}. ` +
            `Start the server with: python src/main.py`
        );
    });

    context.subscriptions.push({
        dispose: () => {
            if (client) {
                client.stop();
            }
        },
    });
}

export function deactivate(): Thenable<void> | undefined {
    return client?.stop();
}

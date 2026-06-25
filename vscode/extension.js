const vscode = require('vscode');
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

function getGscPath() {
    return vscode.workspace.getConfiguration('gsc').get('path', '~/gsc/gsc.py')
        .replace('~', os.homedir());
}

function activate(context) {
    const diagnosticCollection = vscode.languages.createDiagnosticCollection('gsc');
    context.subscriptions.push(diagnosticCollection);

    // Command: Show all findings for project
    context.subscriptions.push(vscode.commands.registerCommand('gsc.showFindings', async () => {
        const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri?.fsPath;
        if (!workspaceRoot) {
            vscode.window.showErrorMessage('No workspace open');
            return;
        }

        const gsc = getGscPath();
        if (!fs.existsSync(gsc)) {
            vscode.window.showErrorMessage(`GSC not found at ${gsc}. Install: git clone https://github.com/poliakarmai/gsc ~/gsc`);
            return;
        }

        await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: 'GSC Audit',
            cancellable: false
        }, async () => {
            try {
                const result = execSync(`python3 "${gsc}" scan "${workspaceRoot}" --ci --json`, {
                    timeout: 60000, maxBuffer: 10 * 1024 * 1024
                });
                const findings = JSON.parse(result.toString());
                
                // Update diagnostic markers
                const diagMap = new Map();
                for (const f of findings) {
                    const uri = vscode.Uri.file(f.file_path);
                    if (!diagMap.has(f.file_path)) diagMap.set(f.file_path, []);
                    const severity = f.category === 'CRITICAL' ? vscode.DiagnosticSeverity.Error :
                                    f.category === 'HIGH' ? vscode.DiagnosticSeverity.Warning :
                                    vscode.DiagnosticSeverity.Information;
                    const diag = new vscode.Diagnostic(
                        new vscode.Range(f.line_number - 1, 0, f.line_number - 1, 200),
                        `[GSC/${f.category}] ${f.title}${f.detail ? ' — ' + f.detail.substring(0, 100) : ''}`,
                        severity
                    );
                    diagMap.get(f.file_path).push(diag);
                }

                diagnosticCollection.clear();
                for (const [filePath, diags] of diagMap) {
                    diagnosticCollection.set(vscode.Uri.file(filePath), diags);
                }

                vscode.window.showInformationMessage(
                    `GSC: ${findings.length} findings (${findings.filter(f=>f.category==='CRITICAL').length} critical)`
                );
            } catch (e) {
                vscode.window.showErrorMessage(`GSC audit failed: ${e.message}`);
            }
        });
    }));

    // Command: Scan current project (same as showFindings)
    context.subscriptions.push(vscode.commands.registerCommand('gsc.scanCurrent', () => {
        vscode.commands.executeCommand('gsc.showFindings');
    }));

    // Auto-scan on file save if enabled
    if (vscode.workspace.getConfiguration('gsc').get('autoScan', false)) {
        context.subscriptions.push(vscode.workspace.onDidSaveTextDocument(() => {
            vscode.commands.executeCommand('gsc.showFindings');
        }));
    }
}

function deactivate() {}

module.exports = { activate, deactivate };

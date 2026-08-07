import * as vscode from "vscode";
import * as path from "path";
import { GscClient } from "./client";
import { GscDiagnostics } from "./diagnostics";
import { GscCodeLensProvider } from "./codeLens";
import { GscFindingsProvider } from "./treeView";
import { GscWebView } from "./webView";
import { Finding, Severity } from "./types";

let diagnostics: GscDiagnostics;
let codeLens: GscCodeLensProvider;
let tree: GscFindingsProvider;
let webview: GscWebView;
let statusItem: vscode.StatusBarItem;

export function activate(ctx: vscode.ExtensionContext): void {
  const client = new GscClient();
  diagnostics = new GscDiagnostics();
  codeLens = new GscCodeLensProvider();
  tree = new GscFindingsProvider();
  webview = new GscWebView(client);

  statusItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  statusItem.text = "$(shield) GSC";
  statusItem.command = "gsc.showChains";
  statusItem.show();

  vscode.window.registerTreeDataProvider("gscFindings", tree);
  ctx.subscriptions.push(vscode.languages.registerCodeLensProvider({ pattern: "**/*" }, codeLens));

  const root = () => vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || "";
  const cfg = () => vscode.workspace.getConfiguration("gsc");

  ctx.subscriptions.push(
    vscode.commands.registerCommand("gsc.scan", async () => {
      const r = root(); if (!r) return vscode.window.showWarningMessage("GSC: no workspace");
      statusItem.text = "$(sync~spin) GSC scanning…";
      try { await client.triggerScan(r); await refresh(client); statusItem.text = "$(shield) GSC ✓"; }
      catch (e) { statusItem.text = "$(shield) GSC ✗"; vscode.window.showErrorMessage(`Scan: ${(e as Error).message}`); }
    }),
    vscode.commands.registerCommand("gsc.refresh", () => refresh(client)),
    vscode.commands.registerCommand("gsc.showChains", () => webview.showChains()),
    vscode.commands.registerCommand("gsc.showPoc", (key: string) => webview.showPoc(key)),
    vscode.commands.registerCommand("gsc.verdictTp", (key: string) => verdict(client, key, "tp")),
    vscode.commands.registerCommand("gsc.verdictFp", (key: string) => verdict(client, key, "fp")),
    vscode.commands.registerCommand("gsc.verdictFixed", (key: string) => verdict(client, key, "fixed")),
    vscode.commands.registerCommand("gsc.override", (key: string) => {
      vscode.window.showInputBox({ prompt: "Override reason (required)", validateInput: v => v.trim() ? null : "Required" })
        .then(reason => { if (reason) client.submitOverride(key, reason).then(() => { vscode.window.showInformationMessage("Override applied"); refresh(client); }); });
    }),
    vscode.commands.registerCommand("gsc.openFinding", async (f: Finding) => {
      const abs = path.isAbsolute(f.file) ? f.file : path.join(root(), f.file);
      const doc = await vscode.workspace.openTextDocument(abs);
      const ed = await vscode.window.showTextDocument(doc);
      const ln = Math.max(0, f.line - 1);
      ed.selection = new vscode.Selection(ln, 0, ln, 0);
      ed.revealRange(new vscode.Range(ln, 0, ln, 0));
    }),
    vscode.commands.registerCommand("gsc.openSettings", () => vscode.commands.executeCommand("workbench.action.openSettings", "gsc"))
  );
  ctx.subscriptions.push(diagnostics, codeLens, statusItem);
  refresh(client);
}

async function refresh(client: GscClient): Promise<void> {
  try {
    const findings = await client.getFindings();
    const r = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || "";
    const minSev = vscode.workspace.getConfiguration("gsc").get<string>("minSeverity", "LOW") as Severity;
    diagnostics.update(findings, r);
    codeLens.setFindings(findings, r);
    tree.setFindings(findings, minSev);
  } catch (e) { /* silent — API may not be running */ }
}

async function verdict(client: GscClient, key: string, v: "tp" | "fp" | "fixed"): Promise<void> {
  let reason: string | undefined;
  if (v === "fp") reason = await vscode.window.showInputBox({ prompt: "FP reason (optional)" });
  try {
    await client.submitVerdict({ finding_key: key, verdict: v, reason });
    vscode.window.showInformationMessage(`Verdict: ${v}`);
    await refresh(client);
  } catch (e) { vscode.window.showErrorMessage(`Verdict: ${(e as Error).message}`); }
}

export function deactivate(): void { diagnostics?.dispose(); }

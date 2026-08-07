"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.activate = activate;
exports.deactivate = deactivate;
const vscode = __importStar(require("vscode"));
const path = __importStar(require("path"));
const client_1 = require("./client");
const diagnostics_1 = require("./diagnostics");
const codeLens_1 = require("./codeLens");
const treeView_1 = require("./treeView");
const webView_1 = require("./webView");
let diagnostics;
let codeLens;
let tree;
let webview;
let statusItem;
function activate(ctx) {
    const client = new client_1.GscClient();
    diagnostics = new diagnostics_1.GscDiagnostics();
    codeLens = new codeLens_1.GscCodeLensProvider();
    tree = new treeView_1.GscFindingsProvider();
    webview = new webView_1.GscWebView(client);
    statusItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    statusItem.text = "$(shield) GSC";
    statusItem.command = "gsc.showChains";
    statusItem.show();
    vscode.window.registerTreeDataProvider("gscFindings", tree);
    ctx.subscriptions.push(vscode.languages.registerCodeLensProvider({ pattern: "**/*" }, codeLens));
    const root = () => vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || "";
    const cfg = () => vscode.workspace.getConfiguration("gsc");
    ctx.subscriptions.push(vscode.commands.registerCommand("gsc.scan", async () => {
        const r = root();
        if (!r)
            return vscode.window.showWarningMessage("GSC: no workspace");
        statusItem.text = "$(sync~spin) GSC scanning…";
        try {
            await client.triggerScan(r);
            await refresh(client);
            statusItem.text = "$(shield) GSC ✓";
        }
        catch (e) {
            statusItem.text = "$(shield) GSC ✗";
            vscode.window.showErrorMessage(`Scan: ${e.message}`);
        }
    }), vscode.commands.registerCommand("gsc.refresh", () => refresh(client)), vscode.commands.registerCommand("gsc.showChains", () => webview.showChains()), vscode.commands.registerCommand("gsc.showPoc", (key) => webview.showPoc(key)), vscode.commands.registerCommand("gsc.verdictTp", (key) => verdict(client, key, "tp")), vscode.commands.registerCommand("gsc.verdictFp", (key) => verdict(client, key, "fp")), vscode.commands.registerCommand("gsc.verdictFixed", (key) => verdict(client, key, "fixed")), vscode.commands.registerCommand("gsc.override", (key) => {
        vscode.window.showInputBox({ prompt: "Override reason (required)", validateInput: v => v.trim() ? null : "Required" })
            .then(reason => { if (reason)
            client.submitOverride(key, reason).then(() => { vscode.window.showInformationMessage("Override applied"); refresh(client); }); });
    }), vscode.commands.registerCommand("gsc.openFinding", async (f) => {
        const abs = path.isAbsolute(f.file) ? f.file : path.join(root(), f.file);
        const doc = await vscode.workspace.openTextDocument(abs);
        const ed = await vscode.window.showTextDocument(doc);
        const ln = Math.max(0, f.line - 1);
        ed.selection = new vscode.Selection(ln, 0, ln, 0);
        ed.revealRange(new vscode.Range(ln, 0, ln, 0));
    }), vscode.commands.registerCommand("gsc.openSettings", () => vscode.commands.executeCommand("workbench.action.openSettings", "gsc")));
    ctx.subscriptions.push(diagnostics, codeLens, statusItem);
    refresh(client);
}
async function refresh(client) {
    try {
        const findings = await client.getFindings();
        const r = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || "";
        const minSev = vscode.workspace.getConfiguration("gsc").get("minSeverity", "LOW");
        diagnostics.update(findings, r);
        codeLens.setFindings(findings, r);
        tree.setFindings(findings, minSev);
    }
    catch (e) { /* silent — API may not be running */ }
}
async function verdict(client, key, v) {
    let reason;
    if (v === "fp")
        reason = await vscode.window.showInputBox({ prompt: "FP reason (optional)" });
    try {
        await client.submitVerdict({ finding_key: key, verdict: v, reason });
        vscode.window.showInformationMessage(`Verdict: ${v}`);
        await refresh(client);
    }
    catch (e) {
        vscode.window.showErrorMessage(`Verdict: ${e.message}`);
    }
}
function deactivate() { diagnostics?.dispose(); }

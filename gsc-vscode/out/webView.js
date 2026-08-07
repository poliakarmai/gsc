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
exports.GscWebView = void 0;
const vscode = __importStar(require("vscode"));
const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
class GscWebView {
    client;
    panel;
    constructor(client) {
        this.client = client;
    }
    async showPoc(key) {
        const poc = await this.client.getPoc(key);
        this.render(`<h2>PoC — ${esc(key)}</h2><p><strong>Impact:</strong> ${esc(poc.impact)}</p><pre><code>${esc(poc.poc)}</code></pre>`, `PoC ${key}`);
    }
    async showChains() {
        const chains = await this.client.getChains();
        const rows = chains.map(c => `<div class="chain ${c.composed_severity.toLowerCase()}"><h3>${c.composed_severity} · ${c.chain_key}</h3><p>conf ${c.confidence.toFixed(2)} · ${c.finding_keys.length} findings</p><p>${esc(c.narrative || "")}</p><code>${c.finding_keys.join(" → ")}</code></div>`).join("");
        this.render(`<h2>Exploit Chains</h2>${rows || "<p>No chains found</p>"}`, "Exploit Chains");
    }
    render(body, title) {
        if (!this.panel) {
            this.panel = vscode.window.createWebviewPanel("gscWebview", title, vscode.ViewColumn.Beside, { enableScripts: false });
            this.panel.onDidDispose(() => { this.panel = undefined; });
        }
        this.panel.title = title;
        this.panel.webview.html = `<!DOCTYPE html><html><head><meta charset="utf-8"><style>body{font-family:var(--vscode-font-family);padding:16px;color:var(--vscode-foreground)}pre{background:var(--vscode-textCodeBlock-background);padding:12px;border-radius:6px;overflow-x:auto}.chain{border:1px solid var(--vscode-panel-border);padding:12px;margin:8px 0;border-radius:6px}.chain.critical{border-left:4px solid #f44}.chain.high{border-left:4px solid #f80}</style></head><body>${body}</body></html>`;
        this.panel.reveal(vscode.ViewColumn.Beside);
    }
}
exports.GscWebView = GscWebView;

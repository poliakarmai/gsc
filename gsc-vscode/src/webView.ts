import * as vscode from "vscode";
import { GscClient } from "./client";

const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

export class GscWebView {
  private panel?: vscode.WebviewPanel;
  constructor(private client: GscClient) {}

  async showPoc(key: string): Promise<void> {
    const poc = await this.client.getPoc(key);
    this.render(`<h2>PoC — ${esc(key)}</h2><p><strong>Impact:</strong> ${esc(poc.impact)}</p><pre><code>${esc(poc.poc)}</code></pre>`, `PoC ${key}`);
  }

  async showChains(): Promise<void> {
    const chains = await this.client.getChains();
    const rows = chains.map(c => `<div class="chain ${c.composed_severity.toLowerCase()}"><h3>${c.composed_severity} · ${c.chain_key}</h3><p>conf ${c.confidence.toFixed(2)} · ${c.finding_keys.length} findings</p><p>${esc(c.narrative || "")}</p><code>${c.finding_keys.join(" → ")}</code></div>`).join("");
    this.render(`<h2>Exploit Chains</h2>${rows || "<p>No chains found</p>"}`, "Exploit Chains");
  }

  private render(body: string, title: string): void {
    if (!this.panel) {
      this.panel = vscode.window.createWebviewPanel("gscWebview", title, vscode.ViewColumn.Beside, { enableScripts: false });
      this.panel.onDidDispose(() => { this.panel = undefined; });
    }
    this.panel.title = title;
    this.panel.webview.html = `<!DOCTYPE html><html><head><meta charset="utf-8"><style>body{font-family:var(--vscode-font-family);padding:16px;color:var(--vscode-foreground)}pre{background:var(--vscode-textCodeBlock-background);padding:12px;border-radius:6px;overflow-x:auto}.chain{border:1px solid var(--vscode-panel-border);padding:12px;margin:8px 0;border-radius:6px}.chain.critical{border-left:4px solid #f44}.chain.high{border-left:4px solid #f80}</style></head><body>${body}</body></html>`;
    this.panel.reveal(vscode.ViewColumn.Beside);
  }
}

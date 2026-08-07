import * as vscode from "vscode";
import * as path from "path";
import { Finding, Severity } from "./types";

const MAP: Record<Severity, vscode.DiagnosticSeverity> = {
  CRITICAL: vscode.DiagnosticSeverity.Error, HIGH: vscode.DiagnosticSeverity.Error,
  MEDIUM: vscode.DiagnosticSeverity.Warning, LOW: vscode.DiagnosticSeverity.Information,
};

export class GscDiagnostics {
  private collection: vscode.DiagnosticCollection;
  constructor() { this.collection = vscode.languages.createDiagnosticCollection("gsc"); }

  update(findings: Finding[], root: string): void {
    this.collection.clear();
    const byFile = new Map<string, vscode.Diagnostic[]>();
    for (const f of findings) {
      const abs = path.isAbsolute(f.file) ? f.file : path.join(root, f.file);
      const ln = Math.max(0, f.line - 1);
      const range = new vscode.Range(ln, 0, ln, 1000);
      const diag = new vscode.Diagnostic(range, `[${f.rule_id}] ${f.title} (${f.confidence.toFixed(2)})`, MAP[f.severity] ?? vscode.DiagnosticSeverity.Warning);
      diag.source = "GSC";
      diag.code = { value: f.rule_id, target: vscode.Uri.parse(`https://gsc.dev/rules/${f.rule_id}`) };
      const arr = byFile.get(abs) || []; arr.push(diag); byFile.set(abs, arr);
    }
    for (const [file, diags] of byFile) this.collection.set(vscode.Uri.file(file), diags);
  }
  clear(): void { this.collection.clear(); }
  dispose(): void { this.collection.dispose(); }
}

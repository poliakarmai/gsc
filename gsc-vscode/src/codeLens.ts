import * as vscode from "vscode";
import * as path from "path";
import { Finding } from "./types";

export class GscCodeLensProvider implements vscode.CodeLensProvider {
  private _onDidChange = new vscode.EventEmitter<void>();
  readonly onDidChangeCodeLenses = this._onDidChange.event;
  private findingsByFile = new Map<string, Finding[]>();

  setFindings(findings: Finding[], root: string): void {
    this.findingsByFile.clear();
    for (const f of findings) {
      const abs = path.isAbsolute(f.file) ? f.file : path.join(root, f.file);
      const arr = this.findingsByFile.get(abs) || []; arr.push(f); this.findingsByFile.set(abs, arr);
    }
    this._onDidChange.fire();
  }

  provideCodeLenses(doc: vscode.TextDocument): vscode.CodeLens[] {
    const findings = this.findingsByFile.get(doc.uri.fsPath) || [];
    const lenses: vscode.CodeLens[] = [];
    for (const f of findings) {
      const ln = Math.max(0, f.line - 1);
      const range = new vscode.Range(ln, 0, ln, 0);
      lenses.push(new vscode.CodeLens(range, { title: "🔬 PoC", command: "gsc.showPoc", arguments: [f.finding_key] }));
      lenses.push(new vscode.CodeLens(range, { title: "✅ TP", command: "gsc.verdictTp", arguments: [f.finding_key] }));
      lenses.push(new vscode.CodeLens(range, { title: "❌ FP", command: "gsc.verdictFp", arguments: [f.finding_key] }));
    }
    return lenses;
  }
  dispose(): void { this._onDidChange.dispose(); }
}

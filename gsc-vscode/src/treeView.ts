import * as vscode from "vscode";
import { Finding, Severity } from "./types";

const ICON: Record<Severity, string> = { CRITICAL: "🔴", HIGH: "🟠", MEDIUM: "🟡", LOW: "🟢" };
const ORDER: Severity[] = ["CRITICAL","HIGH","MEDIUM","LOW"];

export class SeverityNode extends vscode.TreeItem {
  constructor(public readonly severity: Severity, count: number) {
    super(`${ICON[severity]} ${severity} (${count})`, vscode.TreeItemCollapsibleState.Expanded);
    this.contextValue = "severityGroup";
  }
}

export class FindingNode extends vscode.TreeItem {
  constructor(finding: Finding) {
    super(`${finding.rule_id}: ${finding.title}`, vscode.TreeItemCollapsibleState.None);
    this.description = `${finding.file}:${finding.line} · ${finding.confidence.toFixed(2)}`;
    this.contextValue = "finding";
    this.tooltip = finding.snippet;
  }
}

export class GscFindingsProvider implements vscode.TreeDataProvider<SeverityNode | FindingNode> {
  private _onDidChange = new vscode.EventEmitter<void>();
  readonly onDidChangeTreeData = this._onDidChange.event;
  private findings: Finding[] = [];
  private minSev: Severity = "LOW";

  setFindings(findings: Finding[], minSev: Severity): void {
    this.findings = findings; this.minSev = minSev; this._onDidChange.fire();
  }

  getTreeItem(el: SeverityNode | FindingNode): vscode.TreeItem { return el; }

  getChildren(el?: SeverityNode | FindingNode): (SeverityNode | FindingNode)[] {
    if (!el) {
      const cutoff = ORDER.indexOf(this.minSev);
      return ORDER.slice(0, cutoff + 1)
        .map(s => ({ sev: s, items: this.findings.filter(f => f.severity === s) }))
        .filter(g => g.items.length > 0)
        .map(g => new SeverityNode(g.sev, g.items.length));
    }
    if (el instanceof SeverityNode) {
      return this.findings.filter(f => f.severity === el.severity).map(f => new FindingNode(f));
    }
    return [];
  }
}

import * as vscode from "vscode";
import { Finding, Severity } from "./types";
export declare class SeverityNode extends vscode.TreeItem {
    readonly severity: Severity;
    constructor(severity: Severity, count: number);
}
export declare class FindingNode extends vscode.TreeItem {
    constructor(finding: Finding);
}
export declare class GscFindingsProvider implements vscode.TreeDataProvider<SeverityNode | FindingNode> {
    private _onDidChange;
    readonly onDidChangeTreeData: vscode.Event<void>;
    private findings;
    private minSev;
    setFindings(findings: Finding[], minSev: Severity): void;
    getTreeItem(el: SeverityNode | FindingNode): vscode.TreeItem;
    getChildren(el?: SeverityNode | FindingNode): (SeverityNode | FindingNode)[];
}

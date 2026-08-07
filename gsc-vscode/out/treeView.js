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
exports.GscFindingsProvider = exports.FindingNode = exports.SeverityNode = void 0;
const vscode = __importStar(require("vscode"));
const ICON = { CRITICAL: "🔴", HIGH: "🟠", MEDIUM: "🟡", LOW: "🟢" };
const ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
class SeverityNode extends vscode.TreeItem {
    severity;
    constructor(severity, count) {
        super(`${ICON[severity]} ${severity} (${count})`, vscode.TreeItemCollapsibleState.Expanded);
        this.severity = severity;
        this.contextValue = "severityGroup";
    }
}
exports.SeverityNode = SeverityNode;
class FindingNode extends vscode.TreeItem {
    constructor(finding) {
        super(`${finding.rule_id}: ${finding.title}`, vscode.TreeItemCollapsibleState.None);
        this.description = `${finding.file}:${finding.line} · ${finding.confidence.toFixed(2)}`;
        this.contextValue = "finding";
        this.tooltip = finding.snippet;
    }
}
exports.FindingNode = FindingNode;
class GscFindingsProvider {
    _onDidChange = new vscode.EventEmitter();
    onDidChangeTreeData = this._onDidChange.event;
    findings = [];
    minSev = "LOW";
    setFindings(findings, minSev) {
        this.findings = findings;
        this.minSev = minSev;
        this._onDidChange.fire();
    }
    getTreeItem(el) { return el; }
    getChildren(el) {
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
exports.GscFindingsProvider = GscFindingsProvider;

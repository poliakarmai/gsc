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
exports.GscDiagnostics = void 0;
const vscode = __importStar(require("vscode"));
const path = __importStar(require("path"));
const MAP = {
    CRITICAL: vscode.DiagnosticSeverity.Error, HIGH: vscode.DiagnosticSeverity.Error,
    MEDIUM: vscode.DiagnosticSeverity.Warning, LOW: vscode.DiagnosticSeverity.Information,
};
class GscDiagnostics {
    collection;
    constructor() { this.collection = vscode.languages.createDiagnosticCollection("gsc"); }
    update(findings, root) {
        this.collection.clear();
        const byFile = new Map();
        for (const f of findings) {
            const abs = path.isAbsolute(f.file) ? f.file : path.join(root, f.file);
            const ln = Math.max(0, f.line - 1);
            const range = new vscode.Range(ln, 0, ln, 1000);
            const diag = new vscode.Diagnostic(range, `[${f.rule_id}] ${f.title} (${f.confidence.toFixed(2)})`, MAP[f.severity] ?? vscode.DiagnosticSeverity.Warning);
            diag.source = "GSC";
            diag.code = { value: f.rule_id, target: vscode.Uri.parse(`https://gsc.dev/rules/${f.rule_id}`) };
            const arr = byFile.get(abs) || [];
            arr.push(diag);
            byFile.set(abs, arr);
        }
        for (const [file, diags] of byFile)
            this.collection.set(vscode.Uri.file(file), diags);
    }
    clear() { this.collection.clear(); }
    dispose() { this.collection.dispose(); }
}
exports.GscDiagnostics = GscDiagnostics;

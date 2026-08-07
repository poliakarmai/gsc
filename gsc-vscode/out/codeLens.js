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
exports.GscCodeLensProvider = void 0;
const vscode = __importStar(require("vscode"));
const path = __importStar(require("path"));
class GscCodeLensProvider {
    _onDidChange = new vscode.EventEmitter();
    onDidChangeCodeLenses = this._onDidChange.event;
    findingsByFile = new Map();
    setFindings(findings, root) {
        this.findingsByFile.clear();
        for (const f of findings) {
            const abs = path.isAbsolute(f.file) ? f.file : path.join(root, f.file);
            const arr = this.findingsByFile.get(abs) || [];
            arr.push(f);
            this.findingsByFile.set(abs, arr);
        }
        this._onDidChange.fire();
    }
    provideCodeLenses(doc) {
        const findings = this.findingsByFile.get(doc.uri.fsPath) || [];
        const lenses = [];
        for (const f of findings) {
            const ln = Math.max(0, f.line - 1);
            const range = new vscode.Range(ln, 0, ln, 0);
            lenses.push(new vscode.CodeLens(range, { title: "🔬 PoC", command: "gsc.showPoc", arguments: [f.finding_key] }));
            lenses.push(new vscode.CodeLens(range, { title: "✅ TP", command: "gsc.verdictTp", arguments: [f.finding_key] }));
            lenses.push(new vscode.CodeLens(range, { title: "❌ FP", command: "gsc.verdictFp", arguments: [f.finding_key] }));
        }
        return lenses;
    }
    dispose() { this._onDidChange.dispose(); }
}
exports.GscCodeLensProvider = GscCodeLensProvider;

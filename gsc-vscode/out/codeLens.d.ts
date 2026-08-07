import * as vscode from "vscode";
import { Finding } from "./types";
export declare class GscCodeLensProvider implements vscode.CodeLensProvider {
    private _onDidChange;
    readonly onDidChangeCodeLenses: vscode.Event<void>;
    private findingsByFile;
    setFindings(findings: Finding[], root: string): void;
    provideCodeLenses(doc: vscode.TextDocument): vscode.CodeLens[];
    dispose(): void;
}

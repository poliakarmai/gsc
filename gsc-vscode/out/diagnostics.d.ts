import { Finding } from "./types";
export declare class GscDiagnostics {
    private collection;
    constructor();
    update(findings: Finding[], root: string): void;
    clear(): void;
    dispose(): void;
}

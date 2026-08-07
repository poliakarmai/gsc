export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export interface Finding {
    finding_key: string;
    rule_id: string;
    title: string;
    severity: Severity;
    confidence: number;
    file: string;
    line: number;
    snippet: string;
    metadata?: Record<string, unknown>;
}
export interface Chain {
    chain_key: string;
    finding_keys: string[];
    composed_severity: Severity;
    confidence: number;
    narrative?: string;
}
export interface Poc {
    poc: string;
    impact: string;
    format: string;
}
export interface ScanResult {
    findings: Finding[];
    chains?: Chain[];
}
export interface VerdictPayload {
    finding_key: string;
    verdict: "tp" | "fp" | "fixed";
    reason?: string;
}

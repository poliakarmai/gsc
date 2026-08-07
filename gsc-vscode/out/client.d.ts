import { Finding, Chain, Poc, VerdictPayload } from "./types";
export declare class GscClient {
    private baseUrl;
    private apiKey;
    constructor();
    private request;
    triggerScan(target: string): Promise<{
        scan_id?: string;
    }>;
    getFindings(): Promise<Finding[]>;
    getChains(): Promise<Chain[]>;
    getPoc(findingKey: string): Promise<Poc>;
    submitVerdict(payload: VerdictPayload): Promise<void>;
    submitOverride(findingKey: string, reason: string): Promise<void>;
}

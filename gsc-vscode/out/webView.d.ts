import { GscClient } from "./client";
export declare class GscWebView {
    private client;
    private panel?;
    constructor(client: GscClient);
    showPoc(key: string): Promise<void>;
    showChains(): Promise<void>;
    private render;
}

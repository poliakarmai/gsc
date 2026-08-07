import * as vscode from "vscode";
import { Finding, Chain, Poc, VerdictPayload } from "./types";

export class GscClient {
  private baseUrl: string;
  private apiKey: string;

  constructor() {
    const cfg = vscode.workspace.getConfiguration("gsc");
    this.baseUrl = cfg.get<string>("apiUrl", "http://localhost:8766");
    this.apiKey = cfg.get<string>("apiKey", "");
  }

  private async request<T>(path: string, init?: RequestInit): Promise<T> {
    const res = await fetch(`${this.baseUrl}${path}`, {
      ...init,
      headers: { "Content-Type": "application/json", "x-api-key": this.apiKey, ...(init?.headers || {}) },
    });
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      throw new Error(`GSC API ${res.status}: ${body.slice(0, 200)}`);
    }
    return res.json() as Promise<T>;
  }

  async triggerScan(target: string): Promise<{ scan_id?: string }> {
    return this.request("/api/v1/scan", {
      method: "POST",
      body: JSON.stringify({ target, profile: vscode.workspace.getConfiguration("gsc").get("profile", "developer-review") }),
    });
  }

  async getFindings(): Promise<Finding[]> {
    const r = await this.request<{ findings: Finding[] }>("/api/v1/findings");
    return r.findings || [];
  }

  async getChains(): Promise<Chain[]> {
    const r = await this.request<{ chains: Chain[] }>("/api/v1/chains");
    return r.chains || [];
  }

  async getPoc(findingKey: string): Promise<Poc> {
    return this.request<Poc>(`/api/v1/poc/${findingKey}`);
  }

  async submitVerdict(payload: VerdictPayload): Promise<void> {
    await this.request("/api/v1/feedback", { method: "POST", body: JSON.stringify(payload) });
  }

  async submitOverride(findingKey: string, reason: string): Promise<void> {
    await this.request("/api/v1/overrides", { method: "POST", body: JSON.stringify({ finding_key: findingKey, reason }) });
  }
}

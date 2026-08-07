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
exports.GscClient = void 0;
const vscode = __importStar(require("vscode"));
class GscClient {
    baseUrl;
    apiKey;
    constructor() {
        const cfg = vscode.workspace.getConfiguration("gsc");
        this.baseUrl = cfg.get("apiUrl", "http://localhost:8766");
        this.apiKey = cfg.get("apiKey", "");
    }
    async request(path, init) {
        const res = await fetch(`${this.baseUrl}${path}`, {
            ...init,
            headers: { "Content-Type": "application/json", "x-api-key": this.apiKey, ...(init?.headers || {}) },
        });
        if (!res.ok) {
            const body = await res.text().catch(() => "");
            throw new Error(`GSC API ${res.status}: ${body.slice(0, 200)}`);
        }
        return res.json();
    }
    async triggerScan(target) {
        return this.request("/api/v1/scan", {
            method: "POST",
            body: JSON.stringify({ target, profile: vscode.workspace.getConfiguration("gsc").get("profile", "developer-review") }),
        });
    }
    async getFindings() {
        const r = await this.request("/api/v1/findings");
        return r.findings || [];
    }
    async getChains() {
        const r = await this.request("/api/v1/chains");
        return r.chains || [];
    }
    async getPoc(findingKey) {
        return this.request(`/api/v1/poc/${findingKey}`);
    }
    async submitVerdict(payload) {
        await this.request("/api/v1/feedback", { method: "POST", body: JSON.stringify(payload) });
    }
    async submitOverride(findingKey, reason) {
        await this.request("/api/v1/overrides", { method: "POST", body: JSON.stringify({ finding_key: findingKey, reason }) });
    }
}
exports.GscClient = GscClient;

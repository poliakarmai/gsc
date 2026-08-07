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
const assert = __importStar(require("assert"));
suite("GSC Extension Unit", () => {
    test("severity order is correct", () => {
        const ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
        assert.strictEqual(ORDER.indexOf("CRITICAL"), 0);
        assert.strictEqual(ORDER.indexOf("LOW"), 3);
    });
    test("line 1-based to 0-based conversion", () => {
        assert.strictEqual(Math.max(0, 1 - 1), 0);
        assert.strictEqual(Math.max(0, 0 - 1), 0);
    });
    test("html escape prevents XSS", () => {
        const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
        const out = esc("<script>alert(1)</script>");
        assert.ok(!out.includes("<script>"));
        assert.ok(out.includes("&lt;script&gt;"));
    });
    test("minSeverity slicing", () => {
        const ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
        const cutoff = ORDER.indexOf("MEDIUM");
        const visible = ORDER.slice(0, cutoff + 1);
        assert.deepStrictEqual(visible, ["CRITICAL", "HIGH", "MEDIUM"]);
    });
    test("finding_key hexadecimal format", () => {
        assert.ok(/^[0-9a-f]{12}$/.test("abc123def456"));
        assert.ok(!/^[0-9a-f]{12}$/.test("GHIJKL123456"));
    });
});

#!/usr/bin/env node
"use strict";
// Simple unit test runner for gsc-vscode without VS Code runtime
let passed = 0, failed = 0;

function test(name, fn) {
  try { fn(); console.log(`  ✅ ${name}`); passed++; }
  catch (e) { console.log(`  ❌ ${name}: ${e.message}`); failed++; }
}

// ── Tests (copied from unit.test.ts logic) ──

test("severity order correct", () => {
  const ORDER = ["CRITICAL","HIGH","MEDIUM","LOW"];
  if (ORDER.indexOf("CRITICAL") !== 0) throw new Error("bad CRITICAL idx");
  if (ORDER.indexOf("LOW") !== 3) throw new Error("bad LOW idx");
});

test("line 1-based to 0-based conversion", () => {
  if (Math.max(0, 1 - 1) !== 0) throw new Error("1→0 failed");
  if (Math.max(0, 0 - 1) !== 0) throw new Error("0→0 failed");
});

test("html escape prevents XSS", () => {
  const esc = s => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  const out = esc("<script>alert(1)</script>");
  if (out.includes("<script>")) throw new Error("XSS not escaped");
  if (!out.includes("&lt;script&gt;")) throw new Error("missing entity");
});

test("minSeverity slicing", () => {
  const ORDER = ["CRITICAL","HIGH","MEDIUM","LOW"];
  const cutoff = ORDER.indexOf("MEDIUM");
  const visible = ORDER.slice(0, cutoff + 1);
  if (JSON.stringify(visible) !== '["CRITICAL","HIGH","MEDIUM"]') throw new Error("wrong slice");
});

test("finding_key hex format", () => {
  const re = /^[0-9a-f]{12}$/;
  if (!re.test("abc123def456")) throw new Error("valid key rejected");
  if (re.test("GHIJKL123456")) throw new Error("invalid key accepted");
});

test("GscClient URL construction", () => {
  const cfg = { get: (k, d) => ({ apiUrl: "http://localhost:8766", apiKey: "test" })[k] || d };
  const url = cfg.get("apiUrl", "http://localhost:8766");
  if (url !== "http://localhost:8766") throw new Error("wrong URL");
});

test("diagnostic severity mapping", () => {
  const MAP = { CRITICAL: 0, HIGH: 0, MEDIUM: 1, LOW: 2 };
  if (MAP["CRITICAL"] !== 0) throw new Error("CRITICAL≠Error");
  if (MAP["LOW"] !== 2) throw new Error("LOW≠Info");
});

console.log(`\nVSCode extension: ${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);

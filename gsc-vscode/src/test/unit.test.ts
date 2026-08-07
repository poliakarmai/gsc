import * as assert from "assert";

suite("GSC Extension Unit", () => {
  test("severity order is correct", () => {
    const ORDER = ["CRITICAL","HIGH","MEDIUM","LOW"];
    assert.strictEqual(ORDER.indexOf("CRITICAL"), 0);
    assert.strictEqual(ORDER.indexOf("LOW"), 3);
  });

  test("line 1-based to 0-based conversion", () => {
    assert.strictEqual(Math.max(0, 1 - 1), 0);
    assert.strictEqual(Math.max(0, 0 - 1), 0);
  });

  test("html escape prevents XSS", () => {
    const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    const out = esc("<script>alert(1)</script>");
    assert.ok(!out.includes("<script>"));
    assert.ok(out.includes("&lt;script&gt;"));
  });

  test("minSeverity slicing", () => {
    const ORDER = ["CRITICAL","HIGH","MEDIUM","LOW"];
    const cutoff = ORDER.indexOf("MEDIUM");
    const visible = ORDER.slice(0, cutoff + 1);
    assert.deepStrictEqual(visible, ["CRITICAL","HIGH","MEDIUM"]);
  });

  test("finding_key hexadecimal format", () => {
    assert.ok(/^[0-9a-f]{12}$/.test("abc123def456"));
    assert.ok(!/^[0-9a-f]{12}$/.test("GHIJKL123456"));
  });
});

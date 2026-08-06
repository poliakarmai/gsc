"use client";
import { useEffect, useState } from "react";
import { dash } from "@/lib/api";

export default function Findings() {
  const [rows, setRows] = useState<any[]>([]);
  const [sev, setSev] = useState("");

  useEffect(() => {
    dash.findings(sev ? { severity: sev } : undefined)
      .then(r => setRows(r.findings))
      .catch(() => setRows([]));
  }, [sev]);

  return (
    <main className="p-6">
      <h1 className="text-xl font-bold mb-4">Findings</h1>
      <select value={sev} onChange={e => setSev(e.target.value)}
              className="mb-4 border rounded p-1">
        <option value="">All severities</option>
        {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map(s =>
          <option key={s} value={s}>{s}</option>)}
      </select>
      <table className="w-full text-sm">
        <thead>
          <tr className="text-left border-b">
            <th>Sev</th><th>Rule</th><th>Conf</th><th>Location</th>
          </tr>
        </thead>
        <tbody>
          {rows.map(f => (
            <tr key={f.finding_key} className="border-b align-top">
              <td>{f.severity}</td>
              <td>{f.rule_id}</td>
              <td>{f.confidence?.toFixed(2)}</td>
              <td>
                {f.file}:{f.line}
                <pre className="text-xs bg-gray-50 p-2 mt-1 overflow-x-auto">
                  {f.snippet}
                </pre>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </main>
  );
}
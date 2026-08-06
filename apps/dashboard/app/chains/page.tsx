"use client";
import { useEffect, useState } from "react";
import { dash } from "@/lib/api";

export default function Chains() {
  const [rows, setRows] = useState<any[]>([]);
  useEffect(() => { dash.chains().then(r => setRows(r.chains)).catch(() => {}); }, []);
  return (
    <main className="p-6">
      <h1 className="text-xl font-bold mb-4">Chains</h1>
      <div className="space-y-3">
        {rows.map(c => (
          <div key={c.chain_key} className="border rounded p-3">
            <span className="font-mono text-sm">{c.chain_key}</span>
            <span className={`ml-2 text-xs px-2 py-0.5 rounded ${c.composed_severity === "CRITICAL" ? "bg-red-100 text-red-800" : "bg-yellow-100 text-yellow-800"}`}>{c.composed_severity}</span>
            <span className="ml-2 text-xs text-gray-500">{(c.confidence * 100).toFixed(0)}%</span>
            {c.narrative && <p className="text-sm mt-1 text-gray-600">{c.narrative}</p>}
          </div>
        ))}
      </div>
    </main>
  );
}
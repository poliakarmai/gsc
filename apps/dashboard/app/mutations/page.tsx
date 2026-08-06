"use client";
import { useEffect, useState } from "react";
import { dash } from "@/lib/api";

export default function Mutations() {
  const [rows, setRows] = useState<any[]>([]);
  useEffect(() => { dash.mutations().then(r => setRows(r.alerts)).catch(() => {}); }, []);
  return (
    <main className="p-6">
      <h1 className="text-xl font-bold mb-4">Mutation Alerts</h1>
      <table className="w-full text-sm">
        <thead><tr className="text-left border-b"><th>Finding</th><th>Parent</th><th>Kind</th><th>Similarity</th></tr></thead>
        <tbody>
          {rows.map(a => (
            <tr key={`${a.finding_key}-${a.parent_key}`} className="border-b">
              <td className="font-mono">{a.finding_key}</td>
              <td className="font-mono">{a.parent_key}</td>
              <td>{a.kind}</td>
              <td>{(a.similarity * 100).toFixed(0)}%</td>
            </tr>
          ))}
        </tbody>
      </table>
    </main>
  );
}
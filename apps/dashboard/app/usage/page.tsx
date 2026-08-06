"use client";
import { useEffect, useState } from "react";
import { dash } from "@/lib/api";

export default function Usage() {
  const [u, setU] = useState<any>(null);
  useEffect(() => { dash.usage().then(setU).catch(() => {}); }, []);
  if (!u) return <main className="p-6">Loading...</main>;
  const pct = u.scan_limit ? Math.round((u.scans_this_month / u.scan_limit) * 100) : 0;
  return (
    <main className="p-6">
      <h1 className="text-xl font-bold mb-4">Usage</h1>
      {u.scans_this_month >= u.scan_limit && (
        <div className="bg-amber-50 border border-amber-300 p-3 rounded mb-4">
          Monthly scan quota exhausted ({u.scan_limit}).
          <a href="/billing" className="underline ml-1">Upgrade</a>
        </div>
      )}
      <div className="space-y-2">
        <div>Plan: <strong>{u.plan}</strong> · Seats: {u.seats}</div>
        <div className="w-full bg-gray-200 rounded h-4">
          <div className="bg-blue-600 h-4 rounded" style={{ width: `${Math.min(pct, 100)}%` }}></div>
        </div>
        <div className="text-sm">{u.scans_this_month} / {u.scan_limit} scans</div>
        <div className="text-sm">{u.llm_calls_this_month} LLM calls</div>
      </div>
    </main>
  );
}
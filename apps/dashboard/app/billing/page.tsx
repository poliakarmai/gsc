"use client";
import { useState } from "react";

const API = process.env.NEXT_PUBLIC_GSC_API_URL ?? "";

export default function Billing() {
  const [loading, setLoading] = useState(false);

  async function upgrade(plan: string, seats: number) {
    setLoading(true);
    try {
      const res = await fetch(`${API}/api/v2/billing/checkout`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ plan, seats }),
        credentials: "include",
      });
      const { url } = await res.json();
      if (url) window.location.href = url;
    } catch (e) { /* */ }
    setLoading(false);
  }

  return (
    <main className="p-6">
      <h1 className="text-xl font-bold mb-4">Billing</h1>
      <div className="grid grid-cols-2 gap-4 max-w-lg">
        {[{ plan: "team", name: "Team", price: "$29", scans: 500 },
          { plan: "business", name: "Business", price: "$49", scans: 5000 }].map(t => (
          <div key={t.plan} className="border rounded p-4">
            <h2 className="font-bold">{t.name}</h2>
            <p className="text-sm text-gray-600">{t.price}/seat/mo · {t.scans} scans</p>
            <button onClick={() => upgrade(t.plan, 1)} disabled={loading}
                    className="mt-2 bg-black text-white px-4 py-1 rounded text-sm">
              {loading ? "..." : `Upgrade to ${t.name}`}
            </button>
          </div>
        ))}
      </div>
    </main>
  );
}
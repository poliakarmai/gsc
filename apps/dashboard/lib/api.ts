const API = process.env.NEXT_PUBLIC_GSC_API_URL ?? "";

async function req<T>(path: string): Promise<T> {
  const res = await fetch(`${API}${path}`, {
    credentials: "include",
    cache: "no-store",
  });
  if (res.status === 401) {
    if (typeof window !== "undefined") window.location.href = "/login";
    throw new Error("unauthenticated");
  }
  if (res.status === 403) throw new Error("no access to this tenant");
  if (res.status === 402) throw new Error("quota exceeded");
  if (!res.ok) throw new Error(`API ${res.status}`);
  return res.json();
}

export const dash = {
  repos: () => req<{ repos: any[] }>("/api/v2/dash/repos"),
  findings: (p?: { repo_id?: number; severity?: string }) => {
    const qs = new URLSearchParams();
    if (p?.repo_id) qs.set("repo_id", String(p.repo_id));
    if (p?.severity) qs.set("severity", p.severity);
    return req<{ findings: any[] }>(`/api/v2/dash/findings?${qs}`);
  },
  chains: () => req<{ chains: any[] }>("/api/v2/dash/chains"),
  mutations: () => req<{ alerts: any[] }>("/api/v2/dash/mutations"),
  usage: () => req<any>("/api/v2/dash/usage"),
};
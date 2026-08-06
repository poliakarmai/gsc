import { dash } from "@/lib/api";
import { cookies } from "next/headers";

const API = process.env.NEXT_PUBLIC_GSC_API_URL ?? "";

async function getData() {
  const res = await fetch(`${API}/api/v2/dash/repos`, {
    headers: { Cookie: `gsc_session=${(await cookies()).get("gsc_session")?.value ?? ""}` },
    cache: "no-store",
  });
  if (!res.ok) return [];
  return (await res.json()).repos;
}

export default async function Repos() {
  const repos = await getData();
  return (
    <main className="p-6">
      <h1 className="text-xl font-bold mb-4">Repositories</h1>
      <table className="w-full text-sm border">
        <thead><tr className="bg-gray-50"><th className="p-2 text-left">Name</th><th className="p-2 text-left">GitHub ID</th></tr></thead>
        <tbody>
          {repos.map((r: any) => (
            <tr key={r.id} className="border-t">
              <td className="p-2">{r.name}</td>
              <td className="p-2">{r.gh_repo_id}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </main>
  );
}
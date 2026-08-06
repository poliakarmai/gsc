import { NextResponse } from "next/server";

const API = process.env.GSC_API_URL!;

export async function GET(req: Request) {
  const { searchParams } = new URL(req.url);
  const code = searchParams.get("code");
  const state = searchParams.get("state");
  const res = await fetch(
    `${API}/api/v2/auth/github/callback?code=${code}&state=${state}`,
    { method: "POST", cache: "no-store" },
  );
  const reply = new NextResponse(null, { status: 302 });
  reply.headers.set("Location", "/repos");
  const setCookie = res.headers.get("set-cookie");
  if (setCookie) reply.headers.set("set-cookie", setCookie);
  return reply;
}
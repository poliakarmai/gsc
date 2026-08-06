import { NextResponse } from "next/server";

const API = process.env.GSC_API_URL!;

export async function GET() {
  const res = await fetch(`${API}/api/v2/auth/github/begin`, {
    method: "POST", cache: "no-store",
  });
  const { url } = await res.json();
  return NextResponse.redirect(url);
}
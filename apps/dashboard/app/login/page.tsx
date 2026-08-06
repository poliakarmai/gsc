"use client";
const API = process.env.NEXT_PUBLIC_GSC_API_URL ?? "";

export default function Login() {
  return (
    <main className="p-6 flex items-center justify-center min-h-screen">
      <a href={`${API}/api/v2/auth/github/begin`}
         className="bg-black text-white px-6 py-3 rounded text-lg">
        Sign in with GitHub
      </a>
    </main>
  );
}
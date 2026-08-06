export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-white text-gray-900">
        <nav className="border-b px-6 py-3 flex gap-4 text-sm">
          <a href="/repos">Repos</a>
          <a href="/findings">Findings</a>
          <a href="/chains">Chains</a>
          <a href="/mutations">Mutations</a>
          <a href="/usage">Usage</a>
          <a href="/billing">Billing</a>
        </nav>
        <main>{children}</main>
      </body>
    </html>
  );
}
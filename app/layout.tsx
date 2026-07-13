import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Threat Detection System",
  description:
    "Fuses a rule-based structural analysis with an AI semantic analysis under a deny-by-default posture: all content is treated as dangerous until it proves itself safe.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <header className="site-header">
          <div className="inner">
            <h1>🛡️ Threat Detection System</h1>
            <nav>
              <a href="/">Analyse</a>
              <a href="/history">History</a>
              <a href="/settings">Settings</a>
            </nav>
          </div>
        </header>
        <div className="container">{children}</div>
      </body>
    </html>
  );
}

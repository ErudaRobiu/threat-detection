import type { Metadata } from "next";
import { Space_Grotesk, JetBrains_Mono } from "next/font/google";
import SystemStatus from "./components/SystemStatus";
import "./globals.css";

const sans = Space_Grotesk({ subsets: ["latin"], weight: ["400", "500", "600", "700"], variable: "--font-sans" });
const mono = JetBrains_Mono({ subsets: ["latin"], weight: ["400", "500", "600"], variable: "--font-mono" });

export const metadata: Metadata = {
  title: "KWASU Threat Detection System",
  description:
    "Fuses rule-based structural analysis with AI semantic analysis under a deny-by-default posture: all content is dangerous until it proves itself safe.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" data-theme="dark" className={`${sans.variable} ${mono.variable}`} suppressHydrationWarning>
      <body>
        <header className="site-header">
          <div className="inner">
            <div className="brand">
              <span className="logo-box">
                {/* eslint-disable-next-line @next/next/no-img-element */}
                <img className="crest" src="/kwasu-logo.png" alt="Kwara State University crest" />
              </span>
              <span className="brand-name">
                <span className="brand-kwasu">KWASU</span>
                <span className="brand-sub">Threat Detection System</span>
              </span>
            </div>
            <div className="header-right">
              <nav>
                <a href="/" className="active">
                  Analyse
                </a>
                <a href="/history">History</a>
                <a href="/settings">Settings</a>
              </nav>
              <SystemStatus />
            </div>
          </div>
        </header>
        <div className="scan-strip" aria-hidden="true">
          <div className="run" />
        </div>
        {children}
      </body>
    </html>
  );
}

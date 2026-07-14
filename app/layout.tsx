import type { Metadata } from "next";
import { cookies } from "next/headers";
import { Plus_Jakarta_Sans, JetBrains_Mono } from "next/font/google";
import { ShieldCheck } from "lucide-react";
import ThemeToggle from "./components/ThemeToggle";
import "./globals.css";

const sans = Plus_Jakarta_Sans({ subsets: ["latin"], weight: ["400", "500", "600", "700"], variable: "--font-sans" });
const mono = JetBrains_Mono({ subsets: ["latin"], weight: ["400", "500", "700"], variable: "--font-mono" });

export const metadata: Metadata = {
  title: "Threat Detection System",
  description:
    "Fuses rule-based structural analysis with AI semantic analysis under a deny-by-default posture: all content is dangerous until it proves itself safe.",
};

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const theme = (await cookies()).get("theme")?.value === "light" ? "light" : "dark";
  return (
    <html lang="en" data-theme={theme} className={`${sans.variable} ${mono.variable}`}>
      <body>
        <header className="site-header">
          <div className="inner">
            <div className="brand">
              <span className="mark">
                <ShieldCheck size={16} strokeWidth={2} />
              </span>
              Threat Detection
            </div>
            <div className="header-right">
              <nav>
                <a href="/">Analyse</a>
                <a href="/history">History</a>
                <a href="/settings">Settings</a>
              </nav>
              <ThemeToggle />
            </div>
          </div>
        </header>
        {children}
      </body>
    </html>
  );
}

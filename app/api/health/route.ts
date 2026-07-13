/**
 * app/api/health/route.ts
 *
 * Deployment diagnostic — NOT part of the analysis product. It exists to catch a
 * specific silent failure: WHOIS lookups from a datacentre IP are frequently
 * rate-limited or blocked by registrars, and under deny-by-default a null
 * domainAgeDays counts as a FAILURE. If that happens in production, every URL
 * silently loses 0.15 of earned weight, every score inflates, and the UI still
 * looks fine — the corruption would not surface until the Chapter 4 false-positive
 * rate came out absurd with no obvious cause.
 *
 * This endpoint runs the REAL preprocess path (same tldts + WHOIS + TLS code the
 * analysis uses) against three known-good domains and reports the raw facts, so
 * local and production can be compared side by side. A number for domainAgeDays
 * means WHOIS worked; null means it did not.
 */

import { NextResponse } from "next/server";
import { preprocess } from "@/core/preprocess";

export const runtime = "nodejs";
export const maxDuration = 30;
export const dynamic = "force-dynamic";

const DOMAINS = ["google.com", "github.com", "wikipedia.org"];

export async function GET() {
  const t0 = performance.now();

  const whois = await Promise.all(
    DOMAINS.map(async (domain) => {
      const features = await preprocess(`https://${domain}`);
      const u = features.urls[0];
      return {
        domain,
        domainAgeDays: u?.domainAgeDays ?? null, // number = WHOIS ok; null = WHOIS failed/blocked
        sslValid: u?.sslValid ?? null, // true/false = reachable; null = TLS handshake failed
      };
    }),
  );

  const whoisWorking = whois.filter((w) => w.domainAgeDays !== null).length;
  const tlsWorking = whois.filter((w) => w.sslValid !== null).length;

  return NextResponse.json({
    ok: whoisWorking > 0,
    summary: `WHOIS resolved ${whoisWorking}/${DOMAINS.length}, TLS reached ${tlsWorking}/${DOMAINS.length}`,
    whois,
    geminiModel: process.env.GEMINI_MODEL ?? null,
    demoMode: process.env.DEMO_MODE === "1",
    node: process.version,
    elapsedMs: Math.round(performance.now() - t0),
  });
}

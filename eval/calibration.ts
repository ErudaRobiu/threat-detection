/**
 * eval/calibration.ts
 *
 * A prompt-calibration probe, NOT part of the deployed application and NOT the
 * Phase 5 evaluation harness (that is Python). It exists to answer one question
 * before any UI is built on top of the AI layer:
 *
 *   Does Gemini, under our prompt, place legitimate-but-pushy language in the
 *   0.2-0.4 band and genuine-but-urgent language low, rather than flagging
 *   everything that sounds alarming as fraud?
 *
 * If it does not, the HTSA agreement gate has nothing to suppress and the
 * Chapter 4 ablation produces no measurable finding. This is the cheapest place
 * to catch that — before the interface and the harness depend on the prompt.
 *
 * Each message is passed through the real redaction pipeline first, so this also
 * confirms the model scores LANGUAGE with the domains removed. Per item it also
 * records the dropped-pattern count from the verbatim-evidence guard: if the
 * model routinely paraphrases its spans, the guard would silently strip patterns
 * across the 1,600-item Phase 5 corpus and depress A invisibly.
 *
 * Run:  npx vite-node eval/calibration.ts
 *       (credentials are loaded from .env.local, not the ambient environment)
 */

import { readFileSync } from "node:fs";

import { analyzeTextDetailed } from "../core/ai";
import { toRedactedText } from "../core/preprocess";

// --- Load credentials from .env.local ONLY (the single mechanism) -----------
function loadEnvLocal(): void {
  let txt: string;
  try {
    txt = readFileSync(new URL("../.env.local", import.meta.url), "utf8");
  } catch (e) {
    console.error(`Could not read .env.local: ${(e as Error).message}`);
    process.exit(1);
  }
  for (const line of txt.split("\n")) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/);
    if (!m) continue;
    let v = m[2];
    if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) v = v.slice(1, -1);
    process.env[m[1]] = v;
  }
}
loadEnvLocal();

interface Case {
  n: number;
  description: string;
  band: [number, number];
  text: string;
}

const CASES: Case[] = [
  {
    n: 1,
    description: "Textbook phishing, PayPal impersonation + credential ask",
    band: [0.85, 1.0],
    text: `Subject: Your PayPal account has been limited

PayPal Security: we detected an unauthorized login to your account, which has now been temporarily limited. You must verify your identity within 24 hours or your account will be permanently suspended. Click the link below to restore access and confirm your password and card details:
https://paypa1-verify-secure.com/login`,
  },
  {
    n: 2,
    description: "Advance-fee / lottery win, no link",
    band: [0.85, 1.0],
    text: `Subject: FINAL NOTIFICATION OF YOUR AWARD

Dear Lucky Winner, your email address has won the sum of USD $2,500,000 in the International Online Lottery. To claim your winnings you must act immediately. Send your full name, address, and a processing fee of $350 via Western Union to our claims agent. This offer expires in 48 hours and cannot be reissued. Keep this confidential to avoid double claiming.`,
  },
  {
    n: 3,
    description: "Fake invoice, payment demand, no impersonation",
    band: [0.6, 0.8],
    text: `Subject: Overdue invoice #44921 — immediate payment required

Please find attached invoice #44921, now 14 days overdue. To avoid a late fee and suspension of service, settle the outstanding balance of $1,480 today by bank transfer to the account details below. Payment must be received by end of business or the matter will be escalated to collections.`,
  },
  {
    n: 4,
    description: "Recruiter cold outreach, mildly pushy, legitimate",
    band: [0.2, 0.4],
    text: `Subject: Senior Backend Engineer role — quick chat this week?

Hi Daniel, I came across your profile and think you'd be a strong fit for a Senior Backend Engineer position with one of our clients. The team is moving fast and interview slots are filling up for this week, so it would be great to connect soon. Are you open to a 15-minute call tomorrow or Thursday? Let me know a time that works.`,
  },
  {
    n: 5,
    description: "Retail marketing, 'sale ends Sunday', legitimate  [CRITICAL]",
    band: [0.2, 0.4],
    text: `Subject: ⏰ Our Summer Sale ends Sunday — 20% off everything

Hi Sarah! Our Summer Sale ends this Sunday at midnight. Take an extra 20% off everything with code SUN20 — don't miss out before these deals are gone. Shop now while your favourites are still in stock. You're receiving this because you subscribed to Bloom & Co updates. Unsubscribe any time.`,
  },
  {
    n: 6,
    description: "Genuine bank security alert, urgent, no ask  [INVERSE TRAP]",
    // Band widened from 0.20–0.50 to 0.00–0.50 after the first calibration run,
    // where the model scored this 0.08. The message actively defuses itself
    // ("no action is needed", "call the number on the back of your card", "we
    // will never ask for your password or PIN by email"), so there is no
    // manipulation left to detect. The original 0.20 floor wrongly assumed a
    // residual authority signal; scoring it low is the model PASSING the inverse
    // trap (0.96 for phishing vs 0.08 here — a 0.88 separation), not
    // miscalibrating. Recorded here so the change is visible, not a moved
    // goalpost. [Chapter 4]
    band: [0.0, 0.5],
    text: `Subject: New sign-in to your account

We noticed a new sign-in to your account from a new device. If this was you, no action is needed and you can ignore this message. If you don't recognise this activity, please call the number on the back of your card to speak with our support team. For your security, we will never ask for your password or PIN by email.`,
  },
  {
    n: 7,
    description: "Colleague asking to reschedule a meeting",
    band: [0.0, 0.2],
    text: `Subject: Move our 1:1?

Hey, something came up on my end tomorrow morning. Any chance we could push our 1:1 to Thursday afternoon instead? Happy to work around your schedule — let me know what suits.`,
  },
  {
    n: 8,
    description: "Password reset the user actually requested",
    band: [0.0, 0.3],
    text: `Subject: Reset your password

You recently requested to reset your password. Click the link below to choose a new one. This link will expire in 30 minutes for your security. If you didn't request a password reset, you can safely ignore this email and your password will remain unchanged.
https://accounts.example.com/reset?token=abc123`,
  },
];

const pad = (s: string, w: number) => (s.length > w ? s.slice(0, w - 1) + "…" : s.padEnd(w));

interface Row {
  c: Case;
  redacted: string;
  A: number;
  survivingPatterns: { id: string; evidence: string }[];
  dropped: { id: unknown; evidence: unknown; reason: string }[];
  inBand: boolean;
  error?: string;
}

async function main() {
  const model = process.env.GEMINI_MODEL;
  if (!process.env.GEMINI_API_KEY || !model) {
    console.error("GEMINI_API_KEY / GEMINI_MODEL missing from .env.local");
    process.exit(1);
  }
  console.log(`model: ${model}   (credentials loaded from .env.local)\n`);

  const rows: Row[] = [];
  for (const c of CASES) {
    const redacted = toRedactedText(c.text);
    try {
      const a = await analyzeTextDetailed(redacted);
      rows.push({
        c,
        redacted,
        A: a.result.A,
        survivingPatterns: a.result.patterns.map((p) => ({ id: p.id, evidence: p.evidence })),
        dropped: a.dropped.map((d) => ({ id: d.id, evidence: d.evidence, reason: d.reason })),
        inBand: a.result.A >= c.band[0] && a.result.A <= c.band[1],
      });
    } catch (err) {
      rows.push({ c, redacted, A: NaN, survivingPatterns: [], dropped: [], inBand: false, error: (err as Error).message });
    }
  }

  // --- Summary table --------------------------------------------------------
  const header = `${pad("#", 3)}${pad("Description", 52)}${pad("Expected", 12)}${pad("Actual", 8)}${pad("Verdict", 10)}Patterns`;
  console.log(header);
  console.log("-".repeat(110));
  for (const r of rows) {
    const expected = `${r.c.band[0].toFixed(2)}–${r.c.band[1].toFixed(2)}`;
    const actual = Number.isNaN(r.A) ? "ERR" : r.A.toFixed(2);
    const verdict = r.error ? "ERROR" : r.inBand ? "IN" : "OUT ***";
    const pats = r.error ? "(error)" : r.survivingPatterns.map((p) => p.id).join(", ") || "—";
    console.log(`${pad(String(r.c.n), 3)}${pad(r.c.description, 52)}${pad(expected, 12)}${pad(actual, 8)}${pad(verdict, 10)}${pats}`);
  }

  // --- Per-item detail ------------------------------------------------------
  let totalDrops = 0;
  for (const r of rows) {
    console.log(`\n${"=".repeat(72)}`);
    console.log(`item ${r.c.n} — ${r.c.description}`);
    console.log(`expected ${r.c.band[0].toFixed(2)}–${r.c.band[1].toFixed(2)}   actual ${Number.isNaN(r.A) ? "ERR" : r.A.toFixed(2)}   ${r.error ? "ERROR" : r.inBand ? "IN BAND" : "OUT OF BAND ***"}`);
    if (r.error) {
      console.log(`error: ${r.error}`);
      continue;
    }
    console.log(`\nredactedText the model was handed:\n"""\n${r.redacted}\n"""`);
    console.log(`\npatterns returned (${r.survivingPatterns.length + r.dropped.length}):`);
    for (const p of r.survivingPatterns) console.log(`  [kept]    ${pad(p.id, 24)} "${p.evidence}"`);
    for (const d of r.dropped) {
      console.log(`  [DROPPED:${d.reason}] ${pad(String(d.id), 24)} ${JSON.stringify(d.evidence)}`);
      totalDrops++;
    }
    if (r.dropped.length === 0) console.log("  (no patterns dropped by the verbatim-evidence guard)");
  }

  // --- Verdict --------------------------------------------------------------
  const byN = (n: number) => rows.find((r) => r.c.n === n)!;
  const item5 = byN(5);
  const item6 = byN(6);
  const outOfBand = rows.filter((r) => !r.inBand && !r.error);
  const errored = rows.filter((r) => r.error);

  console.log(`\n${"=".repeat(72)}`);
  console.log("VERDICT");
  console.log(`Item 5 (marketing, the gate's reason to exist): A=${Number.isNaN(item5.A) ? "ERR" : item5.A.toFixed(2)} -> ${item5.error ? "ERROR" : item5.inBand ? "IN BAND" : "OUT OF BAND"}`);
  console.log(`Item 6 (genuine bank alert, the inverse trap):  A=${Number.isNaN(item6.A) ? "ERR" : item6.A.toFixed(2)} -> ${item6.error ? "ERROR" : item6.inBand ? "IN BAND" : "OUT OF BAND"}`);
  console.log(`Out of band: ${outOfBand.length}/${rows.length} (items ${outOfBand.map((r) => r.c.n).join(", ") || "none"})`);
  console.log(`Errored:     ${errored.length}/${rows.length}`);
  console.log(`Total patterns dropped by the verbatim-evidence guard: ${totalDrops}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

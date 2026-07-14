/**
 * eval/transcribe-probe.ts
 *
 * Integration check for Stage 1 (image transcription). The pure blindness guard
 * lives in core/image-input.test.ts; this exercises the real Gemini vision call
 * against an actual screenshot, which is the only way to answer the question that
 * matters: does the transcriber preserve a homoglyph typosquat (a digit ONE in
 * "paypa1") instead of "helpfully" repairing it — and does it still survive after
 * the ~1400px downscale the client applies?
 *
 * Usage:
 *   npx vite-node eval/transcribe-probe.ts path/to/phishing-screenshot.png [more.png]
 *
 * To check downscale fidelity, first resize your screenshot to ~1400px on the
 * long edge (Preview → Tools → Adjust Size, or `sips -Z 1400 shot.png`) and run
 * the probe on that. If the digit one does not survive at 1400px, we need to know
 * now — raise the client downscale target above 1400.
 */

import { readFileSync } from "node:fs";
import { extname } from "node:path";

import { transcribeImage } from "../core/transcribe";
import { toRedactedText, extractUrlStrings } from "../core/preprocess";
import { detectBrandImpersonation } from "../core/rules";
import { parse } from "tldts";

function loadEnvLocal(): void {
  const txt = readFileSync(new URL("../.env.local", import.meta.url), "utf8");
  for (const line of txt.split("\n")) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/);
    if (m) process.env[m[1]] = m[2];
  }
}
loadEnvLocal();

const MIME: Record<string, string> = {
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".webp": "image/webp",
  ".heic": "image/heic",
};

async function main() {
  const paths = process.argv.slice(2);
  if (paths.length === 0) {
    console.error("Usage: npx vite-node eval/transcribe-probe.ts <image> [image...]");
    process.exit(1);
  }
  console.log(`transcribe model: ${process.env.GEMINI_TRANSCRIBE_MODEL ?? "gemini-2.5-flash-lite"}\n`);

  const texts: string[] = [];
  for (const p of paths) {
    const bytes = readFileSync(p);
    const mime = MIME[extname(p).toLowerCase()] ?? "image/png";
    console.log(`— ${p} (${(bytes.length / 1024).toFixed(0)} KB, ${mime})`);
    const text = await transcribeImage(bytes.toString("base64"), mime);
    texts.push(text);
    console.log(`transcription:\n"""\n${text}\n"""\n`);
  }

  const combined = texts.join("\n\n");
  const urls = extractUrlStrings(combined);
  const redacted = toRedactedText(combined);

  console.log("=".repeat(64));
  console.log("extracted URLs:", urls.length ? urls.join(", ") : "(none)");
  for (const u of urls) {
    const host = (() => {
      try {
        return new URL(/^[a-z]+:\/\//i.test(u) ? u : `http://${u}`).hostname;
      } catch {
        return u;
      }
    })();
    const domain = parse(host).domain ?? host;
    const imp = detectBrandImpersonation(domain);
    console.log(`  ${domain} -> brand impersonation: ${imp ? `${imp.brand} (distance ${imp.distance})` : "none"}`);
  }

  console.log("\nblindness check (what the AI would be handed):");
  console.log(`  contains [LINK]: ${redacted.includes("[LINK]")}`);
  console.log(`  leaks any extracted domain: ${urls.some((u) => redacted.includes(u.replace(/^https?:\/\//, "").split("/")[0]))}`);
  console.log("\nEyeball the transcription above: every digit-one / zero in a look-alike domain must be preserved verbatim.");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

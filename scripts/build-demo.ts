/**
 * scripts/build-demo.ts
 *
 * Generates core/demo-data.json by running the REAL analysis pipeline over the
 * five DEMO_INPUTS and freezing each result, keyed by SHA-256 of the trimmed
 * text. DEMO_MODE then serves these with no network call.
 *
 * The demo data is genuine system output, not hand-written — it is whatever the
 * pipeline actually produced on these inputs, captured once. Re-run whenever the
 * inputs or the core change:
 *
 *   npx vite-node scripts/build-demo.ts
 */

import { readFileSync, writeFileSync } from "node:fs";
import { analyze } from "../core/analyze";
import { DEMO_INPUTS } from "../core/demo-inputs";
import { demoHash } from "../core/demo";

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

async function main() {
  const out: Record<string, unknown> = {};
  for (const d of DEMO_INPUTS) {
    process.stdout.write(`analysing ${d.id.padEnd(18)} … `);
    const r = await analyze(d.text);
    out[demoHash(d.text)] = r;
    console.log(
      `${r.classification.padEnd(8)} R=${r.ruleScore === null ? "null" : r.ruleScore.toFixed(3)}  ` +
        `A=${r.aiScore === null ? "null" : r.aiScore.toFixed(3)}  H=${r.hybridScore.toFixed(3)}  ` +
        `(rules ${r.timings.rules}ms, ai ${r.timings.ai}ms)`,
    );
  }
  writeFileSync(new URL("../core/demo-data.json", import.meta.url), JSON.stringify(out, null, 2) + "\n");
  console.log(`\nwrote core/demo-data.json (${DEMO_INPUTS.length} examples)`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

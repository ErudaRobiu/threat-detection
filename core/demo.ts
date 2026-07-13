/**
 * core/demo.ts
 *
 * DEMO_MODE lookup. When DEMO_MODE is on, the analyze route resolves a submission
 * against the bundled pre-analysed results in demo-data.json, keyed by SHA-256 of
 * the trimmed submission text, and returns instantly with no network call. This
 * is what keeps the live defence robust to a dead room: the five examples work
 * with the power flickering and the wifi down.
 *
 * Non-matching submissions in DEMO_MODE fall through to the real pipeline (which
 * itself degrades gracefully offline); only the five bundled examples are served
 * from cache.
 */

import { createHash } from "node:crypto";
import type { AnalysisResult } from "./types";
import demoData from "./demo-data.json";

export function demoHash(raw: string): string {
  return createHash("sha256").update(raw.trim(), "utf8").digest("hex");
}

export function getDemoResult(raw: string): AnalysisResult | null {
  const map = demoData as Record<string, AnalysisResult>;
  return map[demoHash(raw)] ?? null;
}

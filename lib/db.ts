/**
 * lib/db.ts — local analysis history (Phase 4).
 *
 * LOCAL SQLite only, via Node's built-in `node:sqlite` (no dependency, no Turso).
 * The database is a single file under `data/history.db`, gitignored.
 *
 * TWO hard rules this module enforces:
 *
 *  1. VERCEL IS EPHEMERAL. Serverless has a read-only / throwaway filesystem, so
 *     a SQLite write there SILENTLY appears to succeed and then vanishes — history
 *     would come back empty with no error. So persistence is GATED on
 *     `process.env.VERCEL`: on Vercel we do not touch the disk at all, and the
 *     history API reports `disabled: true` with a reason instead of lying with an
 *     empty list. Persistence is a local-demo feature by design.
 *
 *  2. FAIL SOFT, ALWAYS. Analysis must never fail because history could not be
 *     written or read. Every export swallows its own errors and returns a safe
 *     value (void / []). A corrupt or unwritable DB degrades the history page,
 *     never the analyzer.
 */

import type { AnalysisResult } from "@/core/types";

// --- environment gate -------------------------------------------------------

/** True on Vercel (and any env that sets VERCEL): filesystem is ephemeral. */
export const HISTORY_DISABLED = !!process.env.VERCEL;

export const HISTORY_DISABLED_REASON =
  "Analysis history is a local-only feature. This deployment runs on Vercel's " +
  "ephemeral serverless filesystem, where a database write would be silently " +
  "discarded, so persistence is turned off here. Run the app locally to keep history.";

export interface HistoryRow {
  id: number;
  createdAt: string;
  contentType: string;
  ruleScore: number | null;
  aiScore: number | null;
  hybridScore: number;
  classification: string;
  aiAvailable: boolean;
  preview: string;
  rulesMs: number | null;
  aiMs: number | null;
  totalMs: number | null;
}

// --- lazy, fail-soft connection ---------------------------------------------

// Typed loosely: node:sqlite has no bundled @types and is imported lazily so the
// module never loads on Vercel.
type Db = { exec(sql: string): void; prepare(sql: string): Stmt } | null;
type Stmt = { run(...a: unknown[]): unknown; all(...a: unknown[]): unknown[]; get(...a: unknown[]): unknown };

let _db: Db | undefined; // undefined = not tried yet; null = tried and unavailable

function db(): Db {
  if (_db !== undefined) return _db;
  _db = null;
  if (HISTORY_DISABLED) return _db; // never open a file on Vercel
  try {
    // require, not import: keeps this off the module graph on Vercel and out of
    // the client bundle. eslint-disable for the dynamic require.
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { DatabaseSync } = require("node:sqlite") as {
      DatabaseSync: new (path: string) => NonNullable<Db>;
    };
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { mkdirSync } = require("node:fs") as typeof import("node:fs");
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const path = require("node:path") as typeof import("node:path");
    const dir = path.join(process.cwd(), "data");
    mkdirSync(dir, { recursive: true });
    const conn = new DatabaseSync(path.join(dir, "history.db"));
    conn.exec(`
      CREATE TABLE IF NOT EXISTS analyses (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at     TEXT    NOT NULL,
        content_type   TEXT    NOT NULL,
        rule_score     REAL,
        ai_score       REAL,
        hybrid_score   REAL    NOT NULL,
        classification TEXT    NOT NULL,
        ai_available   INTEGER NOT NULL,
        preview        TEXT    NOT NULL,
        rules_ms       REAL,             -- NFR01 latency, from result.timings
        ai_ms          REAL,
        total_ms       REAL
      );
    `);
    _db = conn;
  } catch (err) {
    console.error("[lib/db] history unavailable (analysis unaffected):", err);
    _db = null;
  }
  return _db;
}

// --- API --------------------------------------------------------------------

/** A short, single-line preview of the submitted content for the history table. */
function makePreview(result: AnalysisResult, input: string): string {
  const src = result.transcription?.trim() || input.trim();
  const oneLine = src.replace(/\s+/g, " ").slice(0, 140);
  return oneLine.length < src.replace(/\s+/g, " ").length ? oneLine + "…" : oneLine;
}

/**
 * Persist one analysis. FAIL-SOFT: never throws, returns nothing. A write that
 * fails (or is disabled on Vercel) is logged and dropped — the caller already
 * has its result and must return it regardless.
 */
export function saveAnalysis(result: AnalysisResult, input: string): void {
  const conn = db();
  if (!conn) return;
  try {
    conn
      .prepare(
        `INSERT INTO analyses
           (created_at, content_type, rule_score, ai_score, hybrid_score,
            classification, ai_available, preview, rules_ms, ai_ms, total_ms)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        result.createdAt,
        result.contentType,
        result.ruleScore,
        result.aiScore,
        result.hybridScore,
        result.classification,
        result.aiAvailable ? 1 : 0,
        makePreview(result, input),
        result.timings?.rules ?? null,
        result.timings?.ai ?? null,
        result.timings?.total ?? null,
      );
  } catch (err) {
    console.error("[lib/db] saveAnalysis failed (analysis unaffected):", err);
  }
}

/**
 * Most recent analyses, newest first. FAIL-SOFT: returns [] if history is
 * disabled or the read fails.
 */
export function getHistory(limit = 100): HistoryRow[] {
  const conn = db();
  if (!conn) return [];
  try {
    const rows = conn
      .prepare(
        `SELECT id, created_at, content_type, rule_score, ai_score, hybrid_score,
                classification, ai_available, preview, rules_ms, ai_ms, total_ms
           FROM analyses
          ORDER BY id DESC
          LIMIT ?`,
      )
      .all(limit) as Array<Record<string, unknown>>;
    return rows.map((r) => ({
      id: Number(r.id),
      createdAt: String(r.created_at),
      contentType: String(r.content_type),
      ruleScore: r.rule_score === null ? null : Number(r.rule_score),
      aiScore: r.ai_score === null ? null : Number(r.ai_score),
      hybridScore: Number(r.hybrid_score),
      classification: String(r.classification),
      aiAvailable: Number(r.ai_available) === 1,
      preview: String(r.preview),
      rulesMs: r.rules_ms == null ? null : Number(r.rules_ms),
      aiMs: r.ai_ms == null ? null : Number(r.ai_ms),
      totalMs: r.total_ms == null ? null : Number(r.total_ms),
    }));
  } catch (err) {
    console.error("[lib/db] getHistory failed:", err);
    return [];
  }
}

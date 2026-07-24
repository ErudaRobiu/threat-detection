# Database schema (Phase 4 — local analysis history)

From `lib/db.ts`. Local **SQLite** via Node's built-in `node:sqlite` (no
dependency, no Turso). Single file at `data/history.db` (gitignored).

**Gated on `process.env.VERCEL`:** on Vercel the serverless filesystem is
ephemeral — a write would be silently discarded — so persistence is disabled
there and `/api/history` reports `{ disabled: true, reason }` rather than
returning a misleadingly empty list. Persistence is a local-demo feature by
design. All DB access is **fail-soft**: a write/read error is logged and
swallowed so an analysis can never fail because history could not be recorded.

## Table `analyses`

```sql
CREATE TABLE IF NOT EXISTS analyses (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at     TEXT    NOT NULL,   -- ISO-8601 timestamp from the analysis result
  content_type   TEXT    NOT NULL,   -- 'email' | 'url' | 'text' | 'image'
  rule_score     REAL,               -- R in [0,1]; NULL = rule engine abstained
  ai_score       REAL,               -- A in [0,1]; NULL = semantic layer abstained
  hybrid_score   REAL    NOT NULL,   -- H in [0,1]
  classification TEXT    NOT NULL,   -- 'Low' | 'Medium' | 'High' | 'Critical'
  ai_available   INTEGER NOT NULL,   -- 1 = Gemini ran; 0 = degraded to rule-only
  preview        TEXT    NOT NULL    -- single-line, ≤140-char snippet of the input
);
```

Read path (`getHistory`): `SELECT … ORDER BY id DESC LIMIT ?` (newest first,
default 100). `NULL` rule/ai scores are preserved through to the UI as an
en-dash, so abstention stays visible and is never rendered as 0.

**Note (Chapter 4):** this schema stores **scores, not timings**. NFR01 latency
evidence comes from the dedicated timing probe (`eval/out/nfr01_timings.txt`),
not from these rows. A `timings` column will be added post-run for the live demo.

# Project state — handoff for the next session

Read `CLAUDE.md` (the spec/intake, authoritative) and this file first. This is
the working state as of 2026-07-15. When it and CLAUDE.md disagree, CLAUDE.md wins.

## What this is

Final-year CS project. A **Next.js** web app where a user submits a suspicious
email / URL / text (or a **screenshot**) and gets a threat verdict that **fuses a
rule-based structural analysis (R) with a blind AI semantic analysis (A)** under a
**deny-by-default** posture (everything starts at max threat = 1.000 and earns its
way down). The report chapters 1–3 are already submitted; we build the system they
describe and produce artefacts for Chapters 4–5. **Never invent metrics/accuracy
numbers.** The deployed app is one Next app; the Phase-5 evaluation harness is
separate Python in `/eval`, never deployed.

## The four load-bearing invariants (do not "fix" these)

1. **Deny by default.** Start at max threat, earn reductions. An *indeterminate*
   check is a FAILURE (WHOIS returns nothing → fail; TLS host unreachable → fail).
2. **R is normalised over APPLICABLE indicators**, not all nine:
   `R = 1 − Σ(w·pass)/Σ(w)` over applicable. Empty applicable set → `R = null`
   (abstention), never 0 or 1.
3. **The HTSA interaction term is an AGREEMENT GATE, not an amplifier.**
   `H = 0.4R + 0.4A + 0.2RA`; because weights sum to 1, `H ≤ mean(R,A)` always. It
   suppresses on disagreement (soft-AND). Ablation weights are `{0.5, 0.5, 0}`.
4. **Symmetric abstention** (added this project): each layer abstains when it has
   nothing to read. R=null (no structural indicators) → H=A. **A=null** (no
   analysable language, e.g. a bare URL — decided on CONTENT via
   `hasAnalysableLanguage`, ≥15 alnum chars after stripping `[LINK]`/`[EMAIL]`, NOT
   on contentType) → H=R. Both null → `NoAnalysableContentError` → 400. See
   memory `symmetric-abstention`.

## The other non-negotiable: structural blindness

The AI reads **redacted words only** — never the domain/URL/headers. `preprocess`
redacts URLs+bare-domains → `[LINK]` and emails → `[EMAIL]`; the rule engine reads
the real infrastructure, the AI reads the redacted text. This keeps R and A
independent so the gate measures corroboration, not redundancy. **Image input
preserves this**: `core/transcribe.ts` (a SEPARATE Gemini vision call) transcribes
the screenshot to text FIRST, then that text enters the ordinary pipeline — the
image never reaches the analysis layer. `core/image-input.test.ts` is the
regression guard; do not weaken it.

## File map (what matters)

```
core/
  types.ts        THE CONTRACT. ContentType includes "image". AnalysisResult has
                  ruleScore|aiScore: number|null and transcription: string|null.
  rules.ts        pure R engine, 9 indicators, applicability, brand homoglyph match.
                  email_auth is 3-state (present/pass, present/fail, absent→n/a).
  htsa.ts         fuse(R,A,weights,thresholds) — 3 abstention states + NoAnalysableContentError.
  preprocess.ts   raw -> Features. Redaction, WHOIS, TLS, email parse, hasAnalysableLanguage.
  ai.ts           analyzeText(redactedText) — one Gemini call, temp 0, JSON schema,
                  verbatim-evidence guard, sha256 cache. analyzeTextDetailed exposes drops.
  transcribe.ts   Stage-1 image OCR (GEMINI_TRANSCRIBE_MODEL, homoglyph no-autocorrect).
  analyze.ts      orchestrator: preprocess->rules->ai->fuse; A=R degradation; AiUnavailableError.
  demo.ts/demo-inputs.ts/demo-data.json   DEMO_MODE 5 bundled examples (regen: scripts/build-demo.ts).
  *.test.ts       67 tests, all pure (no network/API). `npx vitest run`.
app/
  page.tsx        two-col Analyse screen: drop zone (drag/paste/click/image), tabs, chips.
  components/     ThreatReport, Gauge (score drain), Overview (empty state), ThemeToggle.
  settings/page.tsx   live gamma ablation (badge flip). history/page.tsx = Phase-4 stub.
  api/analyze/route.ts  JSON + multipart(images). api/health/route.ts = WHOIS/TLS diagnostic.
  globals.css     two-theme tokens (dark default), indigo system accent, Plus Jakarta + JetBrains Mono.
eval/             Phase 5 (Python, never deployed). run.py, charts.py, fetch_corpora.sh, NOTES.md.
                  data/ is gitignored (reproduce with fetch_corpora.sh).
docs/             deployment-verification.md, this file.
```

## Phase status

| Phase | State |
|---|---|
| 1 core engine | ✅ committed, tested |
| 2 preprocess + AI + calibration | ✅ committed (calibration 8/8 in band, evidence-drop 0) |
| 3 API + UI + DEMO_MODE + graceful degradation | ✅ committed; redesigned to fintech dark/light; image input added |
| 4 DB + history + settings | ⚠️ Settings (ablation) done; **History is a stub — needs the DB (not built)**; `lib/db.ts` not built |
| 5 eval harness | 🔨 skeleton done (run.py conditions 1–4 + continuous metrics + charts.py). **baseline.py (RF, condition 5) not built. Full 1,600 run NOT started.** |
| 6 deploy/harden | Vercel deploy done by user; health check verified 3/3 WHOIS+TLS (docs/deployment-verification.md) |

## Corpora (sourced 2026-07-14, in eval/data, gitignored)

500 Tranco legit URLs · 500 Phishing.Database phishing URLs · 300 Nazario phishing
emails · 300 SpamAssassin easy_ham legit emails. Two substitutions documented in
`eval/NOTES.md` (PhishTank→Phishing.Database rate-limited; Enron→SpamAssassin too
large for the time-box). Both are one sentence in Chapter 3.

## OPEN — awaiting the user's decision (do not auto-proceed)

1. **Full evaluation run NOT started.** On the 48-item smoke the **agreement gate
   showed no effect** (γ=0 and γ=0.2 identical binary metrics, identical best-F1
   0.818, equal AUC 0.825; flip-zone only 2/24 email items; mean suppression
   0.044). The user must decide: run the full 1,600 anyway, or first check the
   corpus even *has* enough borderline items to show the gate. This is the central
   thesis risk — report honestly, never dress up a null result.
2. **Chapter 3 "rule-only F1 > 0.94" is not reachable on this corpus.** The DMARC
   fix removed the artefact (precision up, FPR down) but exposed genuinely low
   rule-layer recall (phishing on legit infra and text-only phishing → R≈0). This
   is the argument FOR fusion, but the claim needs revising. Awaiting the user.
3. **Transcription prompt** (`core/transcribe.ts`) is committed but the user may
   still tweak wording after testing on real screenshots.

## How to run things (env: GEMINI_API_KEY, GEMINI_MODEL=gemini-2.5-flash, GEMINI_TRANSCRIBE_MODEL=gemini-2.5-flash-lite in .env.local)

```
npx vitest run                                  # 67 pure tests
DEMO_MODE=1 npx next dev -p 3210                 # app at localhost:3210
npx vite-node scripts/build-demo.ts              # regen demo-data.json (after core changes)
npx vite-node eval/calibration.ts                # AI calibration probe
npx vite-node eval/transcribe-probe.ts shot.png  # image homoglyph-fidelity check
bash eval/fetch_corpora.sh                        # re-download corpora
python3 eval/run.py --limit 50                    # eval smoke (needs dev server up)
python3 eval/run.py                               # full run (hours-days; not yet run)
```

## Gotchas

- After changing `core/` logic, **regen `demo-data.json`** (`scripts/build-demo.ts`)
  and **clear `eval/cache.json`** — both cache computed R/A/H and go stale.
- macOS has no `shuf` (use `sort -R`); Bash tool `cd` into subdirs persists — cd back.
- `eval/run.py` is stdlib-only (no pip). `eval/charts.py` needs matplotlib.
- Gemini on-disk caches: `.cache/gemini` (analysis), `.cache/transcribe` (OCR),
  keyed by sha256 of redacted text / image bytes. Gitignored.

## Working preferences (see memories)

- **Do not self-test in the browser** to save tokens — the user drives testing.
  Restart the dev server + cheap HTTP route checks are fine (memory `no-self-testing`).
- **Ask on any unspecified decision within a phase** — the user is detail-oriented
  and wants to be consulted, not informed after. **Never fabricate metrics.**
- Commit/push when asked (has been frequent). End commit trailers per Bash rules.

## Git

Branch `main`, pushed to `github.com/ErudaRobiu/threat-detection`. Latest:
`46220e0` (email_auth applicability + eval metrics). 13 commits, Phases 1–3 + image
input + Phase-5 skeleton all in.

# Results summary — Chapter 4 source (PARTIAL)

> **STATUS: PARTIAL (updated after email-first resume).** The full-corpus run
> attempted all **1,479** items; the Gemini free-tier rate limit degraded part of
> the semantic layer (it fails soft to A=R, deliberately **not cached**). An
> email-first resume then re-scored the rate-limit-starved email class before
> being stopped. What follows is computed from the **clean cache only** — items
> that genuinely scored, degraded and errored items excluded.
>
> **Clean n = 1,151 corpus items** (was 857 before the resume): 724 URLs (381
> legitimate / 343 phishing) and **427 emails (297 legitimate / 130 phishing)**.
> The email-first resume lifted the phishing-email class from 19 to **130**, so
> the semantic and gate numbers below now rest on an adequate positive class
> rather than a tiny one. The **hard-case corpus (100 items, 50/50) is complete**,
> and the Random-Forest baseline (1,000 URLs) is complete. Email coverage is still
> partial (427 of 600 emails scored); numbers are marked FINAL only after a fully
> clean run.
>
> Reporting rule observed throughout: **precision and recall are reported
> separately**, never F1 alone. The gate result is reported as numbers, not
> interpreted — the discussion is the author's.

Hardware (Table 4.1): Apple M1 Pro, 10 cores, 16 GB RAM, macOS 26.2 (build
25C56), arm64; Node v25.9.0, Python 3.9.6. Model `gemini-2.5-flash`, temperature
0, one call per submission, SHA-256 response cache.

---

## 1. Conditions 1–6 (clearance threshold 0.3)

| # | Condition | n | precision | recall | F1 | FPR | AUC |
|---|---|--:|--:|--:|--:|--:|--:|
| 1 | Rule only (R) | 1151 | 0.817 | 0.482 | 0.606 | 0.075 | 0.712 |
| 2 | AI only (A) — email only | 423 | 0.823 | 0.960 | 0.886 | 0.088 | 0.979 |
| 3 | HTSA, γ = 0 (ablation) | 1151 | 0.867 | 0.662 | 0.751 | 0.071 | 0.801 |
| 4 | HTSA, γ = 0.2 (deployed) | 1151 | 0.880 | 0.649 | 0.747 | 0.062 | 0.804 |
| 5 | Random Forest, domain-only | 1000 | 0.743 | 0.654 | 0.696 | 0.226 | 0.767 |
| 6 | HTSA-E (escalation) | 1151 | = Condition 4 at t=0.3 (acts above the clearance line — see §3) |

Best-F1 over a full threshold sweep: rule 0.622 @0.23, AI 0.946 @0.55, HTSA γ=0
0.754 @0.32, HTSA γ=0.2 0.754 @0.22. The gate does not raise best-F1 (identical to
γ=0), consistent with a precision-for-recall trade rather than a strict gain.

Notes on reading this table:

- **Condition 1 (rule only)** has high precision (0.831) but low recall (0.555):
  the structural layer is trustworthy when it fires but misses a large fraction
  of threats, because modern phishing on clean infrastructure and all text-only
  social engineering are structurally innocent. This is the empirical motivation
  for the semantic layer, not an implementation shortfall (see NFR02 restatement
  in `eval/NOTES.md`).
- **Condition 2 (AI only)** is email-only by construction — the semantic layer
  abstains on bare URLs (A = null), so the 724 URL items contribute no A. After the
  email-first resume its n = 423 email items include **126 phishing emails**, and
  its AUC is **0.979** (precision 0.823, recall 0.960) — a credible estimate, no
  longer the tiny-positive-class 1.000 of the 857-item snapshot. The semantic layer
  is the strongest single layer on emails.
- **Condition 5 (Random Forest)** is the domain-only (artefact-free) baseline:
  best-F1 0.727 at its optimal threshold. The inflated F1 = 0.993 obtained on
  full-URL lexical features is a **collection artefact**, not phishing signal (see
  §4). 0.727 is the honest baseline the hybrid is measured against.
- Conditions 3 and 4 are computed from the same cached R and A with no extra API
  calls, exactly as designed.

## 2. The agreement gate (γ = 0 → γ = 0.2), reported as counts

The gate only acts on items that carry **both** layers (URLs abstain on A, so
H = R and the gate cannot move them). Its entire effect therefore lives in the
**423 dual-layer email items (126 phishing)**, not in the 1,151 total. Three
corpora, reported straight:

- **Main corpus, dual-layer subset (423 emails, 126 phishing).** False positives
  9 → 3 (**−6 FP suppressed**); true positives 118 → 112 (**−6 TP lost**);
  precision 0.929 → 0.974, recall 0.937 → 0.889; AUC 0.801 → 0.804. This is a
  **precision-for-recall trade**, not a free win: six false positives removed at
  the cost of six true positives. (On the full 1,151 the same movement reads as
  precision 0.867 → 0.880, FPR 0.071 → 0.062, recall 0.662 → 0.649, AUC up 0.003 —
  the inert URLs dilute it.)
- **Hard-case corpus (100 items, complete).** False positives 10 → 9 (**−1 FP
  suppressed**); true positives 46 → 44 (**−2 TP lost**); precision 0.821 → 0.830,
  recall 0.920 → 0.880. Net-negative at this operating point.
- **48-item smoke.** No classification change either way (identical best-F1 0.818,
  AUC 0.825); mean suppression 0.044.

**Revised reading (supersedes the 857-item snapshot):** with an adequate positive
class the gate is a consistent **precision-for-recall trade**, not the "3 FP
suppressed / 0 TP lost" clean win the thinner data suggested. It lowers FPR and
raises precision, at a matching cost in recall; best-F1 is unchanged. γ above 0.2
remains harmful throughout. Mean gate suppression at γ = 0.2 is 0.034 (max 0.098);
the flip-zone (0.25 ≤ mean(R,A) ≤ 0.40) now holds 37 email items.

## 3. HTSA-E (Condition 6): escalation, tau, and tier movement

HTSA-E adds the disjunctive half of the Chapter-1 posture (either layer may
convict): H_e = max(H, A if A ≥ τ, R if R ≥ τ). Computed from cached R,A on the
combined **926 dual-corpus items (728 legitimate / 198 threat)** after the resume
(was 632).

- **τ = 0.76**, derived — not hand-picked — as the lowest value at which **no
  legitimate training item escalates**. The resume lowered τ from 0.91 to **0.76**,
  because a legitimate internal-business item scoring A = 0.75 now sets the ceiling
  (the 0.90 anchor of the smaller data was not representative). This confirms the
  earlier caveat that τ was anchored to sparse authored data.
- **Legitimate ceilings, reported separately:** A-arm ceiling **0.75**, R-arm
  ceiling **0.588**.
- **Ceiling defect sized:** 73 items have R < 0.15 and A > 0.8 (structurally clean
  but semantically near-certain), capped at Medium by plain HTSA — **71 threats and
  2 legitimate** (was 35 items). These are the threats HTSA-E is designed to escalate.
- **Tier movement, HTSA-E vs HTSA γ=0.2 (926 items):** **112 threats** moved
  Medium → High/Critical, 24 further threats moved up a tier, and — importantly —
  **3 legitimate items now escalate** (was 0). With the larger, lower τ the benefit
  grows (112 vs 33 threats escalated) but it is **no longer cost-free**: a small
  number of legitimate items are escalated on held-out data, an honest
  generalisation gap in the train-derived threshold. At the 0.3 clearance line the
  binary metrics still match Condition 4 (HTSA-E acts at the Medium/High boundary).

## 4. Three independent lines of evidence on the gate

The gate's contribution is corroborated three ways. **Flip-zone algebra:** with
weights summing to 1, H = 0.8·mean(R,A) + 0.2·R·A ≤ mean(R,A) always, so the gate
can only ever *lower* a score, and it lowers most when the layers disagree — the
canonical worked case R = 0.18, A = 0.45 gives H = 0.315 (Medium, a false
positive) at γ = 0 and H = 0.268 (Low, correct) at γ = 0.2, the product term held
small by disagreement. **Gamma sweep:** on the hard-case set the count of
suppressed false positives rises monotonically with γ (1 at γ = 0.2, 6 at
γ = 0.25, 10 by γ = 0.45) while recall falls in step — the soft-AND tightening as
predicted, with the trade made explicit rather than hidden. **UNDP live
counter-example:** a real advance-fee fraud that is *not* structurally clean
(R = 0.5 from a Reply-To mismatch, A = 0.9) scores H = 0.65 High — the gate
correctly does **not** suppress when both layers agree, confirming it penalises
disagreement specifically, not magnitude.

## 5. Artefacts found and corrected

1. **DMARC applicability (email_auth).** The email-authentication indicator was
   made three-state (present/pass, present/fail, absent → not-applicable),
   removing a false-positive artefact where absent headers were scored as
   failures; precision up, FPR down.
2. **URL-length collection confound.** Legitimate URLs (Tranco) were bare ranked
   domains; phishing URLs (Phishing.Database) were full captured URLs, so the two
   classes differed in *shape* before any phishing signal — median URL length 19
   vs 74, path length 0 vs 30. A classifier separates on how the data was
   collected, not on phishing.
3. **RF 0.993 → 0.727.** The Random Forest rode that confound to F1 0.993 (top
   features `path_len`, `url_len`, `num_slash`). Stripping both classes to the
   registrable domain drops it to the honest F1 0.727 / AUC 0.767. The rule engine
   was checked against the same confound and does **not** ride it (its URL
   indicators fire on <5% of phishing and its WHOIS/brand checks are unaffected by
   stripping) — evidence the structural layer measures something real.
4. **Semantic abstention.** A bare URL has no analysable language, so A = null
   (abstain) rather than A = 0; scoring it 0 would have read "nothing to analyse"
   as "cleared". Symmetric on the rule side: R = null when no indicator applies.
5. **The path blind spot (new).** `https://kwasu.edu.ng/schooll-fee-payment` — a
   real, aged, certificated domain with a fabricated misspelled path — scores
   R = 0.000 and is cleared, because all nine indicators read the domain/host/
   headers and none reads the path. On the partial corpus **79 of 343 phishing
   URLs (23%) scored R = 0.000** — a measured structural false-negative
   population. This is a **boundary condition** of structural analysis, not a
   missed signal: when an attacker controls a path on a legitimate domain there is
   no structural evidence to find. The defect is that the system *asserted safety*
   ("cleared") where deny-by-default required "insufficient evidence." (Fix option
   analysed in `eval/NOTES.md`; not implemented — it invalidates cached R.)

## 6. NFR01 — latency (dedicated probe, 40 fresh cache-missing inputs)

Measured against the targets *rules < 2 s, full analysis < 15 s*, split by content
type because URLs skip the Gemini call entirely and lumping them understates the
mean. Source: `eval/out/nfr01_timings.txt`.

| type | n | rules mean / p95 | ai mean / p95 | total mean / p95 |
|---|--:|--:|--:|--:|
| URL   | 14 | **2649 / 6511 ms** | 0 / 0 ms (abstains) | 2649 / 6511 ms |
| email | 13 | 4 / 7 ms | 3173 / 4254 ms | 3177 / 4256 ms |
| text  | 13 | 0 / 0 ms | 3934 / 4997 ms | 3935 / 4997 ms |

- **Full-analysis target (< 15 s): met on every type** — worst-case total
  observed 6.6 s.
- **Rules target (< 2 s): met for email and text (0–4 ms) but NOT for URLs**
  (mean 2649 ms, p95 6511 ms). The rule layer's URL latency is dominated by live
  WHOIS + TLS network calls; the worst case is a dead domain whose WHOIS must time
  out. Reported straight — the sub-2-second rules target does not hold for URL
  submissions under this design, and that is an honest cost of live structural
  verification.
- **WHOIS indeterminate/unreachable: 3 of 14 URL probes** (includes both
  no-record and timeout; the deliberately-dead domains are the worst-case path an
  examiner will probe).

## 7. Operational note (one line for the write-up)

The Next.js dev server destabilised under sustained dead-domain WHOIS/TLS load
during the phishing-URL block, returning transient 404s for a stretch; those
failures were **never cached** (the degradation-guard and error-non-caching held),
so no result was corrupted, and the run is **resumable by design** — a repeated
pass re-scores only the uncached items.

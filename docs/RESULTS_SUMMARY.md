# Results summary — Chapter 4 source (PARTIAL)

> **STATUS: PARTIAL.** The full-corpus run attempted all **1,479** items but the
> Gemini free-tier rate limit degraded the semantic layer over the ~8.8-hour run
> (it fails soft to A=R, and those results are deliberately **not cached**), and
> the process exited during the final email block. What follows is computed from
> the **clean cache only** — items that genuinely scored, with real R and real A
> (or a genuine abstention), degraded and errored items excluded.
>
> **Clean n = 857 corpus items:** 724 URLs (381 legitimate / 343 phishing) and
> **133 emails (114 legitimate / only 19 phishing)**. The phishing-email class is
> the thinnest because Nazario emails ran last, when rate-limiting was heaviest —
> every email-dependent number below (Condition 2, the gate on emails) rests on
> small n and must be read as indicative, not final. The **hard-case corpus (100
> items, 50/50) is complete**, and the Random-Forest baseline (1,000 URLs) is
> complete. All numbers are marked FINAL only after a clean resumed run.
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
| 1 | Rule only (R) | 857 | 0.831 | 0.555 | 0.666 | 0.083 | 0.739 |
| 2 | AI only (A) — email only | 129 | 0.750 | 1.000 | 0.857 | 0.044 | 1.000 |
| 3 | HTSA, γ = 0 (ablation) | 857 | 0.833 | 0.580 | 0.684 | 0.085 | 0.754 |
| 4 | HTSA, γ = 0.2 (deployed) | 857 | 0.843 | 0.580 | 0.687 | 0.079 | 0.756 |
| 5 | Random Forest, domain-only | 1000 | 0.743 | 0.654 | 0.696 | 0.226 | 0.767 |
| 6 | HTSA-E (escalation) | 857 | = Condition 4 at t=0.3 (acts above the clearance line — see §3) |

Notes on reading this table:

- **Condition 1 (rule only)** has high precision (0.831) but low recall (0.555):
  the structural layer is trustworthy when it fires but misses a large fraction
  of threats, because modern phishing on clean infrastructure and all text-only
  social engineering are structurally innocent. This is the empirical motivation
  for the semantic layer, not an implementation shortfall (see NFR02 restatement
  in `eval/NOTES.md`).
- **Condition 2 (AI only)** is email-only by construction — the semantic layer
  abstains on bare URLs (A = null), so the 724 URL items contribute no A. Its
  n = 129 email items include only ~15–19 phishing emails; the AUC of 1.000 is an
  artefact of that tiny positive count and must not be reported as a headline. It
  will move on a resumed run.
- **Condition 5 (Random Forest)** is the domain-only (artefact-free) baseline:
  best-F1 0.727 at its optimal threshold. The inflated F1 = 0.993 obtained on
  full-URL lexical features is a **collection artefact**, not phishing signal (see
  §4). 0.727 is the honest baseline the hybrid is measured against.
- Conditions 3 and 4 are computed from the same cached R and A with no extra API
  calls, exactly as designed.

## 2. The agreement gate (γ = 0 → γ = 0.2), reported as counts

The gate only acts on items that carry **both** layers (emails; URLs abstain on
A, so H = R and the gate cannot move them). Two corpora, two outcomes — both
reported straight:

- **Main partial corpus (857 items).** False positives 42 → 39 (**−3 FP
  suppressed**); true positives 210 → 210 (**0 TP lost**); AUC 0.754 → 0.756.
  Precision 0.833 → 0.843, recall unchanged at 0.580. On the broad corpus the
  gate removes three false positives at no true-positive cost.
- **Hard-case corpus (100 items, complete).** False positives 10 → 9 (**−1 FP
  suppressed**); true positives 46 → 44 (**−2 TP lost**); precision 0.821 → 0.830,
  recall 0.920 → 0.880. On the adversarial borderline set the single suppressed
  false positive costs two true positives — a net-negative trade at this operating
  point. The one FP suppressed is a synthetic authored item.

Mean gate suppression |mean(R,A) − H| at γ = 0.2 is 0.024 (main) / 0.056
(hard-case); maximum 0.095. The flip-zone (0.25 ≤ mean(R,A) ≤ 0.40, where the
gate can cross the clearance line) holds 6 items (main) / 10 items (hard-case,
7 legitimate / 3 threat).

## 3. HTSA-E (Condition 6): escalation, tau, and tier movement

HTSA-E adds the disjunctive half of the Chapter-1 posture (either layer may
convict): H_e = max(H, A if A ≥ τ, R if R ≥ τ). Computed from cached R,A on the
combined 632 dual-corpus items (545 legitimate / 87 threat).

- **τ = 0.910**, derived — not hand-picked — as the lowest value at which **no
  legitimate training item escalates**, i.e. just above the highest legitimate
  escalation score. On a 60/40 split the legitimate ceiling is 0.90.
- **Legitimate ceilings, reported separately:** A-arm ceiling **0.90**, R-arm
  ceiling **0.588**. τ = 0.91 clears both, so no legitimate item escalates. The
  ceiling is set by the A-arm — a **synthetic authored** security-urgency
  legitimate item (A = 0.90) — so τ is currently anchored to authored data; state
  this, and expect movement on a resumed run.
- **Ceiling defect sized:** 35 items have R < 0.15 and A > 0.8 (structurally clean
  but semantically near-certain), capped at Medium by plain HTSA — 33 threats and
  2 legitimate. These are the threats HTSA-E is designed to escalate.
- **Tier movement, HTSA-E vs HTSA γ=0.2 (632 items):** 33 threats moved
  Medium → High/Critical, 4 further threats moved up a tier, and **0 legitimate
  items escalated**. At the clearance threshold of 0.3 the binary metrics are
  identical to Condition 4, because HTSA-E acts at the Medium/High boundary, above
  the clearance line — its effect is a tier change, not a clearance flip.

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

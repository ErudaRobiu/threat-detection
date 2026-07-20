# Evaluation notes (read before building the Phase 5 harness)

## Corpora (for the Chapter 3 revision — source, URL, date, size, balance)

All obtained **2026-07-14**. Raw data lives in `eval/data/` (gitignored;
reproduce with `eval/fetch_corpora.sh`). Totals: **1,000 URLs (500/500)** and
**600 emails (300/300)** = 1,600 items.

| Class | Source | URL | Obtained from | Sample |
|---|---|---|---|---|
| Legitimate URLs | **Tranco** research ranking | https://tranco-list.eu/ (`top-1m.csv.zip`) | full list | top **500** ranked domains → `https://` |
| Phishing URLs | **Phishing.Database** (mitchellkrogza) | https://github.com/mitchellkrogza/Phishing.Database (`phishing-links-ACTIVE.txt`) | 161,929 active URLs | random **500** (seed 42) |
| Phishing emails | **Nazario** phishing corpus | https://monkey.org/~jose/phishing/ (`phishing3.mbox`) | 2,279 messages | **300** (seeded) |
| Legitimate emails | **SpamAssassin** public corpus, `easy_ham` | https://spamassassin.apache.org/old/publiccorpus/ (`20030228_easy_ham.tar.bz2` + `_2`) | 3,900 messages | **300** (seeded) |

**Two substitutions, each defensible and each one sentence in Chapter 3:**

1. **PhishTank → Phishing.Database.** PhishTank's `online-valid.csv` feed returned
   an HTTP-200 rate-limit page ("you have exceeded the request rate limit")
   without a registered API key, and registration has been intermittently closed.
   Rather than block on a registration email, the phishing-URL class was drawn
   from the Phishing.Database aggregated feed, which itself ingests PhishTank and
   OpenPhish and is freely downloadable and citable.

2. **Enron → SpamAssassin easy_ham.** The CMU Enron tarball (1.7 GB) downloaded at
   ~215 KB/s here (≈2 hours), exceeding the 20-minute sourcing time-box. The
   SpamAssassin `easy_ham` corpus is a standard, citable legitimate-email dataset
   and was used for the legitimate-email class instead.

Class balance is exact: URLs 500/500, emails 300/300.

---

## Chapter 4 methodological finding: the URL corpus is trivially separable by a COLLECTION ARTEFACT (and the corpus fix)

**This is a Chapter 4 finding in its own right, not a footnote.** A benchmark that
separates on how the two classes were *collected* rather than on what distinguishes
phishing is a benchmark that flatters every classifier trained on it.

The legitimate URL class (Tranco) is **bare ranked registrable domains**
(`https://google.com`); the phishing class (Phishing.Database) is **full captured
URLs** (`https://budi01.grubwa.duckdns.org/tem/onedrive-4d1/p`). The two classes
therefore differ in *shape* before any phishing signal is considered:

### Table A — URL shape by class, as collected (goes in the report verbatim)

| class | n | median URL len | median path len | mean subdomain depth | >3 depth | IP-host | shortener |
|---|---|---|---|---|---|---|---|
| legit | 500 | 19 | 0  | 0.00 | 0.0% | 0.0% | 0.8% |
| phish | 500 | 74 | 30 | 0.62 | 1.6% | 4.4% | 0.0% |

subdomain_depth histogram (full URL):
- legit: `{0: 500}` — every legit URL is a bare domain, depth 0 by construction.
- phish: `{0:268, 1:189, 2:22, 3:13, 4:3, 5:3, 6:1, 7:1}`.

### Does the RF ride it? Yes, almost entirely. (Condition 5, three rows)

`baseline.py`, RF, 1,000 URLs, 5-fold stratified CV, out-of-fold preds, seed 42:

| row | RF input | acc | prec | rec | F1 | FPR | AUC | best-F1 |
|---|---|---|---|---|---|---|---|---|
| **5a** | all lexical features (ARTEFACT) | 0.993 | 0.998 | 0.988 | **0.993** | 0.002 | 0.999 | 0.994 |
| **5b** | length/path features removed    | 0.967 | 0.979 | 0.954 | 0.967 | 0.020 | 0.986 | 0.968 |
| **5c** | **domain-only (HEADLINE)**       | 0.714 | 0.743 | 0.654 | **0.696** | 0.226 | 0.767 | 0.727 |

5a's top features are `path_len`, `url_len`, `num_slash` — it has learned *"long URL
with a path ⇒ phishing"*, i.e. the collection artefact, not phishing. Strip every URL
to its registrable domain (5c) and the RF falls to **F1 0.696 / AUC 0.767** — the
honest baseline the hybrid is measured against. 5c's surviving signal is real but
modest: `host_entropy`, `tld_len`, `digit_ratio`, `has_brand_token` — phishing domains
are more random-looking, use odder TLDs and more digits. **The Condition-5 headline
number is 5c (best-F1 0.727), not 0.99.** 5a/5b are the diagnostic trail.

### Does the RULE ENGINE ride it? No — this was the real worry, and it is clean.

Checked offline (`eval/confound_check.py`, mirrors `rules.ts`/`preprocess.ts` exactly)
for the three indicators that read URL shape:

- `subdomain_depth` (>3 fails): legit 0.0% vs phish **1.6%** — a 1.6-point gap. The
  indicator barely fires on full URLs at all; it is not a material driver of R.
  After stripping both classes to registrable domain the gap is 0.0 points.
- `url_ip_address`: legit 0.0% vs phish 4.4%. Genuine signal (raw-IP hosts), not a
  length artefact; preserved under stripping.
- `url_shortener`: legit 0.8% vs phish 0.0%. Negligible either way.
- `domain_age` (WHOIS) already operates on the **registrable domain**
  (`preprocess.ts:192`), so it is *unaffected* by stripping the path/subdomain.
- `brand_similarity` reads the **SLD label**, unchanged by stripping — not a shape
  artefact.

**Conclusion: the rule engine does not ride the collection artefact.** Its URL
indicators encode semantic structure (raw-IP host, typosquat brand distance, young
WHOIS, invalid TLS), not raw length, so R's discriminative power on URLs comes from
signal the stripping preserves. The RF was fooled; R substantially is not. That
contrast is itself a Chapter 4 point: it is evidence the structural layer measures
something real rather than a dataset shortcut.

### The corpus fix: option (a), strip BOTH classes to registrable domain.

Chosen over (b) re-sourcing full legit URLs. **(a) loses no items to sourcing/dead
links and the confound check proves it costs the rule engine almost nothing** (shape
indicators fire on <5% of phishing; WHOIS/brand are unaffected). (b) would add path
noise and cost sourcing time. Implementation: `eval/normalise_urls.py` writes
`data/urls_{legit,phish}_domain.txt` as bare `https://<registrable-domain>`; the
full run uses `run.py --url-mode domain` (default). `--url-mode raw` reproduces the
artefact-laden corpus so Chapter 4 can show Condition 1 both ways.

**Sub-decisions (flagged for confirmation — reversible; raw files untouched):**
- **Dedup to unique registrable domains per class**, to avoid double-counting the
  109 phishing URLs that share a host (e.g. 19× `000webhostapp.com`). Without dedup,
  those shared-infra R≈0 items would be counted up to 19× each and would inflate the
  rule layer's apparent false-negative rate — a subtle fabrication. Result: legit 500
  unique, phish **391** unique. Slight imbalance, reported per-class (precision/recall
  separately, per the reporting rule) not as F1 alone.
- **Drop the 6 registrable domains that appear in BOTH classes** (`amazonaws.com`,
  `azure.com`, `blogspot.com`, `duckdns.org`, `github.io`, `pages.dev`) — after
  stripping they are ambiguous labels (a shared host is neither inherently phish nor
  legit). 6/500 = 1.2% removed from each side.
- 14.6% of phishing stripped onto shared-hosting/dynamic-DNS registrable domains that
  are themselves legitimate infrastructure (R≈0). These are kept as the honest
  "phishing on legitimate infrastructure" hard case — the empirical argument for the
  semantic layer, exactly as the smoke found.

---

## Chapter 4 finding (standalone): hand-designed indicators beat naive lexical ML *because* they encode semantics, not string shape

This is a result in its own right, not a caveat on the baseline.

The same collection artefact that inflates the RF to F1 0.993 (5a) leaves the rule
engine essentially unaffected. That asymmetry is the point:

- **The Random Forest is fooled by URL *shape*.** Its discriminative power comes from
  `path_len`, `url_len`, `num_slash` — it learned that the phishing class was collected
  as full captured URLs and the legit class as bare domains. Remove that shape signal
  (5c, domain-only) and it falls to F1 0.696 / AUC 0.767. The model had no concept of
  *why* a URL is dangerous; it keyed on an incidental property of how the corpus was
  assembled.

- **The rule engine is not**, because every URL indicator encodes a *semantic* claim
  about phishing, not a string statistic: a raw-IP host bypasses domain reputation; a
  registrable domain within Levenshtein distance ≤2 of a brand (after homoglyph folding)
  is typosquatting; a WHOIS age under 30 days is disposable infrastructure; an invalid
  TLS certificate is an unverified endpoint. None of these is a function of URL length,
  so stripping the artefact leaves them intact (confirmed offline in `confound_check.py`:
  subdomain_depth's class gap is 1.6 points and vanishes on normalisation; WHOIS and
  brand read the registrable domain / SLD, untouched by shape).

**The argument this supports:** a naive lexical classifier trained end-to-end will
absorb whatever separates the classes in the training data, including dataset
artefacts, and its headline metric can be almost entirely artefact. Hand-designed
indicators grounded in the mechanism of the attack cannot ride an artefact they were
never given, so their (lower) numbers are a truer estimate of real-world power. On
this corpus the honest gap is F1 0.727 (RF, 5c) versus what the rule/hybrid conditions
reach on the artefact-free `--url-mode domain` corpus (full run) — reported like for
like. The methodological lesson (benchmark separable by artefact; feature engineering
robust to it; end-to-end ML not) is worth more to Chapter 4 than the raw baseline number.

---

## Chapter 3 refinement: email_auth applicability (the DMARC artefact)

On this corpus **0/3900 SpamAssassin ham** and **2/2138 Nazario phishing** emails
carry any `Authentication-Results` / `Received-SPF` header (both predate wide
DMARC deployment). Under the original rule, `email_auth` therefore *failed* on
~100% of both classes: zero discriminative power, and a uniform −0.12 penalty to
every legitimate email's earned weight.

Fix (a refinement, not a reweight): `email_auth` is now **inapplicable** when a
message carries no SPF/DKIM/DMARC result at all — the same three-state logic as
WHOIS (present+pass → pass; present+fail → fail; absent → n/a). The applicability
normalisation renormalises R over the indicators that remain. The fixed weight
set the ablation depends on is untouched.

## Chapter 3 refinement: NFR02 (rule-only F1) restated  [ROBIU'S CLAIM TO FINALISE]

> Drafted by the assistant at my instruction; the wording and the decision to
> adopt it are mine to finalise, not the assistant's.

NFR02 as originally written implies every evaluated condition should reach
F1 > 0.94. That is a category error and is restated as follows.

- **F1 > 0.94 is a target for the HYBRID SYSTEM (the deliverable), not for the
  standalone conditions.** The rule-only and AI-only conditions are diagnostic
  baselines that isolate each layer's contribution. They are *expected* to
  underperform the hybrid, and their individual ceilings quantify the limitation
  each layer imposes and the other corrects. Measuring them against the hybrid's
  target is measuring a component against the whole.

- **The rule layer's recall is bounded above by the proportion of threats that
  are *structurally* detectable.** Modern phishing hosted on legitimate
  infrastructure (github.io, square.site, shared hosts) with valid certificates
  and no typosquat, and text-only social engineering carrying no URL or headers
  at all, are by construction structurally innocent (R ≈ 0). No weighting of
  structural indicators can catch input that has nothing structurally wrong with
  it. This is not an implementation shortfall against NFR02 — it is the empirical
  motivation for the semantic layer. If structural analysis alone reached 0.94,
  the hybrid would be unmotivated. **The rule layer's ceiling is the argument for
  fusion.**

**Reporting rule (applies to the whole harness):** report precision and recall
**separately** everywhere, never F1 alone. The DMARC fix raised rule precision
but lowered recall; that trade-off is invisible if only F1 is shown.

## Findings from the 48-item smoke (real data, for Chapters 4/5)

**The two failure modes are mirror images — this is the argument for fusion.**

1. **Phishing on legitimate shared infrastructure defeats the rule layer.** Many
   phishing URLs are hosted on `000webhostapp.com`, `*.github.io`, `square.site`,
   etc. — established domains with valid TLS that are not brand typosquats — so
   every structural indicator passes and **R ≈ 0**. The rule layer clears them;
   only the AI (on a full email) or a human catches them. On bare URLs the AI
   abstains, so these are a genuine hard case (Chapter 5 limitation).

2. **Legitimate mail that fails structural checks produces rule-layer false
   positives.** Text-only Nazario phishing with no URL and no auth headers also
   scores **R = 0** and is caught only by **A ≈ 0.95** — the inverse: the rule
   layer misses it, the semantic layer nails it.

Each layer rescues the other's blind spot. Neither alone is sufficient; that is
the case for the hybrid, and it fell out of real data rather than theory.

**Honest caveat on the agreement gate (smoke, n=48).** γ=0 and γ=0.2 gave
identical binary metrics AND identical best-F1 under a full threshold sweep
(0.818 either way), and equal AUC (0.825). Mean gate suppression 0.044, max
0.095; only **2/24** email items fell in the 0.25–0.40 flip zone. The gate
demonstrably *suppresses* (mean 0.044) but did not change any classification on
this sample. Whether it shows a measurable effect at 1,600 items is the open
question the full run must answer — reported honestly either way.

---

## Semantic abstention changes what "AI-only" (Condition 2) can be measured on

The AI layer abstains (returns A = null) when a submission carries no analysable
language after redaction — i.e. `hasAnalysableLanguage(redactedText)` is false
(fewer than `MIN_ANALYSABLE_CHARS` = 15 alphanumeric characters once `[LINK]` /
`[EMAIL]` tokens and punctuation are stripped). See `core/analyze.ts` and
`core/htsa.ts`.

This is correct behaviour, but it has a hard consequence for the evaluation:

- **A large fraction of the 1,000-URL corpus will trigger AI abstention.** A bare
  URL redacts to `[LINK]`, which has zero analysable characters, so A = null.
- For those items, **Condition 2 (AI-only, A thresholded at 0.3) is UNDEFINED.**
  There is no A to threshold.

### DO NOT score abstained items as A = 0

Scoring an abstained URL as A = 0 would classify every phishing URL as
"AI says safe", manufacturing a perfect false-negative rate for the AI arm and
making the hybrid look better than it is by comparison. That is fabricated data.

### What to actually do

- **Report Condition 2 (AI-only) on the EMAIL corpus only** (600 items: 300
  Nazario phishing + 300 Enron legitimate), where every item has body language
  and A is defined. State this scoping explicitly in Chapter 4.
- Conditions 1, 3, 4, 5 (rule-only, HTSA γ=0, HTSA γ=0.2, RF baseline) are
  reported on the full 1,600-item set as planned.
- Record the abstention rate on the URL corpus as a result in its own right — it
  quantifies how often language-based detection has nothing to work with, which
  is itself part of the argument for the hybrid.

The R and A values are cached independently per item, so Conditions 3 and 4 are
still computed from the cache with no extra API calls, as designed.

---

## Worked examples to preserve for Chapter 4 (the agreement gate on live cases)

These are real system outputs, not illustrations. They are the strongest
demonstrations that the two layers are independent and that the gate does real
work. Do not let them get tidied away because they made an inconvenient demo.

### 1. Genuine GitHub security notification — the gate rescuing a real message

A correctly-authenticated GitHub notification the blind semantic layer reads as
coercive, rescued only by the clean structural layer. Measured (build-demo run):

```
From: GitHub <noreply@github.com>
Reply-To: noreply@github.com
Subject: [GitHub] A new SSH key was added to your account
Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass

Hi, a new SSH key was added to your account. If this was you, there is nothing
else you need to do. If you did not add this key, you can remove it from your
account settings at https://github.com/settings/keys or contact our support team.
```

  R = 0.000   (clean: SPF/DKIM/DMARC pass, github.com established, valid TLS, no shortener)
  A = 0.700   (the blind AI reads "new SSH key added… remove it" as a compromise lure)
  H = 0.4(0.000) + 0.4(0.700) + 0.2(0.000×0.700) = 0.280  ->  LOW

A = 0.700 alone would classify HIGH (blocked). The gate + clean R pull H to 0.280,
below the 0.3 clearance threshold. This is the false-positive suppression on a
genuine message from a real company. (It was cut from the DEMO set only because a
"legitimate email" example should read as unambiguously clean; here A is the point.)

### 2 & 3. Genuine urgent, action-demanding messages (calibration items 9, 10)

Measured A (AI-only calibration probe, temperature 0):

  Item 9  bank fraud alert that DEMANDS action   A = 0.78
  Item 10 payroll deadline that DEMANDS action   A = 0.72

The A is measured. The fused H depends on how the message arrives, and both
framings are worth stating:

- As an authenticated email with clean structure (no URL, SPF/DKIM/DMARC pass):
  R = 0.000, so H = 0.4·A. Item 9 -> H = 0.312 (Medium); item 10 -> H = 0.288 (Low).
  The gate keeps a legitimate urgent message OUT of High/Critical (blocked); at
  A ≈ 0.72–0.78 it cannot clear it fully, which is the correct deny-by-default
  outcome: flag for review, do not block.
- As a bare text SMS with no verifiable structure: rules abstain (R = null), so
  H = A (High). A genuine urgent message with no structure to vouch for it IS
  flagged — a real limitation of any structure-dependent layer, and honest to state.

Item 9 text:
```
Subject: Suspicious transaction blocked — action required
We blocked a transaction of N85,000 on your account. If this was not you, call us
immediately on the number on the back of your card. Your account has been frozen
and will remain restricted until you confirm this activity. For your protection,
do not share your PIN or password with anyone.
```

Item 10 text:
```
Subject: Payroll cutoff is 5pm TODAY
Reminder: the payroll cutoff is 5pm TODAY. If your timesheet is not submitted by
then, you will not be paid this month. There are no exceptions. Submit your
timesheet now at: https://hr.internal.example.com/timesheet
```

These three occupy the high-A / low-R corner where `|R − A|` is largest, so they
are also the peak-suppression points on the gate-suppression-vs-|R−A| scatter.

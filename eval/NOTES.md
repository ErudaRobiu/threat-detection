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

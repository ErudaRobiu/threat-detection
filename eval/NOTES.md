# Evaluation notes (read before building the Phase 5 harness)

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

# CLAUDE.md

## Project: Threat Detection System

This is a final-year Computer Science project. The written report (Chapters One to Three) is already submitted and defines the system. Your job is to build the system that report describes, and to produce the artefacts needed to write Chapters Four and Five.

The report is the specification. Where this document and your instincts disagree, this document wins.

---

# STOP. READ THIS FIRST.

## Mandatory intake

**Do not write any code until you have asked me the questions below and I have answered them.** Ask them all at once, in a single message, numbered. Do not guess, do not assume defaults, do not "make a reasonable choice and note it". Ask.

1. **Gemini API key.** Do I have one? Is it already in `.env.local`? Which model should we target?
2. **Database.** Am I setting up Turso now, or building against local SQLite first and migrating later?
3. **Repo.** Fresh directory, or is there existing scaffolding? Confirm the working directory before you touch anything.
4. **Package manager.** npm, pnpm, or bun?
5. **Deployment.** Deploy to Vercel as we go, or build entirely locally and deploy once at the end?
6. **Scope confirmations.** Confirm each of these is in or out for v1:
   - Settings page with adjustable HTSA weights
   - Analysis history page with chart
   - Screenshot/image upload as an input type
   - `DEMO_MODE` with cached example results
7. **Anything in `/core` already?** If `types.ts`, `htsa.ts` or `rules.ts` are present, read them before proposing anything. They are authoritative.

## Approval gates

Work in the phases listed at the bottom of this document. **At the end of each phase, stop. Show me what you built. Wait for my approval before starting the next phase.** Do not run ahead. Do not batch two phases together because they seem small.

Within a phase, if you hit a decision I have not specified, ask. Do not decide for me and flag it afterwards.

## Never do these

- Never invent evaluation results, metrics, or accuracy numbers. Ever.
- Never write to the report chapters. Those are mine.
- Never use `localStorage` or `sessionStorage`.
- Never add a dependency without telling me what it is and why.
- Never refactor code I have not asked you to touch.

---

# THE SYSTEM

## In one sentence

A web application where a user pastes a suspicious email, URL, or text message, and receives a threat verdict produced by fusing a rule-based structural analysis with an AI semantic analysis, under a security posture in which all content is treated as dangerous until it proves itself safe.

## Architecture

**One Next.js application.** Not a separate frontend and backend. Server-side API routes host the entire analysis core; a client-side React layer renders the interface. There is no FastAPI service. There is no second runtime.

The analysis core is five modules executing in sequence:

```
raw input
   -> preprocess    parse email, extract URLs, resolve WHOIS + TLS
   -> rules         nine weighted indicators  -> R
   -> ai            one Gemini call           -> A
   -> htsa          fuse                      -> H, classification
   -> report        render
```

Separately, and **not part of the deployed application**, a Python evaluation harness drives the deployed API against benchmark corpora and produces the metrics for Chapter Four. It lives in `/eval` and is never deployed.

## File layout

```
/app
  page.tsx                    submission form + threat report
  history/page.tsx            past analyses + chart
  settings/page.tsx           HTSA weight sliders
  /api/analyze/route.ts       the only endpoint that matters
  /api/history/route.ts
/core
  types.ts                    THE CONTRACT. Everything speaks this shape.
  preprocess.ts               raw input -> Features
  rules.ts                    Features -> R
  ai.ts                       text -> A + patterns + explanation
  htsa.ts                     (R, A) -> H + classification
/lib
  db.ts
/eval                         Python. Never deployed. Phase 5.
  run.py
  cache.json
  baseline.py
  charts.py
  /data
```

`core/types.ts`, `core/htsa.ts` and `core/rules.ts` may already be present. **If they are, read them first and build around them.** They are the specification, not a suggestion, and they encode two corrections that took real effort to find. Do not rewrite them without asking.

---

# THE THREE THINGS YOU MUST GET RIGHT

Everything else is ordinary web development. These three are the project.

## 1. Deny by default

Every submission starts at **maximum threat** and earns reductions by passing checks. It does not start at zero and accumulate penalties. This inversion is the thesis of the project.

**Consequence: an indeterminate check counts as a FAILURE.**

If a WHOIS lookup returns no record, that is a fail. If a TLS handshake cannot be established because the host is offline, that is a fail. Not an error. Not an exclusion. Not a skip.

This is deliberate and it must not be "fixed". Phishing infrastructure is routinely withdrawn after a campaign, and WHOIS privacy is routinely used to hide registration dates. An adversary who destroys the evidence must not obtain a lower threat score than one who leaves it intact. **The absence of verification is not verification.**

You will be tempted to treat these as errors and skip them. Do not.

## 2. The rule score must be normalised over APPLICABLE indicators

There are nine indicators. Not all apply to every submission.

- Six require a URL: domain age, TLS certificate, IP-in-URL, brand similarity, subdomain depth, URL shortener.
- Three require email headers: SPF/DKIM/DMARC, reply-to mismatch, credential form in body.

The naive formula `R = 1 - SUM(w * pass)` over all nine is **broken**. On a bare URL submission, the three email indicators can never pass, so their weight is never earned back, so R has a floor. **It classifies `google.com` as Medium Risk.**

The correct formula normalises over the applicable set:

```
R = 1 - [ SUM(w_i * pass_i) over applicable i ]
        / [ SUM(w_i)         over applicable i ]
```

**Abstention.** A plain text message with no URLs and no headers has an empty applicable set. The denominator is zero. In this case the rule engine **abstains** and returns `R = null`. HTSA then reduces to `H = A`. Do not substitute 1.0 (that flags every text message as maximum threat) and do not substitute 0.0 (that clears them all). Both are fabrications.

## 3. The HTSA interaction term is an AGREEMENT GATE, not an amplifier

```
H = (alpha * R) + (beta * A) + (gamma * R * A)
    alpha = 0.4, beta = 0.4, gamma = 0.2, summing to 1
```

**Do not write a comment saying this "amplifies" the score when both layers agree.** That is false, and the original report said it, and it was wrong.

Because the weights sum to 1, the formula is equivalent to:

```
H = 0.8 * mean(R, A) + 0.2 * (R * A)
```

and since `R * A <= mean(R, A)` for all values in [0,1], **H is always less than or equal to the simple average**. It never amplifies. It **penalises disagreement**. It is a soft AND.

Its purpose is false-positive suppression. Worked example, which must remain true after any change you make:

```
Legitimate marketing email: clean domain, valid TLS, SPF passes,
but uses a link shortener and says "act now, expires in 24 hours".

  R = 0.18   (structurally clean)
  A = 0.45   (the AI sees urgency language and gets nervous)

  gamma = 0.0  ->  H = 0.315  ->  MEDIUM RISK.  FALSE POSITIVE.
  gamma = 0.2  ->  H = 0.268  ->  LOW RISK.     CORRECT.
```

The layers disagreed, the product term stayed small, the score was held below the 0.3 clearance threshold. That is the contribution of this project in four lines.

The ablation configuration is `alpha = 0.5, beta = 0.5, gamma = 0.0`. Note that alpha and beta are **0.5, not 0.4**. Removing gamma without redistributing its weight would cap H at 0.8 and make the two conditions incomparable against the same thresholds.

---

# SPECIFICATIONS

## The nine indicators

| Indicator | Weight | Fails when | Applicable to |
|---|---|---|---|
| Domain age | 0.15 | Registered under 30 days ago, **or WHOIS indeterminate** | Any submission with a URL |
| TLS certificate | 0.10 | Missing, expired, self-signed, **or host unreachable** | Any submission with a URL |
| IP address in URL | 0.12 | Host is a raw IP rather than a domain | Any submission with a URL |
| Brand similarity | 0.15 | Domain resembles a known brand without being it | Any submission with a URL |
| Subdomain depth | 0.08 | More than 3 levels of nesting | Any submission with a URL |
| Email authentication | 0.12 | SPF fails or is absent, or neither DKIM nor DMARC passes | Email only |
| Reply-to mismatch | 0.10 | Reply-to domain differs from sender domain | Email only |
| Credential form in body | 0.10 | Body contains form with password or credential input | Email only |
| URL shortener | 0.08 | A known shortening service is used | Any submission with a URL |

Weights sum to 1.000 across the full set.

**Brand similarity is the one with real logic in it.** Three stages:

1. If the registrable domain IS an official brand domain, pass.
2. Otherwise tokenise the second-level label on `[-_.]`, apply **homoglyph normalisation** (fold `0`→`o`, `1`→`l`, `3`→`e`, `5`→`s`, `@`→`a`, and so on), and compare each token against each brand name by **Levenshtein distance**.
3. Distance 0 after normalisation means the token IS the brand name in a domain that is not the brand's. Distance 1 or 2 means typosquatting. Either fails.

Homoglyph normalisation is not optional. `paypa1-verify.com` has raw distance 1 from `paypal`. After normalisation it is distance 0, correctly identified as exact brand-name impersonation. Same mechanism catches `g00gle`, `micr0soft`, `netf1ix`.

## The AI module

**One Gemini call per submission.** Not two. Not a chain.

- `temperature: 0` for reproducibility
- Constrained JSON response schema, so the model cannot return prose
- Cache every response keyed by SHA-256 of the content. The evaluation depends on this.

The schema must require three fields:

```
confidence:   number in [0, 1]
patterns:     array of { id, label, evidence }
explanation:  string, plain English, written for a non-technical reader
```

The six pattern categories are fixed: `urgency_manipulation`, `authority_impersonation`, `emotional_exploitation`, `credential_harvesting`, `financial_manipulation`, `action_coercion`.

**The `evidence` field is not optional and not decorative.** It must be the exact span quoted verbatim from the submitted content that effects the manipulation. Not a paraphrase, not a summary. This is what the threat report renders, and it is the single most convincing element of the demonstration: showing a user the literal sentence "verify within 24 hours or your account will be permanently suspended" and naming it as manufactured urgency. Enforce it in the prompt and validate it in the parser.

## Graceful degradation

The AI module depends on an external service. Wrap the call. If it fails for any reason (network, rate limit, service down), substitute `A = R`, complete the fusion, set `aiAvailable: false`, and return a result annotated accordingly. The UI shows a notice. **The system must remain usable with no internet.**

## The threat report UI

Five blocks, in this order:

1. **Verdict.** Classification and recommended action. Large, colour-coded.
2. **Score decomposition.** R, A, H, and the substituted equation rendered verbatim:
   ```
   H = 0.4(0.800) + 0.4(0.940) + 0.2(0.800 x 0.940) = 0.846
   ```
   This is the most important component in the entire interface. It is where the algorithm becomes visible. Do not hide it behind a disclosure toggle. Do not simplify it. Print the real numbers.
3. **Indicator table.** All nine. Pass, fail, or **not applicable, shown greyed with the weight struck through**. Do not hide the inapplicable ones. Their visibility is what makes the applicability normalisation legible to a reader.
4. **Detected patterns.** Each with its quoted evidence span.
5. **Explanation.** The AI's plain-English paragraph.

## DEMO_MODE

An env flag. When set, `/api/analyze` checks the content hash against a bundled JSON of pre-analysed examples and returns instantly with no network call. Preload five:

1. Obvious phishing email
2. Legitimate email
3. Typosquatted URL
4. Clean URL
5. **The borderline marketing email showing the agreement gate suppressing a false positive**

This exists because the project is defended live in a room where the power and the network are both unreliable. It is not a nice-to-have.

## Non-functional targets

| | Target |
|---|---|
| Rule-based analysis | under 2 seconds |
| Full analysis including AI | under 15 seconds |
| API keys | environment variables only, never in code, never client-side |
| Responsive | must work at mobile width |
| Timings | record and return `{ rules, ai, total }` in ms on every response |

---

# BUILD PHASES

Stop at the end of each. Wait for approval.

### Phase 0: Intake
Ask the intake questions. Confirm the working directory. Read anything already in `/core`. Propose the dependency list. **Stop.**

### Phase 1: Core engine
`types.ts`, `htsa.ts`, `rules.ts`, and a test file.

No API key needed. No network needed. Pure functions only.

The test file must include these cases, and they must pass:
- Phishing email, all nine applicable, R = 0.800, H = 0.846 with A = 0.94, Critical
- `google.com`, six applicable, R = 0.000, Low
- **The same `google.com` input under the un-normalised formula, showing R = 0.320 and a Medium Risk misclassification.** This case documents the defect. Keep it.
- Plain text, no URL, no headers: abstention, R = null, H = A
- `paypa1-verify.com` detected as impersonating `paypal` at normalised distance 0
- `microsotf.com` detected as impersonating `microsoft` at distance 2
- R = 0.18, A = 0.45 under gamma = 0.0 → 0.315 Medium
- R = 0.18, A = 0.45 under gamma = 0.2 → 0.268 Low

**Stop.** Show me the passing output.

### Phase 2: Preprocess and AI
`preprocess.ts` (email parsing, URL extraction, WHOIS, TLS) and `ai.ts` (the Gemini call).

Show me the exact prompt text before you finalise it. I need it for the report.

**Stop.**

### Phase 3: API and UI
`/api/analyze`, the submission form, the threat report. Graceful degradation. DEMO_MODE.

**Stop.**

### Phase 4: Database, history, settings
Turso, the history page with its chart, the settings page with the weight sliders.

The settings page has a second purpose: dragging gamma to zero on a borderline submission and watching the classification flip is a live demonstration of the ablation. Make sure that works.

**Stop.**

### Phase 5: Evaluation harness
Python. In `/eval`. Never deployed.

It drives `POST /api/analyze` against the corpora, caches every response by content hash, and computes metrics for five conditions:

1. Rule only (R thresholded at 0.3)
2. AI only (A thresholded at 0.3)
3. HTSA with gamma = 0 (the ablation)
4. HTSA with gamma = 0.2 (the real system)
5. Random Forest on lexical URL features (scikit-learn, the ML baseline)

Corpora: 1,000 URLs (500 PhishTank phishing, 500 Tranco legitimate) and 600 emails (300 Nazario phishing, 300 Enron legitimate). 1,600 items total.

Because R and A are stored independently per item, conditions 3 and 4 are computed from the cache with no additional API calls.

Charts required: grouped bar of the four metrics across five conditions; confusion matrices; and a scatter of gate suppression against `|R - A|` across the test set, which visualises the agreement gate doing its job.

**Throttle to stay under the free-tier rate limit. Cache aggressively. This run takes days, not minutes.**

**Stop.**

### Phase 6: Deploy and harden
Vercel. Turso in production. Verify DEMO_MODE works with the network disabled.

---

# TONE

I am a working web developer. Do not explain what a React component is. Do not pad. If something I have specified is wrong, say so directly and tell me why.

If you find yourself about to write "I'll assume...", stop and ask instead.

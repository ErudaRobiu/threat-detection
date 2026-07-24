# CHAPTER FOUR

# SYSTEM IMPLEMENTATION AND RESULTS

## 4.1 Introduction

This chapter presents the outcome of translating the design set out in Chapter Three into a working system, and the results of evaluating that system against the research questions. It describes the development environment, the implementation of each module in the analysis core, the database layer, and the user interfaces, before reporting the testing regime and the performance evaluation. The account is deliberately candid about the points at which implementation and measurement revised the assumptions carried into the project, because those revisions form part of the contribution. In particular, formal analysis conducted during implementation established that the interaction term at the heart of the Hybrid Threat Scoring Algorithm behaves in the opposite manner to the one assumed in Chapter Three, and the evaluation that followed produced a mixed rather than a uniformly positive picture of that term. Both findings are reported in full.

Two matters of scope should be stated at the outset. First, the architecture described in Chapter Three separated a Next.js presentation layer from a Python (FastAPI) backend. During implementation this separation was consolidated into a single Next.js application whose server-side API routes host the entire analysis core in TypeScript, removing the second runtime while preserving the logical three-tier structure. The Python component was retained only for the evaluation harness, which drives the deployed system from outside and is never itself deployed. Second, the evaluation reported here was truncated for time before the full corpus completed, so the detection results rest on 857 scored items rather than the full planned set. This is stated wherever the affected figures appear, and again among the limitations in Chapter Five.

## 4.2 Development Environment and Tools

This section records the hardware and software environment in which the system was developed, tested, and evaluated. The values in Table 4.1 were read from the development machine and should be confirmed by the author before submission.

**Table 4.1: Development Environment**

| Component | Specification |
|---|---|
| Processor | Apple M1 Pro, 10 cores [INSERT: confirm] |
| Memory | 16 GB [INSERT: confirm] |
| Operating system | macOS 26.2, build 25C56 [INSERT: confirm] |
| Architecture | arm64 |
| Application runtime | Node.js v25.9.0 |
| Evaluation runtime | Python 3.9.6 |
| Language (application) | TypeScript |
| Language (evaluation harness) | Python |
| Large Language Model | Google Gemini (`gemini-2.5-flash`) |

The application was built with Next.js and React, with the analysis core written as pure TypeScript modules so that it could be unit tested without a network connection or a running server. Styling was implemented in hand-written CSS rather than a utility framework. The evaluation harness was written in the Python standard library with the addition of scikit-learn for the machine-learning baseline and matplotlib for chart generation. Version control was managed with Git.

## 4.3 System Implementation

This section describes the implementation of the five modules that make up the analysis core, in the order in which a submission passes through them: preprocessing, rule-based scoring, semantic analysis, hybrid fusion, and graceful degradation. Each submission is processed by the sequence preprocess, rules, ai, htsa, report, and each module communicates through a single shared type contract so that the layers remain independent. Real excerpts from the implementation are presented as numbered figures.

### 4.3.1 Content Ingestion and Preprocessing

The preprocessing module converts raw input into a structured feature set and, critically, produces the redacted text that the semantic layer will read. The division of labour is deliberate. The rule engine is given the real infrastructure, the sender headers, the domains, and the certificates, while the semantic layer is given only the words, with every web address replaced by the token `[LINK]` and every email address replaced by `[EMAIL]`. This redaction is what keeps the two analytical layers independent, so that their later agreement measures genuine corroboration rather than the same signal counted twice. Figure 4.1 shows the redaction routine.

**Figure 4.1: URL and address redaction (`core/preprocess.ts`)**

```typescript
export const REDACTION_TOKEN = "[LINK]";
export const EMAIL_TOKEN = "[EMAIL]";

export function redactLinks(text: string): string {
  return text
    .replace(SCHEME_URL, REDACTION_TOKEN)
    .replace(WWW_URL, REDACTION_TOKEN)
    // Bare domains: only redact strings the public-suffix list confirms are real
    // ...
}
```

The redaction preserves the linguistic force of the message. A sentence that reads "verify your identity at [LINK]" still carries the coercive signal a human reader would perceive; only the domain, which the semantic layer is not permitted to judge, is removed. Image submissions preserve the same separation, because a screenshot is transcribed to text by a separate vision call before it enters this pipeline, and the image itself never reaches the analysis layers.

### 4.3.2 Rule-Based Threat Scoring Engine

The rule-based engine is the first analytical layer and the concrete expression of the deny-by-default posture. Every submission begins at the maximum threat score of 1.0, fully untrusted, and earns reductions only by passing defined verification checks, which inverts the conventional model in which content begins at zero risk and accumulates penalties. The engine evaluates the nine weighted indicators specified in Chapter Three and reproduced in Table 4.2.

**Table 4.2: Rule-Based Threat Indicators and Weights**

| Indicator | Fails when | Weight | Applicable to |
|---|---|--:|---|
| Domain age | Registered under 30 days ago, or WHOIS indeterminate | 0.15 | Submissions with a URL |
| SSL certificate | Missing, expired, self-signed, or host unreachable | 0.10 | Submissions with a URL |
| URL IP address | Host is a raw IP rather than a domain | 0.12 | Submissions with a URL |
| Brand similarity | Domain resembles a known brand without being it | 0.15 | Submissions with a URL |
| Subdomain depth | More than three levels of nesting | 0.08 | Submissions with a URL |
| Email authentication | SPF fails or is absent, or neither DKIM nor DMARC passes | 0.12 | Email only |
| Reply-to mismatch | Reply-to domain differs from sender domain | 0.10 | Email only |
| Credential form in body | Body contains a password or credential input field | 0.10 | Email only |
| URL shortener | A known shortening service is used | 0.08 | Submissions with a URL |

The weights sum to 1.000 across the full set. Two implementation decisions materially refined the design described in Chapter Three. The first concerns indeterminate checks. Under deny-by-default, a check that cannot be completed counts as a failure rather than an exclusion. A WHOIS lookup that returns no record, or a TLS handshake that cannot be established because the host is offline, is treated as a failed indicator, not a skipped one, on the reasoning that an adversary who withdraws phishing infrastructure after a campaign must not thereby obtain a lower threat score than one who leaves the evidence intact. The absence of verification is not treated as verification.

The second and more consequential refinement concerns the scoring formula itself. Chapter Three specified the rule score as `R = 1 - Sigma(w_i * pass_i)` summed over all nine indicators. Implementation established that this formula is defective, because not every indicator applies to every submission. Six indicators require a URL and three require email headers, so for a bare URL submission the three email indicators can never be passed, their weight can never be earned back, and the score therefore carries a permanent floor. Under the original formula a submission of the address `google.com` scores 0.320 and is misclassified as Medium Risk, a false positive on one of the most reputable domains in existence. The engine was corrected to normalise the score over the applicable indicator set only, as shown in Figure 4.2, and a regression test preserves the defect and its correction so that the misclassification cannot silently return.

**Figure 4.2: Normalised rule score over the applicable set (`core/rules.ts`)**

```typescript
const applicable = indicators.filter((i) => i.applicable);
const applicableWeight = applicable.reduce((s, i) => s + i.weight, 0);

// ABSTENTION. No structural indicator applies (a plain text message with no
// links and no headers). Returning R = 1.0 would flag every such message;
// returning R = 0.0 would clear them all. Both are lies. The engine abstains.
if (applicableWeight === 0) {
  return { R: null, indicators, applicableWeight: 0 };
}

const earned = applicable.reduce((s, i) => s + (i.passed ? i.weight : 0), 0);
const R = 1 - earned / applicableWeight;
```

Where no indicator applies at all, as in a plain text message carrying neither a link nor headers, the engine returns a null score rather than a number. This abstention is important. Substituting 1.0 would flag every text message as maximum threat and substituting 0.0 would clear them all, so the engine declines to invent a structural verdict where there is no structure to inspect, and the fusion stage defers to the semantic layer instead.

The brand-similarity indicator carries the most substantial logic. It first checks whether the registrable domain is an official brand domain, in which case it passes. Otherwise it tokenises the second-level label, applies homoglyph normalisation that folds visually similar characters such as the digit zero to the letter o and the digit one to the letter l, and compares each token against each known brand name by Levenshtein distance. A normalised distance of zero indicates that a token is a brand name inside a domain that is not the brand's, and a distance of one or two indicates typosquatting; both fail. Homoglyph normalisation is necessary rather than cosmetic, because a domain such as `paypa1-verify.com`, spelled with the digit one, has a raw Levenshtein distance of one from the brand, but after normalisation it collapses to distance zero and is correctly identified as exact brand impersonation.

### 4.3.3 AI-Powered Content Analysis Module

The semantic analysis module is the second analytical layer, and it addresses the linguistic dimensions of manipulation that structural analysis cannot capture. It issues exactly one call to the Google Gemini model per submission, at temperature zero for reproducibility, and constrains the response to a fixed JSON schema so that the model cannot return free prose. Every response is cached under the SHA-256 hash of the redacted content, so that a repeated submission never triggers a second call, which is what makes the evaluation reproducible.

The module receives only the redacted text and is instructed in its system prompt that it is deliberately blind to all technical context. It is required to return three fields: a confidence score in the interval from zero to one, an array of detected manipulation patterns drawn from six fixed categories, and a plain-language explanation written for a non-technical reader. The six categories are urgency manipulation, authority impersonation, emotional exploitation, credential harvesting, financial manipulation, and action coercion. For each detected pattern the model must return the exact span of text that carries the manipulation, quoted verbatim. This evidence requirement is enforced twice, once in the prompt and once in a parser that discards any pattern whose quoted evidence cannot be matched as a literal substring of the submission. A model cannot, therefore, cause the report to display a quotation it invented. The full prompt text and response schema are reproduced in the accompanying document `GEMINI_PROMPT.md`.

### 4.3.4 Hybrid Threat Scoring Algorithm

The Hybrid Threat Scoring Algorithm fuses the rule-based score R and the semantic confidence score A into a single hybrid score H. Chapter Three defined the formula as

H = (alpha * R) + (beta * A) + (gamma * R * A),   with alpha = 0.4, beta = 0.4, gamma = 0.2,

and described the interaction term gamma * R * A as an amplifier that "pushes the hybrid score higher than a simple weighted average would produce" when both layers agree. Formal analysis carried out during implementation established that this description is incorrect, and that the term cannot amplify the score under any input. The reasoning is short. Because the three weights sum to unity, the formula is algebraically identical to a convex combination of the arithmetic mean of the two scores and their product,

H = (alpha + beta) * mean(R, A) + gamma * (R * A),

and because the product of two values in the interval from zero to one never exceeds their mean, it follows that H is less than or equal to mean(R, A) for all inputs. The interaction term therefore never raises the score above a simple average. It does the opposite. It withholds the upper portion of the score range from any submission on which only one analytical layer registers a threat, and releases that range in full only when both layers converge. The fusion is conjunctive, a soft logical AND, and its function is the suppression of false positives rather than the amplification of true ones. Figure 4.3 shows the implementation, whose own documentation records the correction.

**Figure 4.3: The interaction term as an agreement gate (`core/htsa.ts`)**

```typescript
//      H = (alpha + beta) * mean(R, A) + gamma * (R * A)
// And since (R * A) <= mean(R, A) for all R, A in [0, 1], it follows that
//      H <= mean(R, A)     for all inputs.
//
// The interaction term therefore NEVER amplifies the score above a weighted
// average. It does the opposite: it withholds the upper portion of the score
// range from content on which only ONE analytical layer registers a threat,
// and releases it in full only when both layers converge.
// This is a conjunctive (soft-AND) fusion. It is an AGREEMENT GATE.
const H = w.alpha * r + w.beta * a + w.gamma * r * a;
```

The worked example that motivates the design survives this reinterpretation intact. A legitimate marketing email with a clean domain, a valid certificate, and a passing SPF record, but which uses a link shortener and the phrase "act now, offer expires in 24 hours", scores R = 0.18 structurally and A = 0.45 semantically. Under a simple average, with gamma set to zero, the hybrid score is 0.315, which crosses the 0.3 clearance threshold into Medium Risk and produces a false positive. Under the agreement gate, with gamma at 0.2, the disagreement between the layers keeps the product term small and the hybrid score falls to 0.268, below the threshold, correctly clearing the message. The layers disagreed, and the gate held the score down. The hybrid score is mapped to one of four risk levels, Low below 0.3, Medium from 0.3 to 0.6, High from 0.6 to 0.8, and Critical from 0.8 upward, and under the deny-by-default posture only content scoring below 0.3 is cleared.

The fusion module also implements symmetric abstention, which was added during implementation and is the mirror of the rule engine's abstention. Where the rule engine returns null because no indicator applied, the hybrid score reduces to A alone. Where the semantic layer returns null because there was no analysable language to read, as with a bare link submitted on its own, the hybrid score reduces to R alone. A null semantic score is explicitly not treated as a score of zero, because zero means the model read the words and judged them safe, whereas null means there were no words to read, and conflating the two would allow a bare typosquat URL to be cleared to Low. Only when both layers abstain does the module refuse to produce a verdict.

### 4.3.5 Graceful Degradation

Because the semantic layer depends on an external service, the analysis core is written to remain usable when that service is unavailable, in satisfaction of the reliability requirement. The orchestrator wraps the semantic call, and if it fails for any reason, whether network loss, rate limiting, or service outage, it substitutes A = R, marks the result as provisional by setting an availability flag to false, and allows the fusion to proceed. Figure 4.4 shows the degradation path.

**Figure 4.4: Graceful degradation to rule-only scoring (`core/analyze.ts`)**

```typescript
try {
  const ai = await analyzeText(features.redactedText);
  // ...
} catch (err) {
  aiAvailable = false;
  if (/* language present but no structural fallback */) {
    // Language present, service down, no structural fallback: cannot degrade.
    throw new AiUnavailableError((err as Error).message);
  }
  // Degrade to A = R (NFR05). The aiAvailable flag marks the verdict provisional.
  console.warn(`[analyze] AI layer unavailable, degrading to A = R`);
}
```

The one case in which degradation is impossible is a submission that carries analysable language but no structural signal, because there is then nothing to degrade to; this raises a distinct error rather than a fabricated verdict. In every other case the system completes its analysis, annotates the result, and the interface displays a notice that the semantic layer was unavailable. This degradation behaviour is exercised directly by the offline demonstration mode described in Section 4.6.

## 4.4 Database Implementation

This section describes the persistence layer, which stores completed analyses for the history view. The database is a local SQLite file accessed through the Node.js built-in SQLite interface, which required no additional dependency. A single table records each analysis, and its schema is shown in Figure 4.5.

**Figure 4.5: Analysis history schema (`lib/db.ts`)**

```sql
CREATE TABLE IF NOT EXISTS analyses (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at     TEXT    NOT NULL,
  content_type   TEXT    NOT NULL,   -- 'email' | 'url' | 'text' | 'image'
  rule_score     REAL,               -- R in [0,1]; NULL = rule engine abstained
  ai_score       REAL,               -- A in [0,1]; NULL = semantic layer abstained
  hybrid_score   REAL    NOT NULL,   -- H in [0,1]
  classification TEXT    NOT NULL,   -- 'Low' | 'Medium' | 'High' | 'Critical'
  ai_available   INTEGER NOT NULL,   -- 1 = Gemini ran; 0 = degraded to rule-only
  preview        TEXT    NOT NULL,   -- single-line, <=140-char snippet
  rules_ms       REAL, ai_ms REAL, total_ms REAL   -- per-analysis latency
);
```

Two properties of the persistence layer are worth recording. First, the null scores that represent abstention are preserved through storage and rendered in the interface as a dash rather than a zero, so that abstention remains visible and is never silently converted into a low score. Second, all database access is fail-soft: a read or write error is logged and swallowed, and an analysis can never fail because history could not be recorded. Persistence is also disabled automatically when the system detects that it is running on an ephemeral serverless filesystem, where a write would appear to succeed and then be discarded; in that environment the history endpoint reports that history is unavailable rather than returning a misleadingly empty list.

## 4.5 System Interfaces

This section presents the system's user-facing interfaces. The interface is organised around a submission screen and a threat report, with supporting history and settings screens. Every figure in this section is a screenshot to be inserted by the author.

The submission screen accepts pasted text, a pasted or dragged screenshot, or a typed URL, and presents the three input types through a single drop zone. Figure 4.6 shows this screen.

**Figure 4.6:** [INSERT: screenshot, "Submission page with drop zone.png"]

The threat report is the system's principal output and is composed of five blocks in a fixed order: the verdict, the score decomposition, the indicator table, the detected patterns, and the plain-language explanation. Figure 4.7 shows a complete report for a phishing example.

**Figure 4.7:** [INSERT: screenshot, "Threat report, whole page, phishing example.png"]

The score decomposition is the component in which the algorithm becomes visible to the user. It prints the rule score, the semantic score, and the hybrid score, together with the substituted equation showing the real numbers, for example H = 0.4(0.800) + 0.4(0.940) + 0.2(0.800 x 0.940) = 0.846. Figure 4.8 shows this block in close-up.

**Figure 4.8:** [INSERT: screenshot, "Score decomposition close-up showing the substituted equation.png"]

The indicator table displays all nine indicators, marking each as passed, failed, or not applicable, with inapplicable indicators greyed and their weights struck through. Their continued visibility is what makes the applicability normalisation legible to a reader, because it shows which indicators contributed to the score and which were excluded. Figure 4.9 shows the indicator table with inapplicable rows visible.

**Figure 4.9:** [INSERT: screenshot, "Indicator table with greyed n:a rows visible.png"]

The detected-patterns block lists each manipulation pattern the semantic layer identified, together with the verbatim span of text that carries it, which is the most persuasive element of the report because it shows the user the literal sentence that constitutes the manipulation. Figure 4.10 shows this block.

**Figure 4.10:** [INSERT: screenshot, "Patterns block with evidence spans.png"]

For contrast, Figure 4.11 shows the report produced for a low-risk submission, in which the verdict is a clearance rather than a warning.

**Figure 4.11:** [INSERT: screenshot, "A Low Risk result.png"]

The settings screen exposes the fusion weights as adjustable controls, and serves a second purpose as a live demonstration of the ablation studied in Section 4.7. Dragging the interaction weight to zero on the borderline marketing example causes its classification to change from Low to Medium in real time, which makes the effect of the interaction term directly observable. Figure 4.12 shows the settings screen.

**Figure 4.12:** [INSERT: screenshot, "Settings page.png"]

Finally, the history screen presents past analyses as a plain table, newest first, showing the timestamp, the content type, the three scores, the verdict, and the per-analysis timings. This is a deliberate simplification of the charted dashboard envisaged in Chapter Three; a table backed by real stored analyses was preferred over a visualisation that would either duplicate the evaluation charts or require fabricated data to look complete. Figure 4.13 shows the history table.

**Figure 4.13:** [INSERT: screenshot, "History table.png"]

## 4.6 System Testing

This section reports the testing carried out on the system, at the levels of unit testing, integration testing, and non-functional requirement verification.

### 4.6.1 Unit Testing

The analysis core was covered by a suite of automated unit tests written to run without a network connection or a running server, so that the scoring logic could be verified in isolation. The suite comprises 67 tests across five files, all of which pass. Table 4.3 summarises the suite by module.

**Table 4.3: Unit Test Summary**

| Test file | Module under test | Tests |
|---|---|--:|
| `core/rules.test.ts` | Rule-based scoring engine | 17 |
| `core/htsa.test.ts` | Hybrid fusion and classification | 15 |
| `core/preprocess.test.ts` | Ingestion, redaction, feature extraction | 22 |
| `core/ai.test.ts` | Response parsing and evidence guard | 9 |
| `core/image-input.test.ts` | Image transcription separation | 4 |
| **Total** | | **67** |

The tests encode the load-bearing behaviours of the system as executable assertions. Among them, the rule-engine tests confirm that a fully applicable phishing email scores R = 0.800, that `google.com` scores 0.000 under the corrected formula while reproducing the 0.320 misclassification under the naive formula, that a plain text message returns a null abstention, and that `paypa1-verify.com` is detected as impersonating `paypal` at normalised distance zero. The fusion tests confirm that the hybrid score never exceeds the mean of its inputs across a grid of values, that the borderline marketing example scores 0.315 under ablation and 0.268 under the gate, and that the equation is rendered verbatim for the report. The full test log is preserved in `docs/test-output.txt`.

### 4.6.2 Integration Testing

Integration testing verified the system end to end, exercising the full path from an HTTP submission through preprocessing, rule scoring, the live semantic call, fusion, persistence, and the returned report. This was carried out by the evaluation harness described in Section 4.7, which submits content to the deployed analysis endpoint and reads back the structured result, and which therefore constitutes a continuous integration test across the entire corpus in addition to its role in measuring detection performance. The graceful-degradation path was verified separately by confirming that the offline demonstration mode returns complete reports for its five bundled examples with no network call, each in between five and thirty-four milliseconds, which is orders of magnitude faster than a live analysis and therefore confirms that no external service was contacted.

### 4.6.3 Non-Functional Requirement Verification

The seven non-functional requirements defined in Chapter Three were verified as summarised in Table 4.4, with the performance requirement examined in detail in Section 4.7.6.

**Table 4.4: Non-Functional Requirement Verification**

| Requirement | Target | Outcome |
|---|---|---|
| NFR-01 Performance | Rules < 2 s; full analysis < 15 s | Partially met: full analysis met on all types; rules under 2 s for email and text but not for URLs (see 4.7.6) |
| NFR-02 Accuracy | Accuracy > 95%; F1 > 0.94 | Not met on this corpus (see 4.7.3 and discussion) |
| NFR-03 Security | Input validation; env-var key storage | Met: API key held only in an environment variable, never client-side; endpoint validates input |
| NFR-04 Usability | Responsive; clear indicators; no training | Met: responsive layout to mobile width; colour-coded verdicts |
| NFR-05 Reliability | Graceful degradation to rule-only | Met: verified degradation path and offline mode (see 4.3.5, 4.6.2) |
| NFR-06 Scalability | Modular architecture | Met: independent core modules on a shared contract |
| NFR-07 Maintainability | Clean, documented, modular; tests | Met: 67 passing unit tests over a modular core |

The accuracy requirement was not met on the corpus used here, and the reasons are examined in Section 4.7.3 and Section 4.8. In summary, the target of an F1 score above 0.94 is properly a target for the complete hybrid deliverable rather than for the diagnostic standalone conditions, and the truncation of the run together with the structural detectability ceiling of the rule layer placed it out of reach on this corpus. This is reported as an unmet target rather than adjusted.

## 4.7 Performance Evaluation Results

This section reports the results of the performance evaluation. It describes the evaluation setup and corpora, the calibration of the semantic layer, the detection performance across all six experimental conditions, the ablation of the interaction term, the measurement artefacts identified and corrected during the study, and the operational performance of the system.

### 4.7.1 Evaluation Setup and Corpora

The evaluation was conducted by a Python harness that drives the deployed analysis endpoint against benchmark corpora and records the rule and semantic scores independently for each item, so that the fusion conditions can be computed from the cache without additional model calls. Two substitutions were made to the corpora specified in Chapter Three, each for a practical reason and each disclosed here. The PhishTank feed returned a rate-limit response without a registered API key, and registration was intermittently closed, so the phishing-URL class was drawn instead from the Phishing.Database aggregated feed, which itself ingests PhishTank and OpenPhish and is freely downloadable and citable. The Enron corpus, at 1.7 gigabytes, exceeded the sourcing time available, so the legitimate-email class was drawn from the SpamAssassin public `easy_ham` corpus, a standard and citable dataset for legitimate mail.

The planned corpus comprised 1,000 URLs and 600 emails. After the URL classes were normalised to their registrable domains, to remove a collection artefact described in Section 4.7.5, and de-duplicated, the harness drove 1,479 items. The run reached all of them over approximately 8.8 hours, but the free-tier rate limit on the semantic model degraded 467 items to rule-only scores, which the harness deliberately did not cache because a degraded score is not a genuine semantic reading, and a further 155 items failed transiently. The detection results below therefore rest on the 857 items that scored cleanly, whose composition is given in Table 4.5. This truncation is a material limitation and is treated as such here and in Chapter Five.

**Table 4.5: Composition of the Clean Evaluation Set (n = 857)**

| Class | Legitimate | Threat | Total |
|---|--:|--:|--:|
| URLs | 381 | 343 | 724 |
| Emails | 114 | 19 | 133 |
| **Total** | **495** | **362** | **857** |

The email class, and the phishing-email class in particular, is thin, because the email corpus was processed last, when rate limiting was heaviest. Only 19 phishing emails scored cleanly. This has a direct bearing on the interpretation of the semantic and fusion conditions, which is stated where those conditions are reported. A separate hard-case corpus of 100 items, evenly split between legitimate and threat, was constructed to supply the borderline cases that the main corpus is sparse in; approximately 22 per cent of its items are authored rather than sourced, a proportion disclosed here because those items were written for the study.

### 4.7.2 Calibration of the Semantic Layer

Before the main evaluation, the semantic layer was calibrated against a small probe of hand-constructed messages with expected confidence bands, to confirm that it places unambiguous phishing high, legitimate marketing in the 0.2 to 0.4 band, and genuine but urgent messages low. The probe behaved as intended, with unambiguous phishing scoring at or above 0.85 and legitimate marketing landing inside its expected band.

One calibration case requires explicit disclosure. Item 6, a genuine bank security alert reading "New sign-in to your account", was originally assigned an expected band of 0.20 to 0.50, and the model scored it 0.08, below the floor. The band was subsequently widened to 0.00 to 0.50. This change is disclosed rather than hidden because it is a widening of an expectation after seeing the result, which ordinarily weakens a claim. In this instance, however, the model was correct and the original band was wrong. The message actively defuses its own alarm, stating that no action is needed, directing the reader to the number on the back of their card rather than to a link, and promising that the sender will never ask for a password or PIN by email. There is, in short, no manipulation left in the text to detect, and the original 0.20 floor wrongly assumed a residual authority signal that the message does not contain. Scoring the same structural situation at 0.96 for a genuine phishing message and 0.08 here, a separation of 0.88, is the model passing an inverse trap rather than miscalibrating. The band was corrected to reflect the correct expectation, and the change is recorded so that it is visible in the account.

### 4.7.3 Detection Performance

Detection performance was measured for six conditions at the 0.3 clearance threshold: the rule layer alone, the semantic layer alone, the hybrid without the interaction term, the hybrid with the interaction term, a Random Forest baseline on lexical URL features, and the escalation variant introduced in Section 4.7.4. In keeping with the reporting convention adopted throughout, precision and recall are reported separately rather than collapsed into F1 alone. Table 4.6 presents the results.

**Table 4.6: Detection Performance Across Six Conditions (threshold 0.3)**

| # | Condition | n | Precision | Recall | F1 | FPR | AUC |
|---|---|--:|--:|--:|--:|--:|--:|
| 1 | Rule only (R) | 857 | 0.831 | 0.555 | 0.666 | 0.083 | 0.739 |
| 2 | AI only (A), email | 129 | 0.750 | 1.000 | 0.857 | 0.044 | 1.000 |
| 3 | HTSA, gamma = 0 | 857 | 0.833 | 0.580 | 0.684 | 0.085 | 0.754 |
| 4 | HTSA, gamma = 0.2 | 857 | 0.843 | 0.580 | 0.687 | 0.079 | 0.756 |
| 5 | Random Forest, domain-only | 1000 | 0.743 | 0.654 | 0.696 | 0.226 | 0.767 |
| 6 | HTSA-E | 857 | see 4.7.4 | | | | |

Several features of Table 4.6 require comment. The rule layer alone achieves high precision, 0.831, but low recall, 0.555, which is the empirical signature of structural detection: when the rule engine fires it is usually right, but it misses a large share of threats, because modern phishing hosted on clean infrastructure and text-only social engineering are structurally innocent. This is not a shortfall of the implementation but the motivation for the semantic layer, and it is discussed further in Section 4.8.

The semantic condition is reported on the email corpus only, because the semantic layer abstains on bare URLs and the 724 URL items therefore carry no semantic score. Its apparent perfect recall and AUC of 1.000 must be read with caution and are not treated as a headline result, because they rest on only 15 phishing emails within a set of 129, a positive class far too small to support a reliable estimate. The figure is reported for completeness and flagged as unreliable.

The Random Forest baseline is reported on the domain-only feature set, which is the artefact-free version explained in Section 4.7.5, and achieves an F1 of 0.696 at the clearance threshold and 0.727 at its own optimal threshold. This is the honest baseline against which the hybrid conditions should be read; a far higher figure obtainable from full-URL lexical features is shown in Section 4.7.5 to be an artefact of how the two classes were collected rather than a measure of phishing detection.

### 4.7.4 Ablation of the Interaction Term

The central experimental question was whether the interaction term, the agreement gate, improves detection, and this section reports the ablation that answers it. The result is mixed, and it is reported as such. Before the figures are read, one structural fact must be established, because it governs their interpretation. The gate operates only on submissions for which both R and A are defined, because for any item on which the semantic layer abstains the hybrid score reduces to R and the interaction term is inert. Every URL item in the corpus abstains, so the gate can act on none of them. The entire effect of the gate therefore lives within the 129 email items on which both scores are defined, of which only 19 are phishing, and it does not rest on 857 items. This is stated plainly so that no reader concludes otherwise.

On those 129 dual-layer items, the gate produces a small and consistent benefit, shown in Table 4.7. Moving the interaction weight from zero to 0.2 raises precision from 0.833 to 1.000 by suppressing all three of the false positives present under the simple average, while recall is unchanged at 1.000, so no true positive is lost.

**Table 4.7: Gate Ablation on the 129 Dual-Layer Email Items**

| Configuration | Precision | Recall | False positives | True positives | False negatives |
|---|--:|--:|--:|--:|--:|
| gamma = 0 (simple average) | 0.833 | 1.000 | 3 | 15 | 0 |
| gamma = 0.2 (agreement gate) | 1.000 | 1.000 | 0 | 15 | 0 |

Across the full clean corpus, where the inert URL items dilute the effect, the same movement raises overall precision from 0.833 to 0.843, lowers the false-positive rate from 0.085 to 0.079, and raises the area under the curve from 0.754 to 0.756, with recall unchanged. On this corpus, therefore, the gate is a small clean improvement.

That is not the whole picture, and the contrary evidence is reported with equal weight. On the hard-case corpus of 100 items, which was constructed specifically to contain borderline cases and on which every item carries both scores, the gate is net-harmful at the same operating point, as Table 4.8 shows. It suppresses one false positive but at the cost of two true positives, and the single false positive it removes is itself an authored item.

**Table 4.8: Gate Ablation on the Hard-Case Corpus (100 items)**

| Configuration | Precision | Recall | False positives | True positives | False negatives |
|---|--:|--:|--:|--:|--:|
| gamma = 0 | 0.821 | 0.920 | 10 | 46 | 4 |
| gamma = 0.2 | 0.830 | 0.880 | 9 | 44 | 6 |

On an earlier 48-item sample the gate produced no change in classification at all, with identical binary metrics, an identical best F1 of 0.818 under a full threshold sweep, and an equal area under the curve of 0.825, although a mean suppression of 0.044 confirmed that the mechanism was acting. Taken together, the three samples describe a mechanism whose effect is real but modest and corpus-dependent: no measurable effect on the smallest sample, a net-harmful trade on the adversarial borderline set, and a small consistent benefit on the main corpus. One finding was consistent across every sample: raising the interaction weight above 0.2 was unambiguously harmful, driving recall down without a compensating gain in precision. The value of 0.2 is therefore an upper bound on the useful weight rather than a point on an improving curve. Figure 4.14 and Figure 4.15 present the condition comparison and the confusion matrices, and Figure 4.16 presents the gamma sweep.

**Figure 4.14:** [INSERT: figure, `eval/out/conditions-bar.png`, grouped bar of the four metrics across the conditions]

**Figure 4.15:** [INSERT: figure, `eval/out/confusion.png`, confusion matrices]

**Figure 4.16:** [INSERT: figure, `eval/out/gamma-curve.png`, best F1 and related metrics across gamma]

A live phishing email encountered during the study exposed a structural limit of the fusion that the gate cannot address, and that motivated an escalation variant, HTSA-E, reported here as the sixth condition. Because the hybrid score is a weighted sum, a structurally clean email, one with R close to zero, is capped at H = beta * A, which at gamma = 0.2 is 0.40, so the score cannot reach High no matter how certain the semantic layer is. Weak safety evidence, a low R that means only that a sender controls their own domain, can thereby veto strong threat evidence, a high A that means the language is unambiguously fraudulent. Across the combined evaluation set, 35 items had R below 0.15 and A above 0.8 and were held at Medium by this cap, and 33 of them were genuine threats. HTSA-E adds a disjunctive escalation on top of the existing gate: if either layer is independently certain, exceeding a high threshold tau, the score is escalated. The threshold was not chosen by hand but derived from the data as the lowest value at which no legitimate training item escalates, which on the training split is tau = 0.910, set just above the highest legitimate escalation score of 0.90. Applying HTSA-E moved 33 threats from Medium to High or Critical, moved four further threats up a tier, and escalated no legitimate item. At the 0.3 clearance threshold its binary metrics are identical to the gated hybrid, because it acts at the Medium-to-High boundary, above the clearance line, so its contribution is a tier change rather than a change in what is cleared. It is reported here as the delivered refinement of the fusion, with the caveat that the threshold that defines it is currently anchored to an authored legitimate item and would be re-derived on a larger clean corpus.

### 4.7.5 Identified Measurement Artefacts and Their Correction

A distinguishing feature of this evaluation was the identification and correction of five measurement artefacts, each of which would have flattered the results had it gone unnoticed. This section records them, because the diagnostic work is part of the contribution.

The first artefact was a collection confound in the URL corpus. The legitimate URLs, drawn from a ranked list of sites, were bare registrable domains, whereas the phishing URLs, drawn from a feed of captured attacks, were full URLs with long paths. The two classes therefore differed in shape before any phishing signal was considered, with a median URL length of 19 characters for the legitimate class against 74 for the phishing class, and a median path length of zero against 30. A classifier trained on such data separates the classes on how they were collected rather than on what distinguishes phishing. The second artefact was the consequence of the first for the machine-learning baseline. A Random Forest trained on the full lexical features achieved an F1 of 0.993, with URL length and path length as its most important features, which is to say it had learned that a long URL is a phishing URL. Stripping both classes to their registrable domains removed the confound and dropped the same model to an F1 of 0.727 and an area under the curve of 0.767, which is the honest baseline reported in Section 4.7.3. The rule engine was checked against the same confound and does not ride it, because its URL indicators fire on fewer than five per cent of the phishing URLs and its domain-age and brand checks are unaffected by stripping the path, which is itself evidence that the structural layer measures a real signal rather than a shape.

The third artefact concerned the email-authentication indicator, whose applicability was corrected so that an absent authentication result is treated as not applicable rather than as a failure, which removed a class of false positives. The fourth artefact was the semantic-abstention correction already described in Section 4.3.4, where a bare URL that produces no semantic score must be recorded as an abstention rather than as a score of zero, since scoring it zero would manufacture a perfect false-negative rate for the semantic layer and make the hybrid appear better by comparison. The fifth artefact, identified late in the study, is a structural blind spot in the treatment of URL paths. A submission of a genuine, aged, certificated domain carrying a fabricated malicious path, such as a real university domain followed by a misspelled fee-payment path, scores R = 0.000 and is cleared, because all nine indicators inspect the domain, the host, or the headers, and none inspects the path. On the clean corpus, 79 of the 343 phishing URLs that scored, 23 per cent, scored R = 0.000, a measured population of structural false negatives. Figure 4.17 and Figure 4.18 present the gate-suppression scatter and the baseline diagnosis.

**Figure 4.17:** [INSERT: figure, `eval/out/suppression.png`, gate suppression against the disagreement between R and A]

**Figure 4.18:** [INSERT: figure, `eval/out/rf-diagnosis.png`, Random Forest feature importances before and after correction]

Three of these five artefacts, the semantic-abstention case, the structural-cleanliness cap that motivated HTSA-E, and the path blind spot, are instances of a single underlying error rather than three independent ones. In each, an absence of evidence was being converted into evidence of absence: a missing semantic reading was read as "cleared", a low structural score was read as "safe", and an unexamined attribute class was read as "verified". Deny-by-default forbids exactly this conversion, and Chapter Three states as much for the case of a failed WHOIS lookup. The principle was sound; its application was inconsistent, and the study made it consistent. This unifying observation is developed in Section 4.8.

### 4.7.6 Operational Performance

Operational latency was measured against the first non-functional requirement, that rule-based analysis complete within two seconds and full analysis within fifteen. Latency was measured with a dedicated probe of 40 fresh submissions that were guaranteed to miss the response cache, split by content type, because URL submissions skip the semantic call entirely and averaging them together with emails would understate the true cost of each. Table 4.9 presents the results.

**Table 4.9: Operational Latency by Content Type (fresh, cache-missing)**

| Content type | n | Rules mean / p95 (ms) | Semantic mean / p95 (ms) | Total mean / p95 (ms) |
|---|--:|--:|--:|--:|
| URL | 14 | 2649 / 6511 | 0 / 0 | 2649 / 6511 |
| Email | 13 | 4 / 7 | 3173 / 4254 | 3177 / 4256 |
| Text | 13 | 0 / 0 | 3934 / 4997 | 3935 / 4997 |

The full-analysis target of fifteen seconds was met on every content type, with a worst observed total of 6.6 seconds. The rule-layer target of two seconds was met for email and text, where the rule computation completes in single-digit milliseconds, but it was not met for URLs, whose rule-layer mean was 2649 milliseconds and whose 95th percentile was 6511 milliseconds. The cause is named precisely, because it is not what the requirement assumed. The rule computation itself is sub-millisecond, as the email and text figures demonstrate; the URL latency is entirely the cost of live network verification, the WHOIS lookups and TLS handshakes that structural verification of a domain requires, and its worst case is a dead phishing domain whose WHOIS query must time out. Of the 14 URL probes, three encountered an indeterminate or unreachable WHOIS response. The miss is therefore a property of live infrastructure verification rather than of computation, and is reported as such.

## 4.8 Discussion of Findings

This section interprets the results as a whole. The evaluation set out to determine whether the hybrid system outperforms its standalone components, and the answer that emerged is qualified rather than emphatic. The two standalone layers fail in mirror-image ways, and this mutual complementarity, rather than any single headline number, is the strongest evidence for the hybrid design. The rule layer clears phishing hosted on legitimate infrastructure, because such content is structurally innocent and every indicator passes, while the semantic layer catches it from the language. Conversely, text-only phishing that carries no URL and no headers defeats the rule layer, which has nothing structural to inspect, and is caught by the semantic layer at high confidence. Each layer rescues the other's blind spot, and this pattern fell out of the data rather than being assumed.

The interaction term is the point on which the study is most instructive, and its lesson is methodological. The term was proposed in Chapter Three as an amplifier of agreement, and implementation established by formal analysis that it cannot amplify at all, that it is instead an agreement gate which suppresses disagreement. The evaluation of that gate then produced a mixed result: no effect on the smallest sample, net harm on the adversarial hard-case corpus, and a small consistent benefit on the main corpus, with any weight above 0.2 harmful throughout. A rigorous account of testing one's own proposed mechanism and finding its benefit modest and conditional is a stronger contribution than a formula reported to have worked on first presentation, and the mixed result is therefore presented as a finding rather than smoothed toward a positive one. It should also be read in the light of the corpus limitation, since the gate's effect lives in 129 email items of which only 19 are phishing, and a larger clean email corpus is required before its value can be settled.

The five measurement artefacts, and the single principle underlying three of them, constitute the study's second substantive finding. The recurring error, the conversion of absent evidence into positive evidence of safety, is precisely the failure mode that a deny-by-default posture exists to prevent, and its repeated appearance in three different guises shows how easily a sound principle is applied inconsistently in practice. Identifying the pattern, rather than merely patching each instance, is what turns three bug fixes into one observation about the discipline of building under deny-by-default.

## 4.9 Comparison with Related Works

This section situates the results against the related work reviewed in Chapter Two. The deep-learning and transformer-based detectors surveyed there report detection accuracies above 99 per cent on standard benchmarks, and the machine-learning baseline in this study reproduced a comparable figure, an F1 of 0.993, before that figure was shown to be a collection artefact. The comparison is instructive precisely because of that correction. A high benchmark number is only as meaningful as the benchmark is free of confounds, and a contribution of this study is to demonstrate, on its own data, how a lexical classifier can attain an apparently excellent score by separating classes on their method of collection rather than on any property of phishing. The honest domain-only baseline of 0.727 is a more faithful point of comparison, and the hybrid conditions should be read against it rather than against the inflated figure.

The more fundamental distinction from the surveyed work is architectural rather than numerical. Most of the detectors reviewed in Chapter Two operate on a single dimension of analysis, whether URL structure, email metadata, or message text, and those that combine dimensions typically do so sequentially rather than through a formal fusion. The system reported here fuses a structural and a semantic score through an explicit mathematical rule whose behaviour was analysed formally, and does so under a deny-by-default posture that treats content as untrusted until verified. The value of that architecture is not that it produced the highest number, which on this truncated corpus it did not, but that it makes the basis of every verdict inspectable, decomposes each score into its structural and semantic contributions, and fails toward caution rather than toward clearance. That combination of formal fusion, deny-by-default, and an auditable verdict is the respect in which this work differs from the related literature, and it is developed further in the conclusions that follow.

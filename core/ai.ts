/**
 * core/ai.ts
 *
 * The AI semantic analysis layer (layer 2). One Gemini call per submission.
 *
 * ---------------------------------------------------------------------------
 * STRUCTURALLY BLIND BY CONSTRUCTION
 * ---------------------------------------------------------------------------
 * analyzeText takes a STRING, not a Features object. That is deliberate and
 * enforced at the type level. This module cannot see the URL list, the domain,
 * the certificate, the registration age, or the SPF/DKIM/DMARC verdicts, because
 * it is never handed them. The string it receives is preprocess's redactedText,
 * in which every URL, email address, and bare domain has already been replaced
 * by the token [LINK].
 *
 * The reason is independence. The rule engine scores infrastructure; this layer
 * scores language. If the AI could also read the domain, R and A would correlate
 * and the HTSA agreement gate would measure nothing. The blindness is the whole
 * point, so do not "enrich" the input with structural facts here. Ever.
 *
 * ---------------------------------------------------------------------------
 * DETERMINISM AND CACHING
 * ---------------------------------------------------------------------------
 * temperature is 0 and the response is a constrained JSON schema, so the model
 * cannot return prose and returns the same answer for the same input. Every
 * response is cached on disk keyed by SHA-256 of the redacted text, so reruns
 * (and the Phase 5 evaluation) cost nothing after the first call.
 */

import { GoogleGenAI, Type, type Schema } from "@google/genai";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import type { AIResult, DetectedPattern, PatternId } from "./types";
import { truncateHead } from "./preprocess";

// ---------------------------------------------------------------------------
// The six fixed pattern categories (Table 3.6). The model returns id + evidence;
// the canonical label is attached here, deterministically, never by the model.
// ---------------------------------------------------------------------------

export const PATTERN_LABELS: Record<PatternId, string> = {
  urgency_manipulation: "Urgency manipulation",
  authority_impersonation: "Authority impersonation",
  emotional_exploitation: "Emotional exploitation",
  credential_harvesting: "Credential harvesting",
  financial_manipulation: "Financial manipulation",
  action_coercion: "Action coercion",
};

const PATTERN_IDS = Object.keys(PATTERN_LABELS) as PatternId[];

// ---------------------------------------------------------------------------
// The prompt. This is the exact system instruction sent to Gemini. It is
// exported so the evaluation and the written report can cite it verbatim.
// The submitted (redacted) message is sent as the user turn, not spliced in
// here, so nothing in this template can be mistaken for user content.
// ---------------------------------------------------------------------------

export const PROMPT_INSTRUCTION = `You are the semantic analysis layer of a threat-detection system. You are given
the plain text of a message that a person has received — an email, a text
message, or a pasted note. Your single job is to judge, FROM THE WORDS ALONE,
how strongly the message is trying to manipulate its reader through social
engineering.

You are deliberately blind to all technical context. You do not know who sent
the message, what domain it came from, how old any web address is, whether any
link is genuine, or whether the message passed any authentication check. Do not
speculate about any of these. Any web link in the text has been replaced with
the token [LINK] and any email address with the token [EMAIL]; treat each only
as evidence that a link or an address is present, never as something whose
safety you can judge. You are judging language, not infrastructure.

--------------------------------------------------------------------------
MANIPULATION CONFIDENCE SCALE
--------------------------------------------------------------------------
Return a single confidence score in [0, 1] for how manipulative the language is.
Anchor it to this scale. Read the bands carefully — most legitimate commercial
mail lands LOW, and getting that right matters as much as catching fraud.

  0.0 - 0.2   Routine communication. No manipulation. Personal messages,
              transactional notices, ordinary correspondence.

  0.2 - 0.4   Persuasive or promotional, but legitimate commercial
              communication. Marketing urgency such as "sale ends Sunday",
              "limited stock", or "offer expires tonight" belongs HERE.
              A discount deadline is salesmanship, not a threat. Do not
              inflate this above 0.4 merely because it is pushy.

  0.4 - 0.6   Some manipulation present, intent ambiguous. The language leans
              on pressure or emotion in a way that a legitimate sender usually
              would not, but there is no clear fraudulent ask.

  0.6 - 0.8   Clear social engineering. Coordinated pressure, impersonation, or
              a manufactured problem steering the reader toward an action.

  0.8 - 1.0   Unambiguous fraud. Impersonation combined with a credential or
              payment demand and a manufactured consequence for inaction.

--------------------------------------------------------------------------
MANIPULATION PATTERNS
--------------------------------------------------------------------------
Identify every pattern below that is present. For each, quote the exact span
that carries it. Absence of patterns is a valid and common answer.

  urgency_manipulation     Manufactured time pressure or a deadline engineered
                           to force a hasty, unconsidered decision.
  authority_impersonation  Posing as a bank, government body, employer, or known
                           company to borrow its trust.
  emotional_exploitation   Fear, guilt, alarm, excitement, sympathy, or greed
                           used to override the reader's judgement.
  credential_harvesting    Soliciting a password, PIN, one-time code, card
                           number, or a login on a linked page.
  financial_manipulation   Pushing a payment, transfer, refund, fee, fine, or
                           investment.
  action_coercion          Pressuring one specific action — click, reply, call a
                           number, download, or disable a security control.

--------------------------------------------------------------------------
EVIDENCE — READ THIS TWICE
--------------------------------------------------------------------------
Every pattern's "evidence" MUST be an exact, character-for-character substring
of the message text. Copy it verbatim. Do NOT paraphrase, summarise, translate,
trim, add quotation marks, or insert an ellipsis. If you cannot quote a literal
span from the text, do not report the pattern. Two different patterns should
quote two different spans. The reader will be shown your quoted span next to the
message, so it has to match exactly.

--------------------------------------------------------------------------
EXPLANATION
--------------------------------------------------------------------------
Write two or three sentences of plain English for a non-technical reader,
explaining what the message is doing and why the score sits where it does. No
jargon.

==========================================================================
WORKED EXAMPLES
==========================================================================

--- Example 1 -------------------------------------------------------------
MESSAGE:
PayPal Security: we detected an unauthorized login to your account, which has
now been temporarily limited. You must verify your identity within 24 hours or
your account will be permanently suspended. Click the link below to restore
access and confirm your password and card details: [LINK]

RESPONSE:
{
  "confidence": 0.96,
  "patterns": [
    { "id": "authority_impersonation", "evidence": "PayPal Security" },
    { "id": "urgency_manipulation", "evidence": "verify your identity within 24 hours or your account will be permanently suspended" },
    { "id": "action_coercion", "evidence": "Click the link below to restore access" },
    { "id": "credential_harvesting", "evidence": "confirm your password and card details" }
  ],
  "explanation": "The message pretends to be PayPal's security team and invents an account problem to alarm the reader, then imposes a 24-hour deadline and pushes them toward a link to hand over their password and card details. A genuine bank never asks for credentials this way. The language alone is unambiguous fraud."
}

--- Example 2 (legitimate marketing — note the score) ---------------------
MESSAGE:
Hi Sarah! Our Summer Sale ends this Sunday at midnight. Take an extra 20% off
everything with code SUN20 — don't miss out before these deals are gone. You're
receiving this because you subscribed to Bloom & Co updates. Unsubscribe any
time.

RESPONSE:
{
  "confidence": 0.4,
  "patterns": [
    { "id": "urgency_manipulation", "evidence": "Our Summer Sale ends this Sunday at midnight" },
    { "id": "action_coercion", "evidence": "don't miss out before these deals are gone" }
  ],
  "explanation": "This is an ordinary retail marketing email using a sale deadline to encourage a purchase. The urgency is about a discount, not a threat, and the message asks for no personal information and includes a normal unsubscribe notice. It is legitimate commercial persuasion, so it sits at the top of the promotional band rather than higher."
}

--- Example 3 -------------------------------------------------------------
MESSAGE:
Hey, are we still on for lunch tomorrow at 1? Let me know if you'd rather push
it to Thursday instead.

RESPONSE:
{
  "confidence": 0.03,
  "patterns": [],
  "explanation": "This is a routine personal message arranging lunch. There is no pressure, no request for anything sensitive, and no manipulation of any kind."
}

==========================================================================
Analyse the message provided by the user and respond with JSON only.`;

// ---------------------------------------------------------------------------
// The constrained response schema. The model physically cannot return prose.
// ---------------------------------------------------------------------------

const RESPONSE_SCHEMA: Schema = {
  type: Type.OBJECT,
  properties: {
    confidence: { type: Type.NUMBER },
    patterns: {
      type: Type.ARRAY,
      items: {
        type: Type.OBJECT,
        properties: {
          id: { type: Type.STRING, enum: PATTERN_IDS },
          evidence: { type: Type.STRING },
        },
        required: ["id", "evidence"],
      },
    },
    explanation: { type: Type.STRING },
  },
  required: ["confidence", "patterns", "explanation"],
};

// ---------------------------------------------------------------------------
// Response parsing and the verbatim-evidence guard
// ---------------------------------------------------------------------------

function clamp01(n: number): number {
  if (!Number.isFinite(n)) return 0;
  return Math.min(1, Math.max(0, n));
}

/**
 * The evidence span must be a literal substring of the submitted text. We first
 * try an exact match; if that fails we retry on whitespace-normalised copies, to
 * tolerate the model collapsing a wrapped line into a single space. Anything
 * that still does not match is a paraphrase and is rejected.
 */
function isVerbatimSpan(span: string, text: string): boolean {
  if (!span) return false;
  if (text.includes(span)) return true;
  const norm = (s: string) => s.replace(/\s+/g, " ").trim();
  return norm(text).includes(norm(span));
}

/** A pattern the model returned that the guard rejected, kept for diagnostics. */
export interface DroppedPattern {
  id: unknown;
  evidence: unknown;
  reason: "unknown_id" | "not_verbatim";
}

/** The parsed result plus the patterns the guard dropped. */
export interface AIParse {
  result: AIResult;
  dropped: DroppedPattern[];
}

/**
 * Turn the raw model JSON into an AIResult, dropping (and recording) any pattern
 * that fails validation. The dropped list is not decorative: a model that
 * routinely paraphrases its evidence spans would have its patterns silently
 * stripped here, depressing A across a whole corpus. Surfacing the drop count
 * makes that visible instead of invisible.
 */
export function parseAIResponseDetailed(rawJson: string, submittedText: string): AIParse {
  const data = JSON.parse(rawJson) as {
    confidence?: unknown;
    patterns?: Array<{ id?: unknown; evidence?: unknown }>;
    explanation?: unknown;
  };

  const A = clamp01(Number(data.confidence));
  const explanation = typeof data.explanation === "string" ? data.explanation : "";

  const patterns: DetectedPattern[] = [];
  const dropped: DroppedPattern[] = [];
  for (const p of data.patterns ?? []) {
    const id = p?.id as PatternId;
    if (!PATTERN_LABELS[id]) {
      console.warn(`[ai] dropping pattern with unknown id: ${JSON.stringify(p?.id)}`);
      dropped.push({ id: p?.id, evidence: p?.evidence, reason: "unknown_id" });
      continue;
    }
    const evidence = typeof p?.evidence === "string" ? p.evidence : "";
    if (!isVerbatimSpan(evidence, submittedText)) {
      console.warn(`[ai] dropping ${id}: evidence not found verbatim in submission: ${JSON.stringify(evidence)}`);
      dropped.push({ id, evidence: p?.evidence, reason: "not_verbatim" });
      continue;
    }
    patterns.push({ id, label: PATTERN_LABELS[id], evidence });
  }

  return { result: { A, patterns, explanation }, dropped };
}

/** Convenience wrapper returning only the AIResult (the deployed path). */
export function parseAIResponse(rawJson: string, submittedText: string): AIResult {
  return parseAIResponseDetailed(rawJson, submittedText).result;
}

// ---------------------------------------------------------------------------
// On-disk cache, keyed by SHA-256 of the redacted text
// ---------------------------------------------------------------------------

const CACHE_DIR = process.env.GEMINI_CACHE_DIR ?? join(process.cwd(), ".cache", "gemini");

export function cacheKey(redactedText: string): string {
  return createHash("sha256").update(redactedText, "utf8").digest("hex");
}

function readCache(key: string): AIParse | null {
  try {
    const file = join(CACHE_DIR, `${key}.json`);
    if (!existsSync(file)) return null;
    return JSON.parse(readFileSync(file, "utf8")) as AIParse;
  } catch {
    return null;
  }
}

function writeCache(key: string, parse: AIParse): void {
  try {
    mkdirSync(CACHE_DIR, { recursive: true });
    writeFileSync(join(CACHE_DIR, `${key}.json`), JSON.stringify(parse), "utf8");
  } catch {
    // A cache write failure must never fail an analysis.
  }
}

// ---------------------------------------------------------------------------
// The one call
// ---------------------------------------------------------------------------

function requireEnv(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is not set`);
  return v;
}

/** analyzeText plus diagnostics: the dropped patterns and whether this was a cache hit. */
export interface AIAnalysis extends AIParse {
  cached: boolean;
}

/**
 * Analyse the LANGUAGE of a submission, returning the result AND the guard's
 * dropped patterns. The argument is the redacted text and nothing else — no
 * Features, no URLs, no structural facts.
 *
 * Throws on any API/parse failure. The orchestration layer (the analyze route)
 * catches that and degrades to A = R with aiAvailable: false; this function does
 * not swallow errors, so the caller can tell a real answer from a fallback.
 */
export async function analyzeTextDetailed(redactedText: string): Promise<AIAnalysis> {
  const text = truncateHead(redactedText); // defensive; preprocess already truncates
  const key = cacheKey(text);

  const cached = readCache(key);
  if (cached) return { ...cached, cached: true };

  const apiKey = requireEnv("GEMINI_API_KEY");
  const model = requireEnv("GEMINI_MODEL"); // never hardcode the model string

  const ai = new GoogleGenAI({ apiKey });
  const response = await ai.models.generateContent({
    model,
    contents: text,
    config: {
      temperature: 0,
      systemInstruction: PROMPT_INSTRUCTION,
      responseMimeType: "application/json",
      responseSchema: RESPONSE_SCHEMA,
    },
  });

  const out = response.text;
  if (!out) throw new Error("Gemini returned an empty response");

  const parsed = parseAIResponseDetailed(out, text);
  writeCache(key, parsed);
  return { ...parsed, cached: false };
}

/** The deployed path: the AIResult alone. */
export async function analyzeText(redactedText: string): Promise<AIResult> {
  return (await analyzeTextDetailed(redactedText)).result;
}

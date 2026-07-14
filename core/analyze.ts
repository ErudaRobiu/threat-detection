/**
 * core/analyze.ts
 *
 * The orchestration: raw submission -> AnalysisResult. This is the sequence the
 * whole system exists to run:
 *
 *   preprocess -> runRules -> analyzeText -> fuse -> assemble
 *
 * It lives in /core (not in the route) so it can be exercised without Next, and
 * so the Phase 5 harness could call it directly if it ever needed to.
 *
 * GRACEFUL DEGRADATION (NFR05): the AI layer depends on an external service. If
 * that call fails for any reason — network down, rate limit, service outage —
 * the whole analysis must still complete. We substitute A = R, mark the result
 * aiAvailable: false, and let the fusion proceed. The system stays usable with
 * no internet, which is the condition it is defended under.
 */

import {
  DEFAULT_THRESHOLDS,
  DEFAULT_WEIGHTS,
  type AnalysisResult,
  type ContentType,
  type DetectedPattern,
  type HTSAWeights,
  type Thresholds,
} from "./types";
import { hasAnalysableLanguage, preprocess } from "./preprocess";
import { runRules } from "./rules";
import { analyzeText } from "./ai";
import { fuse } from "./htsa";

/**
 * Thrown when the AI service fails AND the rule engine abstained (a text-only
 * scam analysed while the semantic service is offline). There is real language
 * to read but nothing to degrade to, so we cannot fabricate a verdict. Distinct
 * from NoAnalysableContentError (invalid input): here the content IS analysable,
 * the capability is just unavailable. The route maps this to 503, not 400.
 */
export class AiUnavailableError extends Error {
  constructor(cause: string) {
    super(`AI content analysis is unavailable and the content has no structural indicators to fall back on: ${cause}`);
    this.name = "AiUnavailableError";
  }
}

export interface AnalyzeOptions {
  /** Override auto-detection of the submission type. */
  contentType?: ContentType;
  /** HTSA weights (the settings page passes these to demonstrate the ablation). */
  weights?: HTSAWeights;
  thresholds?: Thresholds;
  /**
   * Set when the raw text came from transcribing image(s). The modality is
   * labelled "image", but preprocess still auto-detects the underlying email /
   * url / text from the transcribed text so the correct indicators apply. This
   * is the transcript that entered the pipeline; it is echoed in the result as
   * the audit trail. The transcriber runs BEFORE analyze — this is just carrying
   * its output through, never re-reading the image.
   */
  transcription?: string | null;
}

const now = () => (typeof performance !== "undefined" ? performance.now() : Date.now());

export async function analyze(raw: string, opts: AnalyzeOptions = {}): Promise<AnalysisResult> {
  const weights = opts.weights ?? DEFAULT_WEIGHTS;
  const thresholds = opts.thresholds ?? DEFAULT_THRESHOLDS;

  const t0 = now();

  // The structural pipeline. preprocess does the network work (WHOIS, TLS) that
  // resolves the facts the rule engine reads, so its cost is attributed to the
  // rule-based layer, not the AI layer.
  const features = await preprocess(raw, opts.contentType);
  const rule = runRules(features);
  const rulesMs = now() - t0;

  // The semantic layer. It abstains (A = null) when the redacted content carries
  // no analysable language — a bare link with nothing to read. This is decided
  // on the CONTENT, not the content type, so a link-only WhatsApp forward pasted
  // as `text` abstains just as a bare URL does.
  let aiScore: number | null;
  let patterns: DetectedPattern[] = [];
  let explanation = "";
  let aiAvailable = true;
  let aiMs = 0;

  if (!hasAnalysableLanguage(features.redactedText)) {
    aiScore = null; // abstain: no words for the semantic layer to judge
  } else {
    const aiStart = now();
    try {
      const ai = await analyzeText(features.redactedText);
      aiScore = ai.A;
      patterns = ai.patterns;
      explanation = ai.explanation;
    } catch (err) {
      aiAvailable = false;
      if (rule.R === null) {
        // Language present, service down, no structural fallback: cannot degrade.
        throw new AiUnavailableError((err as Error).message);
      }
      // Degrade to A = R (NFR05). The aiAvailable flag marks the verdict provisional.
      aiScore = rule.R;
      explanation =
        "AI content analysis was unavailable, so this assessment rests on the structural rule-based layer alone. Treat it as provisional.";
      console.warn(`[analyze] AI layer unavailable, degrading to A = R: ${(err as Error).message}`);
    }
    aiMs = now() - aiStart;
  }

  // May throw NoAnalysableContentError when both layers abstained (junk input);
  // the route turns that into a 400.
  const fusion = fuse(rule.R, aiScore, weights, thresholds);
  const totalMs = now() - t0;

  const fromImage = opts.transcription != null;

  return {
    id: Date.now(),
    contentType: fromImage ? "image" : features.contentType,
    transcription: opts.transcription ?? null,
    ruleScore: rule.R,
    aiScore,
    hybridScore: fusion.H,
    classification: fusion.classification,
    action: fusion.action,
    workings: fusion.workings,
    indicators: rule.indicators,
    patterns,
    explanation,
    aiAvailable,
    weights,
    timings: { rules: Math.round(rulesMs), ai: Math.round(aiMs), total: Math.round(totalMs) },
    createdAt: new Date().toISOString(),
  };
}

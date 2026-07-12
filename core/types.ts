/**
 * core/types.ts
 *
 * The contract. Everything in the system speaks this shape:
 * the API returns it, the React UI renders it, the Python harness parses it.
 * Change it here and everything downstream follows.
 */

export type ContentType = "email" | "url" | "text";

export type RiskLevel = "Low" | "Medium" | "High" | "Critical";

/** The nine rule-based threat indicators from Table 3.5. */
export type IndicatorId =
  | "domain_age"
  | "ssl_certificate"
  | "url_ip_address"
  | "brand_similarity"
  | "subdomain_depth"
  | "email_auth"
  | "reply_to_mismatch"
  | "html_form_in_email"
  | "url_shortener";

/** The six social engineering pattern categories from Table 3.6. */
export type PatternId =
  | "urgency_manipulation"
  | "authority_impersonation"
  | "emotional_exploitation"
  | "credential_harvesting"
  | "financial_manipulation"
  | "action_coercion";

/**
 * Result of evaluating a single rule-based indicator.
 *
 * `applicable` is the key field. Not every indicator applies to every content
 * type: email authentication cannot be checked on a bare URL, and SSL cannot be
 * checked on a text message containing no links. Inapplicable indicators are
 * excluded from the denominator when R is computed (see htsa.ts / rules.ts),
 * which prevents the score floor that would otherwise make it impossible for a
 * URL submission to ever be classified as Low Risk.
 *
 * `passed` is false whenever the check could not be positively satisfied. This
 * includes the indeterminate case: a WHOIS query that returns no record, or a
 * TLS handshake against an unreachable host, is recorded as NOT PASSED rather
 * than as an error or an exclusion. Under the deny-by-default posture, the
 * absence of verification is not equivalent to verification.
 */
export interface IndicatorResult {
  id: IndicatorId;
  label: string;
  weight: number;
  applicable: boolean;
  passed: boolean;
  /** Human-readable justification, shown in the threat report. */
  detail: string;
}

/** A social engineering pattern detected by the AI layer. */
export interface DetectedPattern {
  id: PatternId;
  label: string;
  /** The exact span quoted from the submitted content. This is what makes the report convincing. */
  evidence: string;
}

/** Output of the rule-based engine (layer 1). */
export interface RuleResult {
  /**
   * The rule-based threat score R, in [0, 1]. 1.0 = fully untrusted.
   *
   * null means ABSTENTION: no structural indicator applied to this submission
   * (e.g. a plain text message containing no links and no headers). The rule
   * engine has no evidence, and fabricating a score would be worse than
   * admitting that. HTSA handles this by deferring entirely to the AI layer.
   */
  R: number | null;
  indicators: IndicatorResult[];
  /** Sum of weights over applicable indicators. The denominator in the R formula. */
  applicableWeight: number;
}

/** Output of the AI content analysis module (layer 2). */
export interface AIResult {
  /** The AI confidence score A, in [0, 1]. */
  A: number;
  patterns: DetectedPattern[];
  explanation: string;
}

/** The HTSA weighting configuration. Exposed on the settings page so the ablation can be demonstrated live. */
export interface HTSAWeights {
  alpha: number; // weight on R
  beta: number;  // weight on A
  gamma: number; // weight on the interaction term (the agreement gate)
}

export const DEFAULT_WEIGHTS: HTSAWeights = {
  alpha: 0.4,
  beta: 0.4,
  gamma: 0.2,
};

/** Classification thresholds from Table 3.7. */
export interface Thresholds {
  medium: number; // >= this is Medium Risk
  high: number;   // >= this is High Risk
  critical: number; // >= this is Critical Risk
}

export const DEFAULT_THRESHOLDS: Thresholds = {
  medium: 0.3,
  high: 0.6,
  critical: 0.8,
};

/** Output of the HTSA fusion step. */
export interface FusionResult {
  H: number;
  classification: RiskLevel;
  action: string;
  /** The substituted equation, e.g. "H = 0.4(0.800) + 0.4(0.940) + 0.2(0.800 x 0.940) = 0.846".
   *  Rendered verbatim in the UI. This single string does more work in a defense than three pages of prose. */
  workings: string;
  /** True when the rule engine abstained and H was taken from the AI layer alone. */
  ruleAbstained: boolean;
}

/**
 * Structured features extracted by the preprocessor.
 *
 * Note that the two network-dependent facts (domainAgeDays, sslValid) are
 * resolved HERE, during preprocessing, not inside the rule engine. This keeps
 * runRules() a pure synchronous function of its input, which means it can be
 * unit-tested with no network and no mocking. That matters for the test table
 * in Chapter 4.
 */
export interface Features {
  contentType: ContentType;
  /** The raw text handed to the AI layer. */
  text: string;
  /** Present for email submissions. */
  email?: {
    fromAddress: string | null;
    fromDomain: string | null;
    replyToAddress: string | null;
    replyToDomain: string | null;
    /** Parsed from Authentication-Results / Received-SPF headers. null = header absent. */
    spf: "pass" | "fail" | "none" | null;
    dkim: "pass" | "fail" | "none" | null;
    dmarc: "pass" | "fail" | "none" | null;
    bodyHasCredentialForm: boolean;
  };
  /** Every URL found in the submission. Empty for a text message with no links. */
  urls: UrlFacts[];
}

export interface UrlFacts {
  raw: string;
  hostname: string;
  /** The registrable domain, e.g. "paypa1-verify.com" from "login.paypa1-verify.com". */
  registrableDomain: string;
  /** Labels between the hostname and the registrable domain. */
  subdomainDepth: number;
  hostIsIpAddress: boolean;
  isKnownShortener: boolean;
  /** Days since registration. null = WHOIS lookup failed or returned no record. */
  domainAgeDays: number | null;
  /** true = valid cert. false = missing/expired/self-signed. null = host unreachable. */
  sslValid: boolean | null;
  /** Set when the domain resembles a known brand without being it. */
  brandImpersonation: { brand: string; distance: number } | null;
}

/** The full analysis result. This is the JSON the API returns. */
export interface AnalysisResult {
  id: number;
  contentType: ContentType;
  ruleScore: number | null;
  aiScore: number;
  hybridScore: number;
  classification: RiskLevel;
  action: string;
  workings: string;
  indicators: IndicatorResult[];
  patterns: DetectedPattern[];
  explanation: string;
  /** false = Gemini failed and the system degraded to rule-only (NFR05). */
  aiAvailable: boolean;
  weights: HTSAWeights;
  timings: { rules: number; ai: number; total: number };
  createdAt: string;
}

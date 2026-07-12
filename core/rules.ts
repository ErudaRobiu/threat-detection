/**
 * core/rules.ts
 *
 * The rule-based threat scoring engine (analysis layer 1).
 *
 * ---------------------------------------------------------------------------
 * DENY BY DEFAULT
 * ---------------------------------------------------------------------------
 * Every submission begins at maximum threat (R = 1.0, fully untrusted) and must
 * EARN reductions by positively passing verification checks. This inverts the
 * permissive-by-default model, in which content starts at zero risk and
 * accumulates penalties.
 *
 * ---------------------------------------------------------------------------
 * THE APPLICABILITY NORMALISATION
 * ---------------------------------------------------------------------------
 * The naive formula R = 1 - SUM(w_i * pass_i) is broken. Five of the nine
 * indicators are email-only. On a bare URL submission those five can never
 * pass, so the maximum achievable reduction is only ~0.55, so R can never fall
 * below ~0.45, so NO URL COULD EVER BE CLASSIFIED LOW RISK. The system would
 * flag google.com as Medium Risk.
 *
 * The fix is to normalise over the applicable indicator set only:
 *
 *     R = 1 - [ SUM(w_i * pass_i) over applicable i ]
 *             / [ SUM(w_i)        over applicable i ]
 *
 * This keeps R in [0, 1] for every content type.
 *
 * ---------------------------------------------------------------------------
 * INDETERMINATE CHECKS COUNT AS FAILURES
 * ---------------------------------------------------------------------------
 * If a check cannot be completed (WHOIS returns no record, TLS handshake fails
 * because the host is offline), it is recorded as NOT PASSED. Not as an error,
 * not as an exclusion.
 *
 * This is a direct consequence of the deny-by-default posture: the absence of
 * positive verification is not equivalent to verification. An adversary who
 * suppresses WHOIS data, or who takes a phishing host offline once the campaign
 * has run, must not thereby earn a LOWER threat score than one who leaves the
 * evidence intact.
 *
 * ---------------------------------------------------------------------------
 * PURITY
 * ---------------------------------------------------------------------------
 * runRules() is synchronous and side-effect free. All network-dependent facts
 * (domain age, SSL validity) are resolved upstream by the preprocessor and
 * arrive as plain data. This means the engine can be unit-tested exhaustively
 * with no network, no API key, and no mocking.
 */

import type {
  Features,
  IndicatorId,
  IndicatorResult,
  RuleResult,
  UrlFacts,
} from "./types";

// ---------------------------------------------------------------------------
// Indicator weights (Table 3.5). Sum to 1.000 across the full set.
// ---------------------------------------------------------------------------

export const WEIGHTS: Record<IndicatorId, number> = {
  domain_age: 0.15,
  ssl_certificate: 0.1,
  url_ip_address: 0.12,
  brand_similarity: 0.15,
  subdomain_depth: 0.08,
  email_auth: 0.12,
  reply_to_mismatch: 0.1,
  html_form_in_email: 0.1,
  url_shortener: 0.08,
};

export const LABELS: Record<IndicatorId, string> = {
  domain_age: "Domain age",
  ssl_certificate: "SSL certificate",
  url_ip_address: "IP address in URL",
  brand_similarity: "Brand similarity",
  subdomain_depth: "Subdomain depth",
  email_auth: "Email authentication (SPF/DKIM/DMARC)",
  reply_to_mismatch: "Reply-to mismatch",
  html_form_in_email: "Credential form in body",
  url_shortener: "URL shortener",
};

/** Indicators that require at least one URL to be present in the submission. */
const URL_INDICATORS: IndicatorId[] = [
  "domain_age",
  "ssl_certificate",
  "url_ip_address",
  "brand_similarity",
  "subdomain_depth",
  "url_shortener",
];

/** Indicators that require email headers to be present. */
const EMAIL_INDICATORS: IndicatorId[] = [
  "email_auth",
  "reply_to_mismatch",
  "html_form_in_email",
];

// ---------------------------------------------------------------------------
// Thresholds and reference data
// ---------------------------------------------------------------------------

/** Domains younger than this are treated as suspicious. Phishing infrastructure is typically days old. */
export const MIN_DOMAIN_AGE_DAYS = 30;

/** Subdomain nesting beyond this depth suggests deliberate obfuscation. */
export const MAX_SUBDOMAIN_DEPTH = 3;

/** Levenshtein distance at or below this (but above zero) indicates typosquatting. */
export const BRAND_SIMILARITY_THRESHOLD = 2;

export const SHORTENER_DOMAINS = new Set([
  "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
  "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "rebrand.ly", "bl.ink",
  "short.io", "lnkd.in", "t.ly", "s.id", "shorte.st", "adf.ly", "bitly.com",
]);

/**
 * Brands whose names are commonly impersonated, paired with their legitimate
 * registrable domains. Extend freely; the matcher is generic.
 */
export const BRANDS: { name: string; official: string[] }[] = [
  { name: "paypal", official: ["paypal.com"] },
  { name: "google", official: ["google.com", "google.co.uk"] },
  { name: "microsoft", official: ["microsoft.com", "live.com", "office.com"] },
  { name: "apple", official: ["apple.com", "icloud.com"] },
  { name: "amazon", official: ["amazon.com", "amazon.co.uk"] },
  { name: "facebook", official: ["facebook.com", "fb.com"] },
  { name: "instagram", official: ["instagram.com"] },
  { name: "whatsapp", official: ["whatsapp.com"] },
  { name: "netflix", official: ["netflix.com"] },
  { name: "linkedin", official: ["linkedin.com"] },
  { name: "dropbox", official: ["dropbox.com"] },
  { name: "docusign", official: ["docusign.com", "docusign.net"] },
  { name: "adobe", official: ["adobe.com"] },
  { name: "dhl", official: ["dhl.com"] },
  { name: "fedex", official: ["fedex.com"] },
  { name: "outlook", official: ["outlook.com"] },
  { name: "binance", official: ["binance.com"] },
  { name: "coinbase", official: ["coinbase.com"] },
  { name: "chase", official: ["chase.com"] },
  { name: "hsbc", official: ["hsbc.com", "hsbc.co.uk"] },
  { name: "gtbank", official: ["gtbank.com"] },
  { name: "zenithbank", official: ["zenithbank.com"] },
  { name: "firstbank", official: ["firstbanknigeria.com"] },
  { name: "accessbank", official: ["accessbankplc.com"] },
  { name: "opay", official: ["opayweb.com"] },
  { name: "kuda", official: ["kuda.com"] },
  { name: "palmpay", official: ["palmpay.com"] },
];

// ---------------------------------------------------------------------------
// Text utilities
// ---------------------------------------------------------------------------

/**
 * Standard Levenshtein edit distance (Wagner-Fischer, two-row optimisation).
 * O(m*n) time, O(min(m,n)) space.
 */
export function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  let prev = new Array<number>(b.length + 1);
  let curr = new Array<number>(b.length + 1);

  for (let j = 0; j <= b.length; j++) prev[j] = j;

  for (let i = 1; i <= a.length; i++) {
    curr[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(
        prev[j] + 1,      // deletion
        curr[j - 1] + 1,  // insertion
        prev[j - 1] + cost, // substitution
      );
    }
    [prev, curr] = [curr, prev];
  }
  return prev[b.length];
}

/**
 * Collapse visually confusable characters to their canonical letter.
 *
 * This is what catches "paypa1" (digit one) and "g00gle" (zeroes). Without it,
 * a homoglyph substitution reads as an ordinary edit and can slip under the
 * distance threshold when combined with other changes. Normalising first makes
 * the substitution free, so the comparison sees "paypal" vs "paypal" at
 * distance 0 and correctly identifies exact brand-name impersonation.
 */
const HOMOGLYPHS: Record<string, string> = {
  "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
  "@": "a", "$": "s", "|": "l", "!": "i",
};

export function normaliseHomoglyphs(s: string): string {
  return s.toLowerCase().split("").map((c) => HOMOGLYPHS[c] ?? c).join("");
}

/**
 * Compare a URL's registrable domain against the brand list.
 *
 * Three outcomes:
 *   1. The domain IS an official brand domain             -> no impersonation
 *   2. A label is a near-miss of a brand name (distance 1-2) -> TYPOSQUAT
 *   3. A label IS a brand name exactly, but the domain is
 *      not that brand's official domain                   -> IMPERSONATION
 *      (e.g. "paypal-secure-login.com" contains the exact
 *       string "paypal" but is not paypal.com)
 */
export function detectBrandImpersonation(
  registrableDomain: string,
): { brand: string; distance: number } | null {
  const domain = registrableDomain.toLowerCase();

  for (const b of BRANDS) {
    if (b.official.includes(domain)) return null; // it really is them
  }

  // Split the second-level label into tokens: "paypa1-verify.com" -> ["paypa1", "verify"]
  const sld = domain.split(".")[0] ?? "";
  const tokens = sld.split(/[-_.]+/).filter(Boolean);

  let best: { brand: string; distance: number } | null = null;

  for (const token of tokens) {
    const normalised = normaliseHomoglyphs(token);
    for (const b of BRANDS) {
      // Ignore tokens too short to be a meaningful match against this brand.
      if (Math.abs(normalised.length - b.name.length) > BRAND_SIMILARITY_THRESHOLD) continue;

      const d = levenshtein(normalised, b.name);
      if (d <= BRAND_SIMILARITY_THRESHOLD) {
        if (best === null || d < best.distance) best = { brand: b.name, distance: d };
      }
    }
  }
  return best;
}

// ---------------------------------------------------------------------------
// The engine
// ---------------------------------------------------------------------------

/** Reduce many URLs to a single verdict per indicator: the WORST case wins. */
function worst<T>(urls: UrlFacts[], pick: (u: UrlFacts) => T, isBad: (v: T) => boolean): { bad: boolean; url: UrlFacts | null } {
  for (const u of urls) {
    if (isBad(pick(u))) return { bad: true, url: u };
  }
  return { bad: false, url: null };
}

/**
 * Evaluate all nine indicators and compute R.
 *
 * Pure. Synchronous. No network, no I/O, no clock.
 */
export function runRules(f: Features): RuleResult {
  const urls = f.urls;
  const hasUrls = urls.length > 0;
  const hasEmailHeaders = f.email !== undefined;

  const indicators: IndicatorResult[] = [];

  const add = (
    id: IndicatorId,
    applicable: boolean,
    passed: boolean,
    detail: string,
  ) => {
    indicators.push({
      id,
      label: LABELS[id],
      weight: WEIGHTS[id],
      applicable,
      // An inapplicable indicator can never be "passed"; it is simply excluded.
      passed: applicable ? passed : false,
      detail,
    });
  };

  // -- 1. Domain age -------------------------------------------------------
  // Indeterminate (null) counts as FAILED. A domain hiding its registration
  // record does not get the benefit of the doubt.
  if (!hasUrls) {
    add("domain_age", false, false, "Not applicable: submission contains no URL.");
  } else {
    const unknown = urls.find((u) => u.domainAgeDays === null);
    const young = urls.find((u) => u.domainAgeDays !== null && u.domainAgeDays < MIN_DOMAIN_AGE_DAYS);
    if (young) {
      add("domain_age", true, false,
        `${young.registrableDomain} was registered ${young.domainAgeDays} days ago. Domains under ${MIN_DOMAIN_AGE_DAYS} days old are characteristic of disposable phishing infrastructure.`);
    } else if (unknown) {
      add("domain_age", true, false,
        `Registration date for ${unknown.registrableDomain} could not be established. Under deny-by-default, an unverifiable domain is treated as unverified, not as clean.`);
    } else {
      const oldest = Math.min(...urls.map((u) => u.domainAgeDays as number));
      add("domain_age", true, true, `All domains are established (oldest link is ${oldest} days old).`);
    }
  }

  // -- 2. SSL certificate --------------------------------------------------
  if (!hasUrls) {
    add("ssl_certificate", false, false, "Not applicable: submission contains no URL.");
  } else {
    const bad = urls.find((u) => u.sslValid === false);
    const unreachable = urls.find((u) => u.sslValid === null);
    if (bad) {
      add("ssl_certificate", true, false,
        `${bad.hostname} presents a missing, expired, or self-signed certificate.`);
    } else if (unreachable) {
      add("ssl_certificate", true, false,
        `${unreachable.hostname} could not be reached for TLS verification. Absence of verification is not verification.`);
    } else {
      add("ssl_certificate", true, true, "All linked hosts present a valid TLS certificate.");
    }
  }

  // -- 3. IP address in URL ------------------------------------------------
  if (!hasUrls) {
    add("url_ip_address", false, false, "Not applicable: submission contains no URL.");
  } else {
    const ip = worst(urls, (u) => u.hostIsIpAddress, (v) => v === true);
    add("url_ip_address", true, !ip.bad,
      ip.bad
        ? `The link points directly at the IP address ${ip.url!.hostname} rather than a registered domain name, bypassing domain reputation entirely.`
        : "All links resolve to registered domain names rather than raw IP addresses.");
  }

  // -- 4. Brand similarity -------------------------------------------------
  if (!hasUrls) {
    add("brand_similarity", false, false, "Not applicable: submission contains no URL.");
  } else {
    const imp = urls.find((u) => u.brandImpersonation !== null);
    if (imp) {
      const { brand, distance } = imp.brandImpersonation!;
      add("brand_similarity", true, false,
        distance === 0
          ? `${imp.registrableDomain} contains the brand name "${brand}" but is not an official ${brand} domain.`
          : `${imp.registrableDomain} is ${distance} character edit${distance === 1 ? "" : "s"} away from the brand "${brand}". This is consistent with typosquatting.`);
    } else {
      add("brand_similarity", true, true, "No linked domain resembles a known impersonated brand.");
    }
  }

  // -- 5. Subdomain depth --------------------------------------------------
  if (!hasUrls) {
    add("subdomain_depth", false, false, "Not applicable: submission contains no URL.");
  } else {
    const deep = urls.find((u) => u.subdomainDepth > MAX_SUBDOMAIN_DEPTH);
    add("subdomain_depth", true, !deep,
      deep
        ? `${deep.hostname} nests ${deep.subdomainDepth} subdomain levels. Excessive nesting is used to push the real domain out of view on mobile address bars.`
        : "Subdomain nesting is within normal bounds.");
  }

  // -- 6. Email authentication (SPF / DKIM / DMARC) ------------------------
  // Passing requires SPF to pass AND at least one of DKIM or DMARC to pass.
  // Absent headers are NOT a pass. An unsigned message is unverified.
  if (!hasEmailHeaders) {
    add("email_auth", false, false, "Not applicable: submission is not an email with headers.");
  } else {
    const e = f.email!;
    const spfPass = e.spf === "pass";
    const dkimPass = e.dkim === "pass";
    const dmarcPass = e.dmarc === "pass";
    const passed = spfPass && (dkimPass || dmarcPass);
    const parts = [
      `SPF: ${e.spf ?? "absent"}`,
      `DKIM: ${e.dkim ?? "absent"}`,
      `DMARC: ${e.dmarc ?? "absent"}`,
    ].join(", ");
    add("email_auth", true, passed,
      passed
        ? `Sender authentication verified (${parts}). The sending server is authorised for this domain.`
        : `Sender authentication could not be verified (${parts}). The message cannot be proven to originate from the domain it claims.`);
  }

  // -- 7. Reply-to mismatch ------------------------------------------------
  if (!hasEmailHeaders) {
    add("reply_to_mismatch", false, false, "Not applicable: submission is not an email with headers.");
  } else {
    const e = f.email!;
    if (!e.replyToDomain) {
      add("reply_to_mismatch", true, true, "No separate reply-to address is set.");
    } else {
      const mismatch = e.replyToDomain.toLowerCase() !== (e.fromDomain ?? "").toLowerCase();
      add("reply_to_mismatch", true, !mismatch,
        mismatch
          ? `Replies would be sent to ${e.replyToAddress} (${e.replyToDomain}), not to the apparent sender at ${e.fromDomain}. The response destination is concealed.`
          : "Reply-to address matches the sender domain.");
    }
  }

  // -- 8. Credential form in body -----------------------------------------
  if (!hasEmailHeaders) {
    add("html_form_in_email", false, false, "Not applicable: submission is not an email with headers.");
  } else {
    const bad = f.email!.bodyHasCredentialForm;
    add("html_form_in_email", true, !bad,
      bad
        ? "The message body contains an embedded form with credential input fields. Legitimate organisations do not collect passwords inside an email."
        : "No credential input fields are embedded in the message body.");
  }

  // -- 9. URL shortener ----------------------------------------------------
  if (!hasUrls) {
    add("url_shortener", false, false, "Not applicable: submission contains no URL.");
  } else {
    const s = urls.find((u) => u.isKnownShortener);
    add("url_shortener", true, !s,
      s
        ? `The link uses the shortening service ${s.registrableDomain}, which conceals the true destination until the moment of click.`
        : "No link-shortening services are used.");
  }

  // -- Compute R -----------------------------------------------------------

  const applicable = indicators.filter((i) => i.applicable);
  const applicableWeight = applicable.reduce((s, i) => s + i.weight, 0);

  // ABSTENTION. No structural indicator applies. This happens for a plain text
  // message with no links and no headers: there is simply nothing structural to
  // inspect. Returning R = 1.0 would flag every such message as maximum threat;
  // returning R = 0.0 would clear them all. Both are lies. The engine abstains
  // and HTSA defers to the AI layer.
  if (applicableWeight === 0) {
    return { R: null, indicators, applicableWeight: 0 };
  }

  const earned = applicable.reduce((s, i) => s + (i.passed ? i.weight : 0), 0);
  const R = 1 - earned / applicableWeight;

  return { R, indicators, applicableWeight };
}

/** Convenience: which indicators actually applied, for the report header. */
export function applicableIds(f: Features): IndicatorId[] {
  const ids: IndicatorId[] = [];
  if (f.urls.length > 0) ids.push(...URL_INDICATORS);
  if (f.email !== undefined) ids.push(...EMAIL_INDICATORS);
  return ids;
}

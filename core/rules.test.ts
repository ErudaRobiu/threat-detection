/**
 * core/rules.test.ts
 *
 * Tests for the rule-based engine (layer 1). Every case here is drawn from the
 * Phase 1 acceptance list. The engine is pure, so these run with no network,
 * no API key, and no mocking.
 *
 * The numbers are load-bearing: they are the figures that go into the Chapter 4
 * test table, so they are asserted exactly (to floating-point tolerance).
 */

import { describe, it, expect } from "vitest";
import {
  runRules,
  detectBrandImpersonation,
  normaliseHomoglyphs,
  levenshtein,
  WEIGHTS,
} from "./rules";
import type { Features, UrlFacts } from "./types";

// ---------------------------------------------------------------------------
// Builders. These fabricate the preprocessor's output directly, so a test can
// set any structural fact without needing WHOIS, TLS, or a real parser.
// A field left unset defaults to the CLEANEST possible value, so each test only
// has to specify the facts it cares about.
// ---------------------------------------------------------------------------

function url(overrides: Partial<UrlFacts> = {}): UrlFacts {
  return {
    raw: "https://example.com",
    hostname: "example.com",
    registrableDomain: "example.com",
    subdomainDepth: 0,
    hostIsIpAddress: false,
    isKnownShortener: false,
    domainAgeDays: 3650, // ~10 years old: clean
    sslValid: true,
    brandImpersonation: null,
    ...overrides,
  };
}

function emailFeatures(overrides: Partial<NonNullable<Features["email"]>> = {}, urls: UrlFacts[] = []): Features {
  return {
    contentType: "email",
    text: "sample email body",
    email: {
      fromAddress: "someone@example.com",
      fromDomain: "example.com",
      replyToAddress: null,
      replyToDomain: null,
      spf: "pass",
      dkim: "pass",
      dmarc: "pass",
      bodyHasCredentialForm: false,
      ...overrides,
    },
    urls,
  };
}

function urlFeatures(urls: UrlFacts[]): Features {
  return { contentType: "url", text: urls.map((u) => u.raw).join(" "), urls };
}

function textFeatures(text: string): Features {
  return { contentType: "text", text, urls: [] };
}

/** Sum of the weights of the indicators that PASSED. */
function earnedWeight(indicators: { passed: boolean; weight: number }[]): number {
  return indicators.filter((i) => i.passed).reduce((s, i) => s + i.weight, 0);
}

// ---------------------------------------------------------------------------
// Case: obvious phishing email. All nine indicators applicable. R = 0.800.
// ---------------------------------------------------------------------------

describe("phishing email — all nine indicators applicable", () => {
  // Two URLs, so a single indicator's "worst case wins" logic is exercised:
  //   URL 1: paypa1-verify.example — young domain, invalid TLS, brand impersonation
  //   URL 2: bit.ly/x              — a known shortener
  // Only IP-in-URL (0.12) and subdomain depth (0.08) pass -> earned = 0.20.
  const features = emailFeatures(
    {
      fromDomain: "paypa1-verify.example",
      replyToAddress: "collector@mailbox.ru",
      replyToDomain: "mailbox.ru", // mismatch -> fail
      spf: "fail", // -> email_auth fail
      dkim: "none",
      dmarc: "none",
      bodyHasCredentialForm: true, // -> html_form_in_email fail
    },
    [
      url({
        raw: "https://paypa1-verify.example/login",
        hostname: "paypa1-verify.example",
        registrableDomain: "paypa1-verify.example",
        domainAgeDays: 3, // fail domain_age
        sslValid: false, // fail ssl_certificate
        brandImpersonation: { brand: "paypal", distance: 0 }, // fail brand_similarity
      }),
      url({
        raw: "https://bit.ly/abc123",
        hostname: "bit.ly",
        registrableDomain: "bit.ly",
        isKnownShortener: true, // fail url_shortener
      }),
    ],
  );

  const result = runRules(features);

  it("marks all nine indicators applicable", () => {
    expect(result.indicators).toHaveLength(9);
    expect(result.indicators.every((i) => i.applicable)).toBe(true);
    expect(result.applicableWeight).toBeCloseTo(1.0, 9);
  });

  it("only IP-in-URL and subdomain depth pass (earned = 0.20)", () => {
    expect(earnedWeight(result.indicators)).toBeCloseTo(0.2, 9);
    const passed = result.indicators.filter((i) => i.passed).map((i) => i.id).sort();
    expect(passed).toEqual(["subdomain_depth", "url_ip_address"]);
  });

  it("R = 0.800", () => {
    expect(result.R).toBeCloseTo(0.8, 9);
  });
});

// ---------------------------------------------------------------------------
// Case: google.com. URL-only. Six applicable. R = 0.000 -> Low.
// ---------------------------------------------------------------------------

describe("google.com — clean URL submission", () => {
  const features = urlFeatures([
    url({
      raw: "https://google.com",
      hostname: "google.com",
      registrableDomain: "google.com",
      domainAgeDays: 9999,
      sslValid: true,
      brandImpersonation: null, // it really IS google
    }),
  ]);

  const result = runRules(features);

  it("has six applicable indicators (the URL set), three not applicable", () => {
    const applicable = result.indicators.filter((i) => i.applicable);
    expect(applicable).toHaveLength(6);
    expect(result.indicators.filter((i) => !i.applicable)).toHaveLength(3);
    expect(result.applicableWeight).toBeCloseTo(0.68, 9);
  });

  it("all applicable indicators pass, so R = 0.000", () => {
    expect(result.R).toBeCloseTo(0.0, 9);
  });
});

// ---------------------------------------------------------------------------
// Case: THE DEFECT. Same google.com input under the naive un-normalised
// formula R = 1 - SUM(w * pass) over ALL NINE indicators. The three email
// indicators can never pass on a URL, so their 0.32 of weight is stranded and
// R floors at 0.320 -> Medium Risk. This is the bug the normalisation fixes.
// It is kept as a regression guard: the normalised engine must NOT reproduce it.
// ---------------------------------------------------------------------------

describe("google.com — un-normalised formula documents the misclassification", () => {
  const features = urlFeatures([
    url({
      raw: "https://google.com",
      hostname: "google.com",
      registrableDomain: "google.com",
      domainAgeDays: 9999,
      sslValid: true,
      brandImpersonation: null,
    }),
  ]);

  const result = runRules(features);

  it("naive R (denominator = all nine weights) = 0.320, a Medium-Risk false positive", () => {
    // The naive formula ignores applicability: it divides by the full weight
    // set (which sums to 1.0), so R = 1 - earned.
    const naiveR = 1 - earnedWeight(result.indicators);
    expect(naiveR).toBeCloseTo(0.32, 9);
    expect(naiveR).toBeGreaterThanOrEqual(0.3); // >= Medium threshold: the bug
  });

  it("the normalised engine does NOT reproduce the defect", () => {
    expect(result.R).toBeCloseTo(0.0, 9);
    expect(result.R!).toBeLessThan(0.3); // Low: the fix
  });
});

// ---------------------------------------------------------------------------
// Case: plain text, no URL, no headers. Empty applicable set -> ABSTENTION.
// ---------------------------------------------------------------------------

describe("plain text message — abstention", () => {
  const result = runRules(textFeatures("Hey, are we still on for lunch tomorrow?"));

  it("returns R = null (not 0, not 1) and zero applicable weight", () => {
    expect(result.R).toBeNull();
    expect(result.applicableWeight).toBe(0);
    expect(result.indicators.every((i) => !i.applicable)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Brand impersonation: homoglyph normalisation and Levenshtein distance.
// ---------------------------------------------------------------------------

describe("brand impersonation detection", () => {
  it("paypa1-verify.com impersonates paypal at normalised distance 0", () => {
    const imp = detectBrandImpersonation("paypa1-verify.com");
    expect(imp).toEqual({ brand: "paypal", distance: 0 });
  });

  it("the homoglyph fold is what makes it distance 0 (raw distance is 1)", () => {
    // Without normalisation, "paypa1" is one substitution from "paypal".
    expect(levenshtein("paypa1", "paypal")).toBe(1);
    // After the fold, the digit 1 becomes l, so it is the brand name exactly.
    expect(normaliseHomoglyphs("paypa1")).toBe("paypal");
    expect(levenshtein(normaliseHomoglyphs("paypa1"), "paypal")).toBe(0);
  });

  it("microsotf.com impersonates microsoft at distance 2 (typosquat)", () => {
    const imp = detectBrandImpersonation("microsotf.com");
    expect(imp).toEqual({ brand: "microsoft", distance: 2 });
  });

  it("google.com is not flagged (it is the official domain)", () => {
    expect(detectBrandImpersonation("google.com")).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Email authentication has THREE states, not two. Absent headers are
// INAPPLICABLE (no check was ever performed), not FAILED — the same distinction
// drawn for WHOIS. This stops a pre-DMARC legitimate email being penalised for
// the non-existence of a protocol.
// ---------------------------------------------------------------------------

describe("email authentication applicability (three states)", () => {
  const auth = (o: Partial<NonNullable<Features["email"]>>) =>
    runRules(emailFeatures(o)).indicators.find((i) => i.id === "email_auth")!;

  it("present + pass -> applicable, passed", () => {
    const a = auth({ spf: "pass", dkim: "pass", dmarc: "pass" });
    expect(a.applicable).toBe(true);
    expect(a.passed).toBe(true);
  });

  it("present + fail -> applicable, failed", () => {
    const a = auth({ spf: "fail", dkim: "none", dmarc: "fail" });
    expect(a.applicable).toBe(true);
    expect(a.passed).toBe(false);
  });

  it("absent entirely -> INAPPLICABLE, not failed (the pre-DMARC case)", () => {
    const a = auth({ spf: null, dkim: null, dmarc: null });
    expect(a.applicable).toBe(false);
  });

  it("a clean email with no auth headers scores R = 0 (email_auth excluded from the denominator)", () => {
    // email_auth inapplicable -> R normalises over reply_to_mismatch + html_form,
    // both of which pass -> R = 0, not 0.375.
    expect(runRules(emailFeatures({ spf: null, dkim: null, dmarc: null })).R).toBeCloseTo(0, 9);
  });
});

// ---------------------------------------------------------------------------
// Sanity: the indicator weights sum to 1.000 across the full set (Table 3.5).
// ---------------------------------------------------------------------------

describe("weights", () => {
  it("sum to 1.000 across all nine indicators", () => {
    const total = Object.values(WEIGHTS).reduce((s, w) => s + w, 0);
    expect(total).toBeCloseTo(1.0, 9);
  });
});

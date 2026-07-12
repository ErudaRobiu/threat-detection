/**
 * core/preprocess.test.ts
 *
 * Tests for the PURE parts of preprocessing: redaction, truncation, and content
 * type detection. The network-dependent parts (WHOIS, TLS, MIME parsing) are not
 * exercised here — they are integration surface, not unit surface.
 *
 * Redaction is the load-bearing test in this file. It is the mechanism that
 * keeps the AI layer structurally blind, so these assertions are the executable
 * proof that a typosquat domain cannot leak into the text the AI reads.
 */

import { describe, it, expect } from "vitest";
import {
  redactLinks,
  truncateHead,
  toRedactedText,
  detectContentType,
  extractUrlStrings,
  REDACTION_TOKEN,
  MAX_AI_INPUT_CHARS,
} from "./preprocess";

describe("redaction — structural blindness", () => {
  it("replaces an http(s) URL with the token", () => {
    expect(redactLinks("Log in at https://paypa1-verify.com/login now")).toBe(
      "Log in at [LINK] now",
    );
  });

  it("hides the typosquat domain the rule engine scores (brand_similarity)", () => {
    const out = redactLinks("Verify here: http://paypa1-verify.com/login");
    expect(out).not.toContain("paypa1");
    expect(out).not.toContain("paypal");
    expect(out).toContain(REDACTION_TOKEN);
  });

  it("redacts www hosts and bare registrable domains", () => {
    expect(redactLinks("Go to www.evil.example.com or evil-bank.com today")).toBe(
      "Go to [LINK] or [LINK] today",
    );
  });

  it("redacts email addresses to a DISTINCT token (a different linguistic signal)", () => {
    expect(redactLinks("Reply to security@paypa1-verify.com to confirm")).toBe(
      "Reply to [EMAIL] to confirm",
    );
  });

  it("PRESERVES that a link exists — the action_coercion signal survives", () => {
    const out = redactLinks("Confirm your password and card details here: https://x.co/a");
    expect(out).toBe("Confirm your password and card details here: [LINK]");
  });

  it("does not eat ordinary prose that merely contains dots", () => {
    const text = "We shipped it in Node.js (see e.g. report.pdf) at 3.14 today.";
    // None of these are real registrable domains, so nothing is redacted.
    expect(redactLinks(text)).toBe(text);
  });

  it("collapses a URL and its split path into a single token", () => {
    const out = redactLinks("here: https://a.com/very/long/path?x=1");
    expect(out).toBe("here: [LINK]");
    expect((out.match(/\[LINK\]/g) ?? []).length).toBe(1);
  });

  it("brand names in prose stay visible — that is the AI's job, not infrastructure", () => {
    // "PayPal Security" as a salutation is authority_impersonation (language).
    // Only the DOMAIN is redacted.
    const out = redactLinks("PayPal Security: confirm at paypa1-verify.com");
    expect(out).toContain("PayPal Security");
    expect(out).not.toContain("paypa1-verify.com");
  });
});

describe("truncation", () => {
  it("leaves short text untouched", () => {
    expect(truncateHead("short")).toBe("short");
  });

  it("keeps the head and marks the cut when over the limit", () => {
    const long = "a".repeat(MAX_AI_INPUT_CHARS + 500);
    const out = truncateHead(long);
    expect(out.startsWith("a".repeat(MAX_AI_INPUT_CHARS))).toBe(true);
    expect(out).toContain("[...truncated...]");
    expect(out.length).toBeLessThan(long.length);
  });

  it("toRedactedText redacts first, then truncates — no partial domain can survive", () => {
    const body = `Read more at https://evil-bank.com/${"x".repeat(MAX_AI_INPUT_CHARS)}`;
    const out = toRedactedText(body);
    expect(out).not.toContain("evil-bank");
    expect(out).toContain(REDACTION_TOKEN);
  });
});

describe("content-type detection", () => {
  it("detects an email by its headers", () => {
    const raw = "From: a@b.com\nTo: c@d.com\nSubject: hi\n\nbody";
    expect(detectContentType(raw)).toBe("email");
  });

  it("detects a bare URL submission", () => {
    expect(detectContentType("https://example.com/path")).toBe("url");
    expect(detectContentType("example.com")).toBe("url");
  });

  it("treats prose as text even when it contains a link", () => {
    expect(detectContentType("Hey check out https://example.com when you can")).toBe("text");
  });
});

describe("URL extraction", () => {
  it("pulls out every distinct URL/host and sheds trailing punctuation", () => {
    const urls = extractUrlStrings("See https://a.com/x, and b-bank.com. Also https://a.com/x again.");
    expect(urls).toContain("https://a.com/x");
    expect(urls).toContain("b-bank.com");
    // de-duplicated
    expect(urls.filter((u) => u === "https://a.com/x")).toHaveLength(1);
  });

  it("does not mistake an email's domain tail for a standalone URL", () => {
    const urls = extractUrlStrings("Reply to security@paypa1-verify.com only");
    expect(urls).not.toContain("paypa1-verify.com");
  });
});

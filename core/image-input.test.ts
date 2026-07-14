/**
 * core/image-input.test.ts
 *
 * Image input is a two-stage design: transcribe the image to text (Stage 1),
 * then run the ordinary pipeline on that text (Stage 2). Stage 1 hits the Gemini
 * vision model, so the assertion that transcription preserves a homoglyph digit
 * (e.g. "paypa1" with the digit one) is an INTEGRATION check — see
 * eval/transcribe-probe.ts, run against a real fixture screenshot.
 *
 * These tests cover the PURE half: given the text a correct transcription would
 * produce, the rule engine must still catch the typosquat, and — critically —
 * the redacted text handed to the AI must NOT contain the domain.
 */

import { describe, it, expect } from "vitest";
import { toRedactedText, extractUrlStrings } from "./preprocess";
import { detectBrandImpersonation } from "./rules";

// What a correct transcription of a PayPal phishing screenshot looks like. The
// typosquat "paypa1-verify.com" uses the digit ONE — the transcriber must not
// have "helpfully" repaired it to "paypal".
const TRANSCRIBED = `From: PayPal Service <service@paypa1-verify.com>
Subject: Your account has been limited

We detected unusual activity on your account. Verify your identity within 24
hours to avoid suspension: http://paypa1-verify.com/login`;

describe("image input — the transcribed typosquat still reaches the rule engine", () => {
  it("the URL is extracted from the transcribed text", () => {
    expect(extractUrlStrings(TRANSCRIBED)).toContain("http://paypa1-verify.com/login");
  });

  it("brand impersonation fires on the extracted domain (homoglyph → paypal, distance 0)", () => {
    expect(detectBrandImpersonation("paypa1-verify.com")).toEqual({ brand: "paypal", distance: 0 });
  });
});

// ---------------------------------------------------------------------------
// THE BLINDNESS REGRESSION GUARD. Do not "optimise" this away.
//
// The whole reason image input is two stages is that a screenshot SHOWS the
// domain, and if that domain reached the semantic layer the AI would score the
// same signal the rule engine scores (brand_similarity), R and A would stop
// being independent, and the agreement gate would measure redundancy instead of
// corroboration. Redaction is what keeps them independent. This test proves the
// domain is gone from the text the AI is handed — for image input exactly as for
// pasted text, because the transcriber sits BEFORE preprocess, not inside it.
// ---------------------------------------------------------------------------

describe("image input — the AI never sees the transcribed domain (blindness holds)", () => {
  const redacted = toRedactedText(TRANSCRIBED);

  it("the redacted text carries the tokens, proving a link and an address were present", () => {
    expect(redacted).toContain("[LINK]");
    expect(redacted).toContain("[EMAIL]");
  });

  it("the redacted text does NOT contain the domain, the brand, or the raw URL", () => {
    expect(redacted).not.toContain("paypa1-verify.com");
    expect(redacted).not.toContain("paypa1");
    expect(redacted).not.toContain("paypal");
    expect(redacted).not.toContain("http://");
  });
});

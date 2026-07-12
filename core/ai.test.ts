/**
 * core/ai.test.ts
 *
 * Tests for the PURE part of the AI layer: response parsing and the
 * verbatim-evidence guard. No network, no API key — parseAIResponse is a pure
 * function of (model JSON, submitted text).
 *
 * The evidence guard is the important one: it is what stops a paraphrased or
 * hallucinated quote reaching the threat report. Every rendered evidence span
 * is guaranteed to be a literal substring of what the user submitted.
 */

import { describe, it, expect } from "vitest";
import { parseAIResponse, PATTERN_LABELS } from "./ai";

const SUBMISSION =
  "PayPal Security: verify your identity within 24 hours or your account will be permanently suspended. Confirm your password here: [LINK]";

describe("parseAIResponse — valid response", () => {
  const raw = JSON.stringify({
    confidence: 0.96,
    patterns: [
      { id: "authority_impersonation", evidence: "PayPal Security" },
      { id: "urgency_manipulation", evidence: "verify your identity within 24 hours" },
    ],
    explanation: "Impersonates PayPal and manufactures urgency.",
  });

  const result = parseAIResponse(raw, SUBMISSION);

  it("maps confidence to A", () => {
    expect(result.A).toBeCloseTo(0.96, 9);
  });

  it("attaches the canonical label from the id (the model never supplies labels)", () => {
    expect(result.patterns[0]).toEqual({
      id: "authority_impersonation",
      label: PATTERN_LABELS.authority_impersonation,
      evidence: "PayPal Security",
    });
  });

  it("keeps the explanation", () => {
    expect(result.explanation).toBe("Impersonates PayPal and manufactures urgency.");
  });
});

describe("parseAIResponse — the verbatim-evidence guard", () => {
  it("drops a pattern whose evidence is a paraphrase, keeping the valid one", () => {
    const raw = JSON.stringify({
      confidence: 0.9,
      patterns: [
        { id: "urgency_manipulation", evidence: "verify your identity within 24 hours" }, // verbatim -> kept
        { id: "credential_harvesting", evidence: "they ask for your password" }, // paraphrase -> dropped
      ],
      explanation: "x",
    });
    const result = parseAIResponse(raw, SUBMISSION);
    expect(result.patterns).toHaveLength(1);
    expect(result.patterns[0].id).toBe("urgency_manipulation");
  });

  it("accepts evidence that differs only by collapsed whitespace (wrapped line)", () => {
    const submission = "verify your identity\nwithin 24 hours";
    const raw = JSON.stringify({
      confidence: 0.7,
      patterns: [{ id: "urgency_manipulation", evidence: "verify your identity within 24 hours" }],
      explanation: "x",
    });
    const result = parseAIResponse(raw, submission);
    expect(result.patterns).toHaveLength(1);
  });

  it("drops a pattern with an unknown id", () => {
    const raw = JSON.stringify({
      confidence: 0.5,
      patterns: [{ id: "not_a_real_category", evidence: "PayPal Security" }],
      explanation: "x",
    });
    expect(parseAIResponse(raw, SUBMISSION).patterns).toHaveLength(0);
  });
});

describe("parseAIResponse — defensive coercion", () => {
  it("clamps confidence into [0, 1]", () => {
    expect(parseAIResponse(JSON.stringify({ confidence: 1.5, patterns: [], explanation: "" }), "x").A).toBe(1);
    expect(parseAIResponse(JSON.stringify({ confidence: -0.2, patterns: [], explanation: "" }), "x").A).toBe(0);
  });

  it("treats a non-numeric confidence as 0", () => {
    expect(parseAIResponse(JSON.stringify({ confidence: null, patterns: [], explanation: "" }), "x").A).toBe(0);
  });

  it("tolerates a missing patterns array", () => {
    expect(parseAIResponse(JSON.stringify({ confidence: 0.3, explanation: "x" }), "x").patterns).toEqual([]);
  });
});

/**
 * core/htsa.test.ts
 *
 * Tests for the Hybrid Threat Scoring Algorithm (the fusion step). These assert
 * the two facts the whole project turns on:
 *   1. When both layers agree on a threat, H reaches the top of the range.
 *   2. When the layers disagree, the interaction term holds H DOWN, below a
 *      simple average, suppressing the false positive.
 *
 * The worked example from htsa.ts (R=0.18, A=0.45) is reproduced under both the
 * ablation weights (gamma=0) and the real weights (gamma=0.2) to show the
 * classification flip. This is the ablation, in a unit test.
 */

import { describe, it, expect } from "vitest";
import { fuse, gateSuppression, ABLATION_WEIGHTS, NoAnalysableContentError } from "./htsa";
import { DEFAULT_WEIGHTS } from "./types";

// ---------------------------------------------------------------------------
// Agreement: both layers register a threat. H rises to the top of the range.
// R = 0.800 (from the phishing-email rule test), A = 0.94.
// H = 0.4(0.8) + 0.4(0.94) + 0.2(0.8 x 0.94) = 0.846 -> Critical.
// ---------------------------------------------------------------------------

describe("both layers agree — the gate opens", () => {
  const result = fuse(0.8, 0.94, DEFAULT_WEIGHTS);

  it("H = 0.846", () => {
    expect(result.H).toBeCloseTo(0.846, 3);
  });

  it("classifies Critical", () => {
    expect(result.classification).toBe("Critical");
  });

  it("renders the substituted equation verbatim for the report", () => {
    expect(result.ruleAbstained).toBe(false);
    expect(result.workings).toContain("0.4(0.800)");
    expect(result.workings).toContain("0.94");
    expect(result.workings).toContain("0.846");
  });

  it("H never exceeds the simple mean of the two scores", () => {
    const mean = (0.8 + 0.94) / 2; // 0.870
    expect(result.H).toBeLessThanOrEqual(mean);
  });
});

// ---------------------------------------------------------------------------
// Disagreement: the borderline marketing email. R = 0.18, A = 0.45.
// This is the project's central worked example. Under the ablation (gamma = 0)
// it is a Medium-Risk false positive; under the real weights (gamma = 0.2) the
// agreement gate pulls it below 0.3 and it is correctly cleared to Low.
// ---------------------------------------------------------------------------

describe("layers disagree — the agreement gate suppresses the false positive", () => {
  it("ablation (gamma = 0): H = 0.315 -> Medium Risk (FALSE POSITIVE)", () => {
    const result = fuse(0.18, 0.45, ABLATION_WEIGHTS);
    expect(result.H).toBeCloseTo(0.315, 3);
    expect(result.classification).toBe("Medium");
  });

  it("real system (gamma = 0.2): H = 0.268 -> Low Risk (CORRECT)", () => {
    const result = fuse(0.18, 0.45, DEFAULT_WEIGHTS);
    expect(result.H).toBeCloseTo(0.268, 3);
    expect(result.classification).toBe("Low");
  });

  it("the interaction term is what moved it across the 0.3 threshold", () => {
    const ablation = fuse(0.18, 0.45, ABLATION_WEIGHTS).H;
    const real = fuse(0.18, 0.45, DEFAULT_WEIGHTS).H;
    expect(ablation).toBeGreaterThanOrEqual(0.3); // flagged
    expect(real).toBeLessThan(0.3); // cleared
    // The gate suppression equals the gap between the ablation mean and real H.
    expect(gateSuppression(0.18, 0.45)).toBeCloseTo(ablation - real, 9);
  });
});

// ---------------------------------------------------------------------------
// Abstention: the rule engine returned null. HTSA defers entirely to the AI.
// ---------------------------------------------------------------------------

describe("rule abstention — H = A", () => {
  const result = fuse(null, 0.62, DEFAULT_WEIGHTS);

  it("H equals A exactly", () => {
    expect(result.H).toBe(0.62);
    expect(result.ruleAbstained).toBe(true);
    expect(result.aiAbstained).toBe(false);
  });

  it("classifies on A alone and says so in the workings", () => {
    expect(result.classification).toBe("High"); // 0.62 >= 0.6
    expect(result.workings).toContain("H = A");
  });
});

// ---------------------------------------------------------------------------
// Semantic abstention: A = null (a bare link, no analysable language). HTSA
// defers to the rule engine. This is what lets a typosquat URL reach a real
// verdict instead of being cleared to Low by A = 0 misread as "safe".
// ---------------------------------------------------------------------------

describe("semantic abstention — H = R", () => {
  const result = fuse(0.59, null, DEFAULT_WEIGHTS);

  it("H equals R exactly (not suppressed by a fabricated A = 0)", () => {
    expect(result.H).toBeCloseTo(0.59, 9);
    expect(result.aiAbstained).toBe(true);
    expect(result.ruleAbstained).toBe(false);
  });

  it("classifies on R alone and says so in the workings", () => {
    expect(result.classification).toBe("Medium"); // 0.59 >= 0.3, < 0.6
    expect(result.workings).toContain("H = R");
    expect(result.workings).toContain("semantic layer");
  });

  it("a clean bare URL (R = 0) still clears to Low", () => {
    expect(fuse(0, null).classification).toBe("Low");
  });

  it("distinguishes a typosquat from a clean URL, which A = 0 fusion could not", () => {
    expect(fuse(0.59, null).classification).toBe("Medium"); // typosquat: flagged
    expect(fuse(0.0, null).classification).toBe("Low"); // google.com: cleared
  });
});

// ---------------------------------------------------------------------------
// Both layers abstain: junk input. Nothing to fuse. Must throw, never return 0.
// ---------------------------------------------------------------------------

describe("both layers abstain — rejected, not zeroed", () => {
  it("throws NoAnalysableContentError rather than returning H = 0", () => {
    expect(() => fuse(null, null)).toThrow(NoAnalysableContentError);
  });
});

// ---------------------------------------------------------------------------
// The structural guarantee: H <= mean(R, A) for ALL inputs. Never amplifies.
// ---------------------------------------------------------------------------

describe("H never amplifies — soft-AND guarantee", () => {
  it("H <= mean(R, A) across a grid of inputs", () => {
    for (let r = 0; r <= 1.0001; r += 0.1) {
      for (let a = 0; a <= 1.0001; a += 0.1) {
        const R = Math.min(1, r);
        const A = Math.min(1, a);
        const H = fuse(R, A, DEFAULT_WEIGHTS).H;
        const mean = (R + A) / 2;
        expect(H).toBeLessThanOrEqual(mean + 1e-9);
      }
    }
  });
});

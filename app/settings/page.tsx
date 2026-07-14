"use client";

import { useState } from "react";
import { fuse } from "@/core/htsa";
import type { HTSAWeights, RiskLevel, Thresholds } from "@/core/types";
import { DEFAULT_WEIGHTS, DEFAULT_THRESHOLDS } from "@/core/types";

// The canonical borderline worked example (htsa.ts / the report). It is what
// makes the ablation visible: at gamma = 0.2 it clears to Low; drag gamma to 0
// and the simple average pushes it back over 0.3 into Medium.
const EXAMPLE_R = 0.18;
const EXAMPLE_A = 0.45;

const riskClass: Record<RiskLevel, string> = {
  Low: "risk-low",
  Medium: "risk-medium",
  High: "risk-high",
  Critical: "risk-critical",
};
const riskColor: Record<RiskLevel, string> = {
  Low: "var(--green)",
  Medium: "var(--amber)",
  High: "var(--orange)",
  Critical: "var(--red)",
};

function Slider({
  label,
  value,
  min,
  max,
  step,
  onChange,
}: {
  label: string;
  value: number;
  min: number;
  max: number;
  step: number;
  onChange: (v: number) => void;
}) {
  return (
    <div className="slider-row">
      <div className="srow-head">
        <span>{label}</span>
        <span className="sval">{value.toFixed(2)}</span>
      </div>
      <input type="range" min={min} max={max} step={step} value={value} onChange={(e) => onChange(Number(e.target.value))} />
    </div>
  );
}

export default function SettingsPage() {
  const [weights, setWeights] = useState<HTSAWeights>({ ...DEFAULT_WEIGHTS });
  const [thresholds, setThresholds] = useState<Thresholds>({ ...DEFAULT_THRESHOLDS });

  const result = fuse(EXAMPLE_R, EXAMPLE_A, weights, thresholds);
  const setW = (k: keyof HTSAWeights) => (v: number) => setWeights((w) => ({ ...w, [k]: v }));
  const setT = (k: keyof Thresholds) => (v: number) => setThresholds((t) => ({ ...t, [k]: v }));

  return (
    <div className="settings-grid">
      {/* Controls */}
      <div className="card">
        <div className="block-title">HTSA weights</div>
        <Slider label="alpha · weight on R" value={weights.alpha} min={0} max={1} step={0.05} onChange={setW("alpha")} />
        <Slider label="beta · weight on A" value={weights.beta} min={0} max={1} step={0.05} onChange={setW("beta")} />
        <Slider label="gamma · interaction (the agreement gate)" value={weights.gamma} min={0} max={0.5} step={0.05} onChange={setW("gamma")} />

        <div className="block-title" style={{ marginTop: 24 }}>
          Classification thresholds
        </div>
        <Slider label="medium ≥" value={thresholds.medium} min={0} max={1} step={0.05} onChange={setT("medium")} />
        <Slider label="high ≥" value={thresholds.high} min={0} max={1} step={0.05} onChange={setT("high")} />
        <Slider label="critical ≥" value={thresholds.critical} min={0} max={1} step={0.05} onChange={setT("critical")} />

        <p className="settings-note" style={{ marginTop: 20 }}>
          Weights are normalised to sum to 1 before fusion, so dragging gamma to 0 with alpha and beta at 0.4 reproduces the
          ablation (0.5 / 0.5 / 0). Watch the badge flip.
        </p>
        <button
          className="analyse-btn"
          style={{ marginTop: 8, width: "auto", padding: "8px 16px" }}
          onClick={() => {
            setWeights({ ...DEFAULT_WEIGHTS });
            setThresholds({ ...DEFAULT_THRESHOLDS });
          }}
        >
          Reset to defaults
        </button>
      </div>

      {/* Live preview */}
      <div className="card">
        <div className="block-title">Live ablation — borderline example</div>
        <div className="tiles" style={{ marginBottom: 20 }}>
          <div className="tile">
            <div className="tlabel">R · rule</div>
            <div className="tval mono" style={{ color: "var(--amber)" }}>
              {EXAMPLE_R.toFixed(3)}
            </div>
            <div className="tcap">structurally clean</div>
          </div>
          <div className="tile">
            <div className="tlabel">A · ai</div>
            <div className="tval mono" style={{ color: "var(--amber)" }}>
              {EXAMPLE_A.toFixed(3)}
            </div>
            <div className="tcap">mildly persuasive</div>
          </div>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 16, marginBottom: 18 }}>
          <span
            className={`badge ${riskClass[result.classification]}`}
            style={{ borderColor: riskColor[result.classification], color: riskColor[result.classification] }}
          >
            {result.classification} risk
          </span>
          <span className="mono" style={{ fontSize: 24, fontWeight: 600, color: riskColor[result.classification] }}>
            {result.H.toFixed(3)}
          </span>
        </div>

        <div className="fusion" style={{ marginBottom: 18 }}>
          <div className="fusion-track" style={{ marginTop: 0 }}>
            <div
              className="fusion-fill"
              style={{ width: `${result.H * 100}%`, background: riskColor[result.classification], transition: "width 200ms, background 200ms" }}
            />
          </div>
        </div>

        <div className="equation">
          {result.workings.split("\n").map((ln, i, arr) => (
            <div key={i} style={i === arr.length - 1 ? { color: riskColor[result.classification], fontWeight: 700 } : undefined}>
              {ln}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

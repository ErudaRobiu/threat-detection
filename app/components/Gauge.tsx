"use client";

import { useEffect, useState } from "react";
import type { RiskLevel } from "@/core/types";

const RADIUS = 92;
const LEN = Math.PI * RADIUS; // semicircle arc length
const PATH = `M 18 118 A ${RADIUS} ${RADIUS} 0 0 1 202 118`; // top semicircle, left -> right

function riskVar(v: number): string {
  if (v >= 0.8) return "var(--red)";
  if (v >= 0.6) return "var(--orange)";
  if (v >= 0.3) return "var(--amber)";
  return "var(--green)";
}

const klassClass: Record<RiskLevel, string> = {
  Low: "risk-low",
  Medium: "risk-medium",
  High: "risk-high",
  Critical: "risk-critical",
};

/**
 * The score drain. The arc starts FULL (H = 1.000) and sweeps back to the actual
 * H over ~900ms, the number counting down in sync. Deny-by-default made visible:
 * content starts at maximum threat and earns its way down. prefers-reduced-motion
 * skips to the final value.
 */
export default function Gauge({ H, classification }: { H: number; classification: RiskLevel }) {
  const finalOffset = LEN * (1 - H);
  const [offset, setOffset] = useState(0); // 0 = arc fully drawn (H = 1.000)
  const [num, setNum] = useState(1);

  useEffect(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      setOffset(finalOffset);
      setNum(H);
      return;
    }
    const id = requestAnimationFrame(() => setOffset(finalOffset)); // triggers CSS transition
    const start = performance.now();
    let raf = 0;
    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / 900);
      const eased = 1 - Math.pow(1 - t, 3);
      setNum(1 + (H - 1) * eased);
      if (t < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => {
      cancelAnimationFrame(id);
      cancelAnimationFrame(raf);
    };
  }, [H, finalOffset]);

  const color = riskVar(H);

  return (
    <div className="gauge-wrap">
      <svg width="220" height="132" viewBox="0 0 220 132" aria-hidden="true">
        {/* remainder as tick marks */}
        <path d={PATH} fill="none" stroke="var(--text-3)" strokeWidth="14" strokeDasharray="2 9" />
        {/* risk-coloured fill that drains */}
        <path
          d={PATH}
          fill="none"
          stroke={color}
          strokeWidth="14"
          strokeLinecap="round"
          strokeDasharray={LEN}
          strokeDashoffset={offset}
          style={{ transition: "stroke-dashoffset 900ms cubic-bezier(0.2, 0.7, 0.3, 1)" }}
        />
      </svg>
      <div className="gauge-center">
        <div className={`klass ${klassClass[classification]}`}>{classification}</div>
        <div className="h mono">
          {num.toFixed(3)} <span className="max">/1.00</span>
        </div>
      </div>
    </div>
  );
}

"use client";

import { Ruler, Brain, type LucideIcon } from "lucide-react";
import type { AnalysisResult } from "@/core/types";
import Gauge from "./Gauge";

function riskVar(v: number): string {
  if (v >= 0.8) return "var(--red)";
  if (v >= 0.6) return "var(--orange)";
  if (v >= 0.3) return "var(--amber)";
  return "var(--green)";
}
const riskClass = (v: number) => (v >= 0.8 ? "risk-critical" : v >= 0.6 ? "risk-high" : v >= 0.3 ? "risk-medium" : "risk-low");
const sevName = (v: number) => (v >= 0.8 ? "critical" : v >= 0.6 ? "high" : v >= 0.3 ? "medium" : "low");
const fmtTime = (ms: number) => (ms < 1000 ? `${ms}ms` : `${(ms / 1000).toFixed(1)}s`);

const URL_RE = /((?:https?:\/\/|www\.)[^\s<>()]+|\b[a-z0-9-]+(?:\.[a-z0-9-]+)+(?:\/[^\s<>()]*)?)/gi;

/** Highlight URLs/domains in the transcription so the user can audit what we read. */
function highlightUrls(text: string) {
  const out: React.ReactNode[] = [];
  let last = 0;
  let key = 0;
  let m: RegExpExecArray | null;
  URL_RE.lastIndex = 0;
  while ((m = URL_RE.exec(text)) !== null) {
    if (m.index > last) out.push(text.slice(last, m.index));
    out.push(
      <mark className="url-hl" key={key++}>
        {m[0]}
      </mark>,
    );
    last = m.index + m[0].length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

/** A component-score metric tile (R or A). */
function Tile({
  label,
  value,
  caption,
  icon: Icon,
  tone,
}: {
  label: string;
  value: number | null;
  caption: string;
  icon: LucideIcon;
  tone: "rule" | "ai";
}) {
  return (
    <div className={`tile ${tone === "ai" ? "tile-ai" : ""}`}>
      <div className="tchip">
        <Icon size={17} strokeWidth={1.5} />
      </div>
      <div className="tlabel">{label}</div>
      {value === null ? (
        <div className="tval mono" style={{ color: "var(--text-3)", fontSize: 20 }}>
          abstained
        </div>
      ) : (
        <div className="tval mono" style={{ color: riskVar(value) }}>
          {value.toFixed(3)}
        </div>
      )}
      <div className="tcap">{caption}</div>
    </div>
  );
}

export default function ThreatReport({ result, onReset }: { result: AnalysisResult; onReset?: () => void }) {
  const {
    id,
    contentType,
    classification,
    action,
    ruleScore,
    aiScore,
    hybridScore,
    workings,
    indicators,
    patterns,
    explanation,
    aiAvailable,
    timings,
    weights,
    transcription,
  } = result;

  const equationLines = workings.split("\n");
  const bothPresent = ruleScore !== null && aiScore !== null;
  const interaction = bothPresent ? weights.gamma * ruleScore! * aiScore! : 0;
  const annoLeft = Math.min(88, Math.max(12, hybridScore * 100));

  return (
    <div className="report">
      {/* Case bar — content type, case id, and a reset to a fresh analysis */}
      <div className="report-head">
        <div className="rh-left">
          <span className="rh-badge">{contentType}</span>
          <span className="rh-case mono">
            CASE #{String(id).padStart(6, "0")} · {fmtTime(timings.total)}
          </span>
        </div>
        {onReset && (
          <button className="rh-new" onClick={onReset}>
            ＋ NEW ANALYSIS
          </button>
        )}
      </div>

      {!aiAvailable && (
        <div className="notice">
          AI content analysis was unavailable — this verdict rests on the rule-based layer alone (A set equal to R). Provisional.
        </div>
      )}

      {/* 1. VERDICT — hero panel, flooded with the severity colour and the arc gauge */}
      <div className="block hero" data-sev={sevName(hybridScore)}>
        <div className="hero-lines" aria-hidden="true" />
        <div className="hero-inner">
          <Gauge H={hybridScore} classification={classification} />
          <div className="hero-action">
            <div className={`klass-line ${riskClass(hybridScore)}`}>Recommended action</div>
            <div className="act">{action}</div>
          </div>
        </div>
      </div>

      {/* Audit trail — the transcription that entered the pipeline (image submissions). */}
      {transcription != null && (
        <details className="block extracted">
          <summary>
            Extracted text <span className="ex-note">— what we read from the image</span>
          </summary>
          <pre className="ex-body mono">{highlightUrls(transcription)}</pre>
        </details>
      )}

      {/* 2. SCORE DECOMPOSITION */}
      <div className="block">
        <div className="block-title">Score decomposition</div>
        <div className="tiles">
          <Tile label="R · rule" value={ruleScore} caption="structural" icon={Ruler} tone="rule" />
          <Tile label="A · ai" value={aiScore} caption="semantic" icon={Brain} tone="ai" />
        </div>

        <div className="fusion">
          <div className="fusion-track">
            {bothPresent && (
              <div className="anno mono" style={{ left: `${annoLeft}%` }}>
                interaction γRA {interaction >= 0 ? "+" : ""}
                {interaction.toFixed(3)}
              </div>
            )}
            <div className="fusion-fill" style={{ width: `${hybridScore * 100}%`, background: riskVar(hybridScore) }} />
          </div>
        </div>

        <div className="equation">
          {equationLines.map((ln, i) => (
            <div
              key={i}
              className={i === equationLines.length - 1 ? "result" : undefined}
              style={i === equationLines.length - 1 ? { color: riskVar(hybridScore) } : undefined}
            >
              {ln}
            </div>
          ))}
        </div>

        {ruleScore === null && <div className="abstain-note">Rules abstained: no structural indicators applied. H = A.</div>}
        {aiScore === null && <div className="abstain-note">AI abstained: no analysable language. H = R.</div>}

        <div className="decomp-foot">
          <span className="mono">
            weights α={weights.alpha} β={weights.beta} γ={weights.gamma}
          </span>
        </div>
      </div>

      {/* 3. INDICATORS */}
      <div className="block">
        <div className="block-title">Rule indicators</div>
        {indicators.map((i) => {
          const state = !i.applicable ? "na" : i.passed ? "pass" : "fail";
          return (
            <div className={`ind ${state === "na" ? "na" : ""}`} key={i.id}>
              <div className={`pip pip-${state}`} />
              <div>
                <div className="name">
                  {i.label}
                  {state === "na" && <span className="na-tag">n/a</span>}
                </div>
                <div className="detail">{i.detail}</div>
              </div>
              <div className="wt mono">{i.weight.toFixed(2)}</div>
            </div>
          );
        })}
      </div>

      {/* 4. DETECTED PATTERNS */}
      <div className="block">
        <div className="block-title">Detected manipulation patterns</div>
        {patterns.length === 0 ? (
          <div className="empty">
            {aiScore === null
              ? "The semantic layer abstained — no analysable language to inspect."
              : "No manipulation patterns detected in the language."}
          </div>
        ) : (
          patterns.map((p, idx) => (
            <div className="pattern" key={`${p.id}-${idx}`}>
              <div className="plabel tracking-label">{p.label}</div>
              <div className="quote">“{p.evidence}”</div>
            </div>
          ))
        )}
      </div>

      {/* 5. EXPLANATION */}
      <div className="block">
        <div className="block-title">Explanation</div>
        {explanation ? (
          <p className="explanation">{explanation}</p>
        ) : (
          <div className="empty">No semantic explanation (the AI layer did not run on this submission).</div>
        )}
      </div>

      <div className="report-foot">
        rules {fmtTime(timings.rules)} · ai {fmtTime(timings.ai)} · total {fmtTime(timings.total)}
      </div>
    </div>
  );
}

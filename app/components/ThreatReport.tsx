import type { AnalysisResult, RiskLevel } from "@/core/types";

const riskClass: Record<RiskLevel, string> = {
  Low: "risk-low",
  Medium: "risk-medium",
  High: "risk-high",
  Critical: "risk-critical",
};

const fmt = (n: number | null) => (n === null ? "—" : n.toFixed(3));

export default function ThreatReport({ result }: { result: AnalysisResult }) {
  const {
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
    contentType,
    timings,
    weights,
  } = result;

  return (
    <div>
      {/* Degradation notice: the AI service failed and we fell back to rule-only. */}
      {!aiAvailable && (
        <div className="notice">
          AI content analysis was unavailable, so this verdict rests on the structural
          rule-based layer alone (A was set equal to R). Treat it as provisional.
        </div>
      )}

      {/* 1. VERDICT */}
      <div className={`verdict ${riskClass[classification]}`}>
        <div className="level">{classification} Risk</div>
        <div className="action">{action}</div>
        <div className="meta">
          Submission type: {contentType}
          {ruleScore === null && " · rule engine abstained"}
          {aiScore === null && " · semantic layer abstained"}
        </div>
      </div>

      {/* 2. SCORE DECOMPOSITION — the most important block. Real numbers, verbatim. */}
      <div className="card">
        <h2>Score decomposition</h2>
        <div className="scores">
          <div className="score-tile">
            <div className="label">R · rules</div>
            <div className="value">{fmt(ruleScore)}</div>
            <div className="sub">{ruleScore === null ? "abstained" : "structural"}</div>
          </div>
          <div className="score-tile">
            <div className="label">A · ai</div>
            <div className="value">{fmt(aiScore)}</div>
            <div className="sub">{aiScore === null ? "abstained" : "semantic"}</div>
          </div>
          <div className="score-tile">
            <div className="label">H · hybrid</div>
            <div className="value">{hybridScore.toFixed(3)}</div>
            <div className="sub">fused verdict</div>
          </div>
        </div>
        <div className="workings">{workings}</div>
        <div className="timings">
          weights α={weights.alpha} β={weights.beta} γ={weights.gamma} · timings rules {timings.rules}ms · ai{" "}
          {timings.ai}ms · total {timings.total}ms
        </div>
      </div>

      {/* 3. INDICATOR TABLE — all nine, inapplicable ones greyed with struck weight. */}
      <div className="card">
        <h2>Rule indicators</h2>
        <table className="indicator-table">
          <thead>
            <tr>
              <th>Indicator</th>
              <th>Result</th>
              <th className="weight">Weight</th>
            </tr>
          </thead>
          <tbody>
            {indicators.map((i) => {
              const state = !i.applicable ? "na" : i.passed ? "pass" : "fail";
              return (
                <tr key={i.id} className={state === "na" ? "row-na" : ""}>
                  <td>
                    {i.label}
                    <div className="detail">{i.detail}</div>
                  </td>
                  <td>
                    <span className={`tag tag-${state}`}>
                      {state === "na" ? "N/A" : state === "pass" ? "Pass" : "Fail"}
                    </span>
                  </td>
                  <td className="weight">{i.weight.toFixed(2)}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* 4. DETECTED PATTERNS — each with its verbatim evidence span. */}
      <div className="card">
        <h2>Detected manipulation patterns</h2>
        {patterns.length === 0 ? (
          <div className="empty">
            {aiScore === null
              ? "The semantic layer abstained — there was no analysable language to inspect."
              : "No manipulation patterns were detected in the language."}
          </div>
        ) : (
          patterns.map((p, idx) => (
            <div className="pattern" key={`${p.id}-${idx}`}>
              <div className="name">{p.label}</div>
              <div className="evidence">“{p.evidence}”</div>
            </div>
          ))
        )}
      </div>

      {/* 5. EXPLANATION */}
      <div className="card">
        <h2>Explanation</h2>
        {explanation ? (
          <p className="explanation">{explanation}</p>
        ) : (
          <div className="empty">No semantic explanation (the AI layer did not run on this submission).</div>
        )}
      </div>
    </div>
  );
}

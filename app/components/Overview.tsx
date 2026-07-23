import { Lock } from "lucide-react";

const STEPS: { name: string; note: string; hot?: boolean }[] = [
  { name: "Preprocess", note: "parse, extract URLs, resolve WHOIS + TLS, redact links" },
  { name: "Rule engine", note: "nine weighted structural indicators → R" },
  { name: "AI semantic", note: "one blind Gemini pass over the words → A" },
  { name: "HTSA fusion", note: "agreement gate fuses R and A → H", hot: true },
  { name: "Report", note: "verdict, decomposition, evidence" },
];

const INDICATORS: [string, number][] = [
  ["Domain age", 0.15],
  ["SSL certificate", 0.1],
  ["IP address in URL", 0.12],
  ["Brand similarity", 0.15],
  ["Subdomain depth", 0.08],
  ["Email authentication", 0.12],
  ["Reply-to mismatch", 0.1],
  ["Credential form in body", 0.1],
  ["URL shortener", 0.08],
];
const MAX_WEIGHT = 0.15;

const PATTERNS = [
  "Urgency manipulation",
  "Authority impersonation",
  "Emotional exploitation",
  "Credential harvesting",
  "Financial manipulation",
  "Action coercion",
];

// 20-segment threat meter, full (1.000) — deny-by-default made visible.
const METER = Array.from({ length: 20 }, (_, i) => (i < 6 ? "g" : i < 13 ? "a" : "r"));

export default function Overview() {
  return (
    <div className="overview">
      {/* Deny by default — thesis + full threat meter */}
      <div className="deny-hero">
        <div className="deny-row">
          <div className="deny-copy">
            <div className="deny-tag">
              <span className="flick" aria-hidden="true" />
              DENY BY DEFAULT
            </div>
            <p>
              Every submission starts at maximum threat — <span className="mono">1.000</span> — and must earn a lower score by
              passing checks. Structural facts and language are scored independently, then fused: agreement releases the score,
              disagreement holds it down.
            </p>
          </div>
          <div className="threat-readout">
            <div className="tr-head">
              <span className="tr-label">THREAT LEVEL</span>
              <span className="tr-val">1.000</span>
            </div>
            <div className="threat-meter" aria-hidden="true">
              {METER.map((c, i) => (
                <i className={c} key={i} />
              ))}
            </div>
            <div className="tr-scale">
              <span>CLEAR</span>
              <span className="crit">CRITICAL</span>
            </div>
          </div>
        </div>
      </div>

      {/* Pipeline — numbered, HTSA fusion hot */}
      <div className="block">
        <div className="block-title">Pipeline</div>
        <div className="pipeline">
          {STEPS.map((s, i) => (
            <div className={`pstep ${s.hot ? "hot" : ""}`} key={s.name}>
              <div className="picon">
                <span className="pn">0{i + 1}</span>
              </div>
              <div className="pname">{s.name}</div>
              <div className="pnote">{s.note}</div>
              {i < STEPS.length - 1 && (
                <div className="parrow" aria-hidden="true">
                  →
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      <div className="ov-layers">
        <div className="block">
          <div className="block-title">Structural layer — R</div>
          {INDICATORS.map(([name, wt]) => (
            <div className="ov-ind" key={name}>
              <div>
                <div className="ov-name">{name}</div>
                <div className="ov-bar">
                  <i style={{ width: `${(wt / MAX_WEIGHT) * 100}%` }} />
                </div>
              </div>
              <span className="ov-wt">{wt.toFixed(2)}</span>
            </div>
          ))}
        </div>
        <div className="block layer-violet">
          <div className="block-title">Semantic layer — A</div>
          {PATTERNS.map((p) => (
            <div className="ov-pat" key={p}>
              {p}
            </div>
          ))}
          <p className="ov-blind">
            <Lock size={14} strokeWidth={1.6} />
            The semantic layer reads redacted words only — never the domain, cert, or headers.
          </p>
        </div>
      </div>
    </div>
  );
}

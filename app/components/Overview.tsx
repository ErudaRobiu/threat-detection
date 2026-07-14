import { FileSearch, Ruler, Brain, GitMerge, FileText } from "lucide-react";

const STEPS = [
  { icon: FileSearch, name: "Preprocess", note: "parse, extract URLs, resolve WHOIS + TLS, redact links" },
  { icon: Ruler, name: "Rule engine", note: "nine weighted structural indicators → R" },
  { icon: Brain, name: "AI semantic", note: "one blind Gemini pass over the words → A" },
  { icon: GitMerge, name: "HTSA fusion", note: "agreement gate fuses R and A → H" },
  { icon: FileText, name: "Report", note: "verdict, decomposition, evidence" },
];

const INDICATORS = [
  ["Domain age", "0.15"],
  ["SSL certificate", "0.10"],
  ["IP address in URL", "0.12"],
  ["Brand similarity", "0.15"],
  ["Subdomain depth", "0.08"],
  ["Email authentication", "0.12"],
  ["Reply-to mismatch", "0.10"],
  ["Credential form in body", "0.10"],
  ["URL shortener", "0.08"],
];

const PATTERNS = [
  "Urgency manipulation",
  "Authority impersonation",
  "Emotional exploitation",
  "Credential harvesting",
  "Financial manipulation",
  "Action coercion",
];

export default function Overview() {
  return (
    <div className="overview">
      <div className="block ov-thesis">
        <div className="block-title">Deny by default</div>
        <p>
          Every submission starts at maximum threat — <span className="mono">1.000</span> — and must earn a lower score by
          passing checks. Structural facts and language are scored independently, then fused: agreement releases the score,
          disagreement holds it down.
        </p>
      </div>

      <div className="block">
        <div className="block-title">Pipeline</div>
        <div className="pipeline">
          {STEPS.map((s, i) => (
            <div className="pstep" key={s.name}>
              <div className="picon" style={{ animationDelay: `${i * 0.9}s` }}>
                <s.icon size={17} strokeWidth={1.5} />
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
              <span>{name}</span>
              <span className="mono">{wt}</span>
            </div>
          ))}
        </div>
        <div className="block">
          <div className="block-title">Semantic layer — A</div>
          {PATTERNS.map((p) => (
            <div className="ov-pat" key={p}>
              {p}
            </div>
          ))}
          <p className="ov-blind">The semantic layer reads redacted words only — never the domain, cert, or headers.</p>
        </div>
      </div>
    </div>
  );
}

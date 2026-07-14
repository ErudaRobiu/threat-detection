"use client";

import { useState, type DragEvent } from "react";
import { UploadCloud, Loader2 } from "lucide-react";
import type { AnalysisResult, ContentType } from "@/core/types";
import { DEMO_INPUTS } from "@/core/demo-inputs";
import ThreatReport from "./components/ThreatReport";
import Overview from "./components/Overview";

type TypeChoice = "auto" | ContentType;
const TABS: { id: TypeChoice; label: string }[] = [
  { id: "auto", label: "Auto" },
  { id: "email", label: "Email" },
  { id: "url", label: "URL" },
  { id: "text", label: "Text" },
];

export default function Home() {
  const [content, setContent] = useState("");
  const [typeChoice, setTypeChoice] = useState<TypeChoice>("auto");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [hot, setHot] = useState(false);

  async function submit() {
    const text = content.trim();
    if (!text || loading) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ content: text, contentType: typeChoice === "auto" ? undefined : typeChoice }),
      });
      const data = await res.json();
      if (!res.ok) setError(data.error ?? "Analysis failed.");
      else setResult(data as AnalysisResult);
    } catch {
      setError("Could not reach the analysis service.");
    } finally {
      setLoading(false);
    }
  }

  function onDrop(e: DragEvent) {
    e.preventDefault();
    setHot(false);
    const file = e.dataTransfer.files?.[0];
    if (!file) return;
    file.text().then((t) => {
      setContent(t);
      setResult(null);
      setError(null);
    });
  }

  return (
    <div className="workspace">
      {/* LEFT: input */}
      <div className="left-col">
        <div className="card">
          <div className="seg">
            {TABS.map((t) => (
              <button key={t.id} className={typeChoice === t.id ? "active" : ""} onClick={() => setTypeChoice(t.id)}>
                {t.label}
              </button>
            ))}
          </div>

          <div
            className={`dropzone ${hot ? "hot" : ""}`}
            onDragOver={(e) => {
              e.preventDefault();
              setHot(true);
            }}
            onDragEnter={(e) => {
              e.preventDefault();
              setHot(true);
            }}
            onDragLeave={() => setHot(false)}
            onDrop={onDrop}
          >
            <svg className="dz-border">
              <rect />
            </svg>
            {loading && <div className="scanline" />}
            <div className={`dz-hint ${content ? "hidden" : ""}`}>
              <div className="dz-chip">
                <UploadCloud size={26} strokeWidth={1.5} />
              </div>
              <div>
                <div className="dz-title">Drop a file to analyse</div>
                <div className="dz-sub">.eml or .txt &nbsp;·&nbsp; or paste &nbsp;·&nbsp; or click to type</div>
              </div>
            </div>
            <textarea
              value={content}
              onChange={(e) => setContent(e.target.value)}
              spellCheck={false}
              aria-label="Content to analyse"
            />
          </div>

          <button className="analyse-btn" style={{ marginTop: 14 }} onClick={submit} disabled={loading || !content.trim()}>
            {loading ? <Loader2 size={16} strokeWidth={1.5} className="spin" /> : null}
            {loading ? "Analysing" : "Analyse"}
          </button>
        </div>

        <div className="card">
          <div className="tracking-label" style={{ marginBottom: 10 }}>
            Examples
          </div>
          <div className="chips">
            {DEMO_INPUTS.map((d) => (
              <button
                key={d.id}
                onClick={() => {
                  setContent(d.text);
                  setResult(null);
                  setError(null);
                }}
              >
                {d.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* RIGHT: report */}
      <div>
        {error && <div className="error-banner">{error}</div>}
        {result ? <ThreatReport key={result.id} result={result} /> : !error && <Overview />}
      </div>
    </div>
  );
}

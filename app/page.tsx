"use client";

import { useState } from "react";
import type { AnalysisResult, ContentType } from "@/core/types";
import { DEMO_INPUTS } from "@/core/demo-inputs";
import ThreatReport from "./components/ThreatReport";

type TypeChoice = "auto" | ContentType;

export default function Home() {
  const [content, setContent] = useState("");
  const [typeChoice, setTypeChoice] = useState<TypeChoice>("auto");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AnalysisResult | null>(null);

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
        body: JSON.stringify({
          content: text,
          contentType: typeChoice === "auto" ? undefined : typeChoice,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error ?? "Analysis failed.");
      } else {
        setResult(data as AnalysisResult);
      }
    } catch {
      setError("Could not reach the analysis service.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main>
      <div className="card">
        <h2>Submit content for analysis</h2>
        <p style={{ marginTop: 0, color: "var(--text-dim)", fontSize: 14 }}>
          Paste a suspicious email (with headers), a URL, or a text message. Every submission
          starts at maximum threat and must earn a lower score by passing checks.
        </p>
        <textarea
          value={content}
          onChange={(e) => setContent(e.target.value)}
          placeholder="Paste an email, URL, or message here…"
          spellCheck={false}
        />
        <div className="controls">
          <label style={{ fontSize: 13, color: "var(--text-dim)" }}>
            Type&nbsp;
            <select value={typeChoice} onChange={(e) => setTypeChoice(e.target.value as TypeChoice)}>
              <option value="auto">Auto-detect</option>
              <option value="email">Email</option>
              <option value="url">URL</option>
              <option value="text">Text message</option>
            </select>
          </label>
          <button className="primary" onClick={submit} disabled={loading || !content.trim()}>
            {loading && <span className="spinner" />}
            {loading ? "Analysing…" : "Analyse"}
          </button>
        </div>

        <div className="examples">
          <span style={{ fontSize: 12.5, color: "var(--text-faint)", alignSelf: "center" }}>Try an example:</span>
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

      {error && <div className="error-banner">{error}</div>}
      {result && <ThreatReport result={result} />}
    </main>
  );
}

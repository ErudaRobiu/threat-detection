/**
 * app/history/page.tsx — Phase 4 analysis history (plain table).
 *
 * Server component: reads the local SQLite history directly (fail-soft) and
 * renders newest-first. Three states:
 *   - disabled (Vercel / ephemeral fs): a notice, no fabricated rows;
 *   - empty (local, nothing analysed yet): an empty-state prompt;
 *   - populated: a plain table of past analyses.
 * No donut, no time-series chart — a table, by design.
 */

import { History } from "lucide-react";
import { getHistory, HISTORY_DISABLED, HISTORY_DISABLED_REASON } from "@/lib/db";
import type { RiskLevel } from "@/core/types";

export const dynamic = "force-dynamic"; // re-read on every request

const riskClass: Record<string, string> = {
  Low: "risk-low",
  Medium: "risk-medium",
  High: "risk-high",
  Critical: "risk-critical",
};

function fmtScore(n: number | null): string {
  return n === null ? "—" : n.toFixed(3);
}

function fmtTime(iso: string): string {
  const d = new Date(iso);
  return isNaN(d.getTime())
    ? iso
    : d.toLocaleString(undefined, {
        year: "numeric",
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      });
}

export default function HistoryPage() {
  const rows = HISTORY_DISABLED ? [] : getHistory(100);

  if (HISTORY_DISABLED) {
    return (
      <div className="stub">
        <div className="picon" style={{ width: 44, height: 44, borderRadius: 12 }}>
          <History size={20} strokeWidth={1.5} />
        </div>
        <h2>History is off on this deployment</h2>
        <p>{HISTORY_DISABLED_REASON}</p>
      </div>
    );
  }

  if (rows.length === 0) {
    return (
      <div className="stub">
        <div className="picon" style={{ width: 44, height: 44, borderRadius: 12 }}>
          <History size={20} strokeWidth={1.5} />
        </div>
        <h2>No analyses yet</h2>
        <p>Run an analysis on the Analyse page and it will appear here, newest first.</p>
      </div>
    );
  }

  return (
    <div className="hist-wrap">
      <div className="hist-head">
        <h2>Analysis history</h2>
        <span className="mono hist-count">{rows.length} stored</span>
      </div>
      <div className="card hist-card">
        <div className="hist-scroll">
          <table className="hist">
            <thead>
              <tr>
                <th>Time</th>
                <th>Type</th>
                <th className="num">R</th>
                <th className="num">A</th>
                <th className="num">H</th>
                <th>Verdict</th>
                <th>Preview</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id}>
                  <td className="mono nowrap">{fmtTime(r.createdAt)}</td>
                  <td className="nowrap">{r.contentType}</td>
                  <td className="num mono">{fmtScore(r.ruleScore)}</td>
                  <td className="num mono">{fmtScore(r.aiScore)}</td>
                  <td className="num mono">{r.hybridScore.toFixed(3)}</td>
                  <td className={`nowrap ${riskClass[r.classification as RiskLevel] ?? ""}`}>
                    {r.classification}
                    {!r.aiAvailable && <span className="hist-deg mono"> AI↓</span>}
                  </td>
                  <td className="hist-prev">{r.preview}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

import { History } from "lucide-react";

/**
 * Phase 4 screen. Deliberately a placeholder, not mock data: a history dashboard
 * (metric tiles, risk-distribution donut, table, H-over-time chart) is only
 * honest once it is backed by real stored analyses, which arrive with the
 * database in Phase 4. Filling it with fabricated numbers would be exactly the
 * kind of invented metric this project must never show.
 */
export default function HistoryPage() {
  return (
    <div className="stub">
      <div className="picon" style={{ width: 44, height: 44, borderRadius: 12 }}>
        <History size={20} strokeWidth={1.5} />
      </div>
      <h2>History arrives in Phase 4</h2>
      <p>
        The analysis history — metric tiles, risk-level distribution, the table of past analyses, and the H-over-time chart —
        is backed by the database built in Phase 4. It will populate from real stored analyses, not placeholder data.
      </p>
    </div>
  );
}

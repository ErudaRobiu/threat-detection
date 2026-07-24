/**
 * app/api/history/route.ts — read the local analysis history (Phase 4).
 *
 * Returns `{ disabled, reason?, items }`. On Vercel `disabled` is true, `items`
 * is empty, and `reason` explains why (ephemeral filesystem — see lib/db.ts).
 * Locally it returns the most recent analyses, newest first. Fail-soft: a read
 * error yields an empty list, never a 500.
 */

import { NextResponse } from "next/server";
import { getHistory, HISTORY_DISABLED, HISTORY_DISABLED_REASON } from "@/lib/db";

export const runtime = "nodejs";
export const dynamic = "force-dynamic"; // never statically cache history

export function GET() {
  if (HISTORY_DISABLED) {
    return NextResponse.json({ disabled: true, reason: HISTORY_DISABLED_REASON, items: [] });
  }
  return NextResponse.json({ disabled: false, items: getHistory(100) });
}

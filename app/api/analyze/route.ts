/**
 * app/api/analyze/route.ts
 *
 * The one endpoint that matters. It hosts the entire analysis core server-side:
 * preprocess -> rules -> ai -> fuse. The client never runs analysis and never
 * sees an API key.
 *
 * Runs on the Node.js runtime (not edge): preprocess needs the `tls` and WHOIS
 * network stack and the on-disk Gemini cache.
 */

import { NextResponse } from "next/server";
import { analyze, AiUnavailableError } from "@/core/analyze";
import { getDemoResult } from "@/core/demo";
import { NoAnalysableContentError } from "@/core/htsa";
import type { ContentType, HTSAWeights } from "@/core/types";

export const runtime = "nodejs";
export const maxDuration = 30;

interface Body {
  content?: string;
  contentType?: ContentType;
  weights?: HTSAWeights;
}

export async function POST(req: Request) {
  let body: Body;
  try {
    body = (await req.json()) as Body;
  } catch {
    return NextResponse.json({ error: "Invalid JSON body." }, { status: 400 });
  }

  const content = (body.content ?? "").trim();
  if (!content) {
    return NextResponse.json({ error: "No content was submitted." }, { status: 400 });
  }

  // DEMO_MODE: serve the bundled, pre-analysed examples with no network call.
  if (process.env.DEMO_MODE === "1") {
    const demo = getDemoResult(content);
    if (demo) return NextResponse.json(demo);
  }

  try {
    const result = await analyze(content, { contentType: body.contentType, weights: body.weights });
    return NextResponse.json(result);
  } catch (err) {
    if (err instanceof NoAnalysableContentError) {
      return NextResponse.json(
        { error: "The submission contains no analysable content — no links, no email headers, and no readable text." },
        { status: 400 },
      );
    }
    if (err instanceof AiUnavailableError) {
      return NextResponse.json(
        { error: "This submission needs semantic analysis, which is currently unavailable. Please try again shortly." },
        { status: 503 },
      );
    }
    console.error("[api/analyze] fatal:", err);
    return NextResponse.json({ error: "Analysis failed unexpectedly." }, { status: 500 });
  }
}

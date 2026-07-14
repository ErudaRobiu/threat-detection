/**
 * app/api/analyze/route.ts
 *
 * The one endpoint. Accepts either JSON (pasted text) or multipart (image
 * screenshots). Images are transcribed to raw text FIRST (Stage 1), then that
 * text runs the ordinary pipeline (Stage 2). The image never reaches the
 * analysis layer — see core/transcribe.ts.
 *
 * Runs on the Node.js runtime: preprocess needs the tls/WHOIS stack and the
 * on-disk caches.
 */

import { NextResponse } from "next/server";
import { analyze, AiUnavailableError } from "@/core/analyze";
import { transcribeImages } from "@/core/transcribe";
import { getDemoResult } from "@/core/demo";
import { NoAnalysableContentError } from "@/core/htsa";
import type { ContentType, HTSAWeights } from "@/core/types";

export const runtime = "nodejs";
export const maxDuration = 45;

const MAX_IMAGES = 3;
const MAX_BYTES = 5 * 1024 * 1024; // 5MB each
const OK_TYPES = new Set(["image/png", "image/jpeg", "image/webp", "image/heic", "image/heif"]);

function fail(error: string, status: number) {
  return NextResponse.json({ error }, { status });
}

export async function POST(req: Request) {
  const contentType = req.headers.get("content-type") ?? "";

  // ---- Image path: multipart ----------------------------------------------
  if (contentType.includes("multipart/form-data")) {
    let form: FormData;
    try {
      form = await req.formData();
    } catch {
      return fail("Could not read the uploaded files.", 400);
    }
    const files = form.getAll("images").filter((f): f is File => f instanceof File);
    if (files.length === 0) return fail("No image was uploaded.", 400);
    if (files.length > MAX_IMAGES) return fail(`Please upload at most ${MAX_IMAGES} images.`, 400);

    const images: { base64: string; mimeType: string }[] = [];
    for (const file of files) {
      if (!OK_TYPES.has(file.type)) return fail(`Unsupported image type: ${file.type || "unknown"}.`, 400);
      if (file.size > MAX_BYTES) return fail("Each image must be under 5MB.", 400);
      const buf = Buffer.from(await file.arrayBuffer());
      images.push({ base64: buf.toString("base64"), mimeType: file.type });
    }

    let transcription: string;
    try {
      transcription = await transcribeImages(images);
    } catch (err) {
      // No text to degrade to: a transcription failure is not an analysis failure.
      console.error("[api/analyze] transcription failed:", err);
      return fail("Could not read the image. Please try again shortly.", 503);
    }
    if (!transcription.trim()) return fail("No readable message found in this image.", 400);

    try {
      const result = await analyze(transcription, { transcription });
      return NextResponse.json(result);
    } catch (err) {
      return mapAnalyzeError(err);
    }
  }

  // ---- Text path: JSON ----------------------------------------------------
  let body: { content?: string; contentType?: ContentType; weights?: HTSAWeights };
  try {
    body = (await req.json()) as typeof body;
  } catch {
    return fail("Invalid JSON body.", 400);
  }
  const content = (body.content ?? "").trim();
  if (!content) return fail("No content was submitted.", 400);

  if (process.env.DEMO_MODE === "1") {
    const demo = getDemoResult(content);
    if (demo) return NextResponse.json(demo);
  }

  try {
    const result = await analyze(content, { contentType: body.contentType, weights: body.weights });
    return NextResponse.json(result);
  } catch (err) {
    return mapAnalyzeError(err);
  }
}

function mapAnalyzeError(err: unknown) {
  if (err instanceof NoAnalysableContentError) {
    return fail(
      "The submission contains no analysable content — no links, no email headers, and no readable text.",
      400,
    );
  }
  if (err instanceof AiUnavailableError) {
    return fail("This submission needs semantic analysis, which is currently unavailable. Please try again shortly.", 503);
  }
  console.error("[api/analyze] fatal:", err);
  return fail("Analysis failed unexpectedly.", 500);
}

/**
 * core/transcribe.ts
 *
 * STAGE 1 of image input, and it is deliberately isolated from the analysis.
 *
 * A screenshot of a phishing email SHOWS the sender domain and the URL. Gemini is
 * multimodal and could "analyse" the image directly — but if the image ever
 * reached the semantic layer, the AI would read "paypa1-verify.com" with its own
 * eyes, the redaction-based blindness would be undone, R and A would correlate,
 * and the agreement gate would measure redundancy instead of corroboration. The
 * central claim would die silently (the metrics would look BETTER).
 *
 * So this module ONLY transcribes. It turns an image into the raw text a person
 * would have pasted, and hands that text to the ordinary pipeline. It is an input
 * adapter that sits BEFORE preprocess, never inside it. It judges nothing.
 *
 * A separate, cheaper model (GEMINI_TRANSCRIBE_MODEL, default gemini-2.5-flash-
 * lite) does this mechanical work. Responses are cached by SHA-256 of the image
 * bytes.
 */

import { GoogleGenAI } from "@google/genai";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export const TRANSCRIBE_PROMPT = `You are a transcription tool. You are given an image — a screenshot of an email,
a text message, or a chat. Your only job is to transcribe the text it contains,
exactly as it appears. You do not judge, summarise, translate, explain, or
comment. You reproduce.

Transcribe everything visible, preserving structure:
  - If it is an email, reproduce every header line you can see — From, Reply-To,
    To, Subject, Date, and any authentication results — each on its own line,
    then a blank line, then the body.
  - If it is a text message or chat, reproduce the message text as shown.
  - Reproduce EVERY web address and email address character for character.

==========================================================================
DO NOT AUTOCORRECT. READ THIS TWICE.
==========================================================================
Transcribe each character exactly as it is drawn, even when it looks like a
mistake. If the image shows "paypa1" with the digit ONE, write the digit one —
do NOT "correct" it to "paypal". If a domain shows "g00gle" with zeros, write
the zeros. You are copying glyphs, not fixing spelling.

Again, because it is the thing that matters most: never repair a look-alike or
misspelled domain. "paypa1-verify.com", "micros0ft.com", "amaz0n-security.net"
must be transcribed with their exact digits and letters. Silently correcting a
look-alike domain to the real brand would destroy the single most important
signal in the system downstream, and it would fail invisibly. When a character
is genuinely ambiguous, prefer the literal glyph shown — a digit over the letter
it resembles — rather than the word you expect to see.

Output the transcribed text only. No preamble, no markdown, no notes. If the
image contains no readable message text, output nothing at all.`;

const CACHE_DIR = process.env.TRANSCRIBE_CACHE_DIR ?? join(process.cwd(), ".cache", "transcribe");

function cacheKey(base64: string): string {
  return createHash("sha256").update(base64).digest("hex");
}

function readCache(key: string): string | null {
  try {
    const file = join(CACHE_DIR, `${key}.txt`);
    return existsSync(file) ? readFileSync(file, "utf8") : null;
  } catch {
    return null;
  }
}

function writeCache(key: string, text: string): void {
  try {
    mkdirSync(CACHE_DIR, { recursive: true });
    writeFileSync(join(CACHE_DIR, `${key}.txt`), text, "utf8");
  } catch {
    // never fail a transcription over a cache write
  }
}

function requireEnv(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is not set`);
  return v;
}

/**
 * Transcribe one image to raw text. Throws on API failure — there is no text to
 * degrade to, so the caller returns 503 rather than degrading (a transcription
 * failure is not the same as an AI-analysis failure).
 */
export async function transcribeImage(base64: string, mimeType: string): Promise<string> {
  const key = cacheKey(base64);
  const cached = readCache(key);
  if (cached !== null) return cached;

  const apiKey = requireEnv("GEMINI_API_KEY");
  const model = process.env.GEMINI_TRANSCRIBE_MODEL ?? "gemini-2.5-flash-lite";

  const ai = new GoogleGenAI({ apiKey });
  const response = await ai.models.generateContent({
    model,
    contents: [
      {
        role: "user",
        parts: [{ inlineData: { data: base64, mimeType } }, { text: "Transcribe the message in this image." }],
      },
    ],
    config: { temperature: 0, systemInstruction: TRANSCRIBE_PROMPT },
  });

  const text = (response.text ?? "").trim();
  writeCache(key, text);
  return text;
}

/** Transcribe several image parts (a long email screenshotted in pieces) into one text. */
export async function transcribeImages(images: { base64: string; mimeType: string }[]): Promise<string> {
  const parts = await Promise.all(images.map((img) => transcribeImage(img.base64, img.mimeType)));
  return parts
    .map((p) => p.trim())
    .filter(Boolean)
    .join("\n\n");
}

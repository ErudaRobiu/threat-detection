/**
 * core/preprocess.ts
 *
 * Raw submission -> Features. This is the only module that touches the network
 * and the only module that reaches the outside world at all.
 *
 * ---------------------------------------------------------------------------
 * DIVISION OF LABOUR (read this before touching redaction)
 * ---------------------------------------------------------------------------
 * The rule engine reads INFRASTRUCTURE: the domain, its registration age, its
 * TLS certificate, the sending authentication. The AI reads LANGUAGE: the
 * words, the manufactured pressure, the ask. Neither may see the other's
 * evidence, or the two scores stop being independent and the HTSA agreement
 * gate measures nothing.
 *
 * Concretely, this module produces TWO views of the same submission:
 *   features.urls[]       the real parsed URLs + network facts, for rules.ts
 *   features.redactedText every URL / email / bare domain replaced by [LINK],
 *                         and this is the ONLY thing ai.ts is given.
 *
 * A typosquat domain such as "paypa1-verify.com" is already scored by
 * brand_similarity (Levenshtein + homoglyph) in rules.ts. If the AI could read
 * that domain too, both layers would fire on the same evidence. Redaction
 * prevents that. It is not a nicety; it is what makes the project's central
 * claim true.
 *
 * ---------------------------------------------------------------------------
 * INDETERMINATE NETWORK FACTS RESOLVE TO null, NEVER TO A GUESS
 * ---------------------------------------------------------------------------
 * A WHOIS lookup that returns no usable creation date resolves domainAgeDays to
 * null. A TLS host that cannot be reached resolves sslValid to null. The rule
 * engine reads null as a FAILURE (deny by default). This module must never
 * paper over an unreachable host with an optimistic value.
 */

import { simpleParser, type ParsedMail } from "mailparser";
import { parse } from "tldts";
import { firstResult, whoisDomain } from "whoiser";
import tls from "node:tls";

import type { ContentType, Features, UrlFacts } from "./types";
import { detectBrandImpersonation, SHORTENER_DOMAINS } from "./rules";

// ---------------------------------------------------------------------------
// Redaction and truncation (pure — the load-bearing structural-blindness step)
// ---------------------------------------------------------------------------

export const REDACTION_TOKEN = "[LINK]";
export const MAX_AI_INPUT_CHARS = 8000;

const SCHEME_URL = /\b(?:https?|ftp):\/\/[^\s<>()]+/gi;
const WWW_URL = /\bwww\.[^\s<>()]+/gi;
const EMAIL = /\b[^\s<>()@]+@[^\s<>()@]+\.[a-z]{2,}\b/gi;
const BARE_HOST = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi;

/**
 * True only when `host` ends in a real ICANN TLD. tldts assigns a `.domain` even
 * to unknown suffixes (so "Node.js" and "report.pdf" would otherwise look like
 * domains); gating on isIcann keeps ordinary prose out of the redactor.
 */
function isRealDomain(host: string): boolean {
  return parse(host).isIcann === true;
}

/**
 * Replace anything that reveals WHERE a link points — full URLs, www hosts,
 * email addresses, and bare registrable domains — with the literal token
 * [LINK], while PRESERVING that a link exists. "Confirm your details here:
 * [LINK]" still carries the action_coercion signal a human reads; it just
 * cannot tell the AI which domain the link goes to.
 */
export function redactLinks(text: string): string {
  let out = text
    .replace(SCHEME_URL, REDACTION_TOKEN)
    .replace(WWW_URL, REDACTION_TOKEN)
    .replace(EMAIL, REDACTION_TOKEN);

  // Bare domains: only redact strings the public-suffix list confirms are real
  // registrable domains, so ordinary prose ("Node.js", "e.g.", "report.pdf")
  // is left untouched.
  out = out.replace(BARE_HOST, (m) => (isRealDomain(m) ? REDACTION_TOKEN : m));

  // Collapse adjacent tokens ("[LINK]/[LINK]") into one, matching how a human
  // sees a single link where a URL and its path were split across matches.
  return out.replace(/(?:\[LINK\][/\s]*){2,}/g, `${REDACTION_TOKEN} `).trimEnd();
}

/** Keep the head; real emails carry huge quoted threads and signature blocks. */
export function truncateHead(text: string, max = MAX_AI_INPUT_CHARS): string {
  return text.length <= max ? text : `${text.slice(0, max)}\n\n[...truncated...]`;
}

/** The exact string handed to the AI layer: redact first (so no URL is sliced), then truncate. */
export function toRedactedText(humanText: string): string {
  return truncateHead(redactLinks(humanText));
}

// ---------------------------------------------------------------------------
// Content-type detection
// ---------------------------------------------------------------------------

const EMAIL_HEADER = /^(?:from|to|subject|date|received|reply-to|return-path|authentication-results|dkim-signature|message-id)\s*:/im;

export function detectContentType(raw: string): ContentType {
  const t = raw.trim();
  if (EMAIL_HEADER.test(t.slice(0, 4000))) return "email";
  // A submission that is a single bare URL / domain with no surrounding prose.
  if (t.length > 0 && !/\s/.test(t)) {
    const hasScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(t);
    let host = t;
    if (hasScheme) {
      try {
        host = new URL(t).hostname;
      } catch {
        host = t;
      }
    }
    if (hasScheme || isRealDomain(host)) return "url";
  }
  return "text";
}

// ---------------------------------------------------------------------------
// URL extraction and per-URL fact resolution
// ---------------------------------------------------------------------------

/** Pull candidate URL/host strings out of free text, de-duplicated, in order. */
export function extractUrlStrings(text: string): string[] {
  const found: string[] = [];
  const push = (s: string) => {
    const cleaned = s.replace(/[.,;:!?)"'>\]]+$/, ""); // shed trailing punctuation
    if (cleaned && !found.includes(cleaned)) found.push(cleaned);
  };
  for (const m of text.matchAll(SCHEME_URL)) push(m[0]);
  for (const m of text.matchAll(WWW_URL)) push(m[0]);
  for (const m of text.matchAll(BARE_HOST)) {
    // Skip bare hosts that are actually the tail of an email address.
    const before = text[m.index! - 1];
    if (before === "@") continue;
    if (isRealDomain(m[0])) push(m[0]);
  }
  return found;
}

const WHOIS_TIMEOUT_MS = 6000;
const TLS_TIMEOUT_MS = 6000;

async function resolveUrlFacts(rawUrl: string): Promise<UrlFacts> {
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(rawUrl) ? rawUrl : `http://${rawUrl}`;

  let hostname = rawUrl;
  try {
    hostname = new URL(withScheme).hostname;
  } catch {
    hostname = rawUrl;
  }

  const p = parse(hostname);
  const hostIsIpAddress = p.isIp === true;
  const registrableDomain = p.domain ?? hostname;
  const subdomainDepth = p.subdomain ? p.subdomain.split(".").filter(Boolean).length : 0;
  const isKnownShortener = SHORTENER_DOMAINS.has(registrableDomain.toLowerCase());

  // Brand and WHOIS are meaningless for a raw-IP host.
  const brandImpersonation = hostIsIpAddress ? null : detectBrandImpersonation(registrableDomain);
  const [domainAgeDays, sslValid] = await Promise.all([
    hostIsIpAddress ? Promise.resolve<number | null>(null) : lookupDomainAgeDays(registrableDomain),
    checkTls(hostname),
  ]);

  return {
    raw: rawUrl,
    hostname,
    registrableDomain,
    subdomainDepth,
    hostIsIpAddress,
    isKnownShortener,
    domainAgeDays,
    sslValid,
    brandImpersonation,
  };
}

/**
 * Days since the domain was registered, or null if it cannot be established.
 * null is deliberate: under deny-by-default the rule engine treats an
 * unverifiable registration date as a failure, not as clean.
 */
async function lookupDomainAgeDays(domain: string): Promise<number | null> {
  try {
    const results = await whoisDomain(domain, { timeout: WHOIS_TIMEOUT_MS, follow: 2 });
    const created = findCreationDate(firstResult(results));
    if (!created) return null;
    const ms = Date.now() - created.getTime();
    if (!Number.isFinite(ms) || ms < 0) return null;
    return Math.floor(ms / 86_400_000);
  } catch {
    return null;
  }
}

/** Scan a WHOIS record for the first key that looks like a creation date and parses. */
function findCreationDate(record: ReturnType<typeof firstResult> | undefined): Date | null {
  if (!record) return null;
  for (const [key, value] of Object.entries(record)) {
    if (!/creat|registered on|registration date|registration time/i.test(key)) continue;
    const raw = Array.isArray(value) ? value[0] : value;
    if (typeof raw !== "string") continue;
    const d = new Date(raw);
    if (!Number.isNaN(d.getTime())) return d;
  }
  return null;
}

/**
 * true  = a valid, in-date, trusted certificate for this host.
 * false = reachable but the certificate is missing, expired, or self-signed.
 * null  = the host could not be reached for TLS verification at all.
 *
 * rejectUnauthorized is off so a bad certificate still completes the handshake
 * and we can classify it as false rather than have it thrown as an error and
 * mistaken for unreachable.
 */
function checkTls(hostname: string): Promise<boolean | null> {
  return new Promise((resolve) => {
    let settled = false;
    const done = (v: boolean | null) => {
      if (settled) return;
      settled = true;
      resolve(v);
    };

    const socket = tls.connect(
      { host: hostname, port: 443, servername: hostname, timeout: TLS_TIMEOUT_MS, rejectUnauthorized: false },
      () => {
        const cert = socket.getPeerCertificate();
        let valid = socket.authorized;
        if (!cert || Object.keys(cert).length === 0) {
          valid = false;
        } else {
          const now = Date.now();
          const from = Date.parse(cert.valid_from);
          const to = Date.parse(cert.valid_to);
          if (Number.isNaN(from) || Number.isNaN(to) || now < from || now > to) valid = false;
        }
        socket.end();
        done(valid);
      },
    );
    socket.on("error", () => done(null)); // unreachable / handshake could not complete
    socket.on("timeout", () => {
      socket.destroy();
      done(null);
    });
  });
}

// ---------------------------------------------------------------------------
// Email header parsing
// ---------------------------------------------------------------------------

function registrableOf(hostOrAddress: string | null | undefined): string | null {
  if (!hostOrAddress) return null;
  const host = hostOrAddress.includes("@") ? hostOrAddress.split("@").pop()! : hostOrAddress;
  return parse(host).domain ?? host.toLowerCase();
}

type AuthState = "pass" | "fail" | "none" | null;

/** Read SPF/DKIM/DMARC verdicts out of Authentication-Results / Received-SPF. */
function parseAuthResults(parsed: ParsedMail): { spf: AuthState; dkim: AuthState; dmarc: AuthState } {
  const collect = (name: string): string => {
    const h = parsed.headers.get(name);
    if (!h) return "";
    if (typeof h === "string") return h;
    if (Array.isArray(h)) return h.join(" ");
    return String((h as { value?: unknown }).value ?? "");
  };

  const authResults = `${collect("authentication-results")} ${collect("received-spf")}`.toLowerCase();

  const verdict = (mechanism: string): AuthState => {
    const m = authResults.match(new RegExp(`${mechanism}\\s*=\\s*(pass|fail|softfail|neutral|none|permerror|temperror)`));
    if (!m) return null;
    if (m[1] === "pass") return "pass";
    if (m[1] === "none" || m[1] === "neutral") return "none";
    return "fail";
  };

  // Received-SPF puts the verdict as the first token ("Received-SPF: pass ...").
  let spf = verdict("spf");
  if (spf === null) {
    const rspf = collect("received-spf").trim().toLowerCase();
    if (rspf.startsWith("pass")) spf = "pass";
    else if (rspf.startsWith("fail") || rspf.startsWith("softfail")) spf = "fail";
    else if (rspf.startsWith("none") || rspf.startsWith("neutral")) spf = "none";
  }

  return { spf, dkim: verdict("dkim"), dmarc: verdict("dmarc") };
}

const CREDENTIAL_INPUT = /<input[^>]+type\s*=\s*["']?password/i;
const CREDENTIAL_FIELDS = /password|card\s*number|cvv|cvc|social security|\bssn\b|\bpin\b|routing number|account number/i;

function bodyHasCredentialForm(parsed: ParsedMail): boolean {
  const html = typeof parsed.html === "string" ? parsed.html : "";
  if (!html) return false;
  if (CREDENTIAL_INPUT.test(html)) return true;
  return /<form[\s>]/i.test(html) && /<input/i.test(html) && CREDENTIAL_FIELDS.test(html);
}

function extractEmailFacts(parsed: ParsedMail): NonNullable<Features["email"]> {
  const fromAddress = parsed.from?.value?.[0]?.address ?? null;
  const replyToAddress = parsed.replyTo?.value?.[0]?.address ?? null;
  const { spf, dkim, dmarc } = parseAuthResults(parsed);

  return {
    fromAddress,
    fromDomain: registrableOf(fromAddress),
    replyToAddress,
    replyToDomain: registrableOf(replyToAddress),
    spf,
    dkim,
    dmarc,
    bodyHasCredentialForm: bodyHasCredentialForm(parsed),
  };
}

/** Subject + plain-text body: the words a human reads, before redaction. */
function emailHumanText(parsed: ParsedMail): string {
  const subject = parsed.subject ? `Subject: ${parsed.subject}\n\n` : "";
  const body = parsed.text ?? (typeof parsed.html === "string" ? stripHtml(parsed.html) : "") ?? "";
  return `${subject}${body}`.trim();
}

function stripHtml(html: string): string {
  return html
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/\s+/g, " ")
    .trim();
}

// ---------------------------------------------------------------------------
// The entry point
// ---------------------------------------------------------------------------

/**
 * Turn a raw submission into Features. Async: WHOIS and TLS are network calls.
 *
 * @param raw          The pasted email / URL / message.
 * @param explicitType Optional override; otherwise the type is auto-detected.
 */
export async function preprocess(raw: string, explicitType?: ContentType): Promise<Features> {
  const contentType = explicitType ?? detectContentType(raw);

  let humanText = raw.trim();
  let email: Features["email"] | undefined;

  if (contentType === "email") {
    const parsed = await simpleParser(raw);
    email = extractEmailFacts(parsed);
    humanText = emailHumanText(parsed) || raw.trim();
  }

  const urlStrings = extractUrlStrings(humanText);
  const urls = await Promise.all(urlStrings.map(resolveUrlFacts));

  return {
    contentType,
    text: humanText,
    redactedText: toRedactedText(humanText),
    email,
    urls,
  };
}

# Deployment verification — WHOIS/TLS from a datacentre IP

**Purpose (Chapter 4 artefact).** Under deny-by-default, a `null` `domainAgeDays`
counts as a *failure*: every URL that cannot be dated loses 0.15 of earned weight
and its score inflates. WHOIS from a cloud/datacentre IP is frequently rate-
limited or blocked by registrars, which would corrupt R across the entire
evaluation *silently* — the UI would look fine and the Chapter 4 false-positive
rate would come out inexplicably high. This check confirms it does not happen on
the production host before any evaluation is run.

`GET /api/health` runs the real `preprocess` path (same tldts + WHOIS + TLS code
the analysis uses) against three known-good domains and reports the raw facts.
A number for `domainAgeDays` = WHOIS succeeded; `null` = WHOIS blocked.

## Local (developer machine)

Captured 2026-07-13 · Node v25.9.0 · `elapsedMs` 1579

```json
{
  "ok": true,
  "summary": "WHOIS resolved 3/3, TLS reached 3/3",
  "whois": [
    { "domain": "google.com",    "domainAgeDays": 10528, "sslValid": true },
    { "domain": "github.com",    "domainAgeDays": 6852,  "sslValid": true },
    { "domain": "wikipedia.org", "domainAgeDays": 9312,  "sslValid": true }
  ],
  "geminiModel": "gemini-2.5-flash",
  "demoMode": true,
  "elapsedMs": 1579
}
```

## Production (Vercel)

Confirmed 2026-07-14 · `elapsedMs` ≈ 1300

```
WHOIS resolved 3/3   ·   TLS reached 3/3   ·   ~1.3s
```

## Conclusion

WHOIS and TLS resolve fully from the Vercel datacentre IP — **3/3 on both, local
and production**. Registrars are not blocking the production host, so
`domainAgeDays` is not systematically `null` in deployment and R is not corrupted.
The single largest silent-failure risk to the evaluation is closed before Phase 5.

> To append the per-domain production JSON verbatim, capture
> `GET https://<deployment>/api/health` and paste it above.

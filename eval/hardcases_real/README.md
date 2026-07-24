# Drop your real redacted emails here

These are the **strongest** items in the hard-case set: real legitimate mail that
genuinely arrived and is genuinely urgent/alarming. They anchor the legitimate
class against the "you authored your own test data" objection. Each file dropped
here is tagged `source: "real-redacted"`, `synthetic: false`, `label: 0` (legit).

## Format

One email per file. Two accepted forms:

- **`.eml`** — a raw saved email (headers + body). Best fidelity: the rule layer
  reads the real From/Reply-To/SPF headers, exactly as in production.
- **`.txt`** — plain text. Put the subject on the first line as `Subject: ...`,
  then a blank line, then the body.

## Filename convention (sets the label AND category)

`<prefix>__<anything>.eml|.txt`  — double underscore after the prefix.

**Legit (label 0) — the primary use of this folder:**

| prefix | category | examples |
|---|---|---|
| `marketing__`     | marketing-urgency      | "sale ends tonight", "last chance", cart-expiry |
| `transactional__` | transactional-urgency  | delivery/shipping notice, invoice, receipt, order |
| `security__`      | security-urgency       | login alert, fraud alert, password reset you requested |
| `internal__`      | internal-business      | payroll/deadline/IT-notice from your org |

**Threat (label 1) — for real threat emails you want in the corpus:**

| prefix | category | examples |
|---|---|---|
| `spam__`  | spam-real  | adult/dating spam, e.g. "Brunette Ready to Share Life's Joys" |
| `phish__` | phish-real | real credential-phish / fake-invoice you received |
| `scam__`  | scam-real  | advance-fee / 419 / inheritance, e.g. the UNDP notice |

e.g. `security__real_bank_login_alert.eml`, `scam__undp_advance_fee.eml`,
`spam__brunette_life_joys.eml`.
(No recognised prefix → defaults to legit `transactional-urgency`.)

After dropping a file: `python3 build_hardcases.py && python3 hardcase_run.py`
(rebuild the corpus, then score the new item — one API call, rest served from cache).

## What to redact — and what NOT to

The AI layer is **already structurally blind**: before it sees anything, the
pipeline redacts every URL and email address to `[LINK]` / `[EMAIL]`. So:

- **KEEP the urgency language, tone, structure, and subject verbatim.** That is
  the whole point — it's what the AI reads and scores.
- **KEEP real domains/company names where they aren't sensitive.** A real
  legitimate domain making the rule layer return a low R is exactly the realistic
  signal we want. Don't sanitise `amazon.com` into `example.com`.
- **STRIP genuine PII** the language doesn't need: account numbers, card digits,
  full postal addresses, your full name, order-specific tokens. Replace with a
  neutral placeholder (`[name]`, `£XX`, `#XXXX`) — keep it readable.

## Privacy

This folder is **gitignored** — nothing here is committed. Only the assembled
`eval/hardcases.jsonl` contains the redacted text, and whether *that* gets
committed is your call (it publishes your redacted mail; see the handoff note).

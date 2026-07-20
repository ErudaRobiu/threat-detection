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

## Filename convention (sets the category)

`<category>__<anything>.eml|.txt`  — double underscore after the category.

| prefix | category | examples |
|---|---|---|
| `marketing__`     | marketing-urgency      | "sale ends tonight", "last chance", cart-expiry |
| `transactional__` | transactional-urgency  | delivery/shipping notice, invoice, receipt, order |
| `security__`      | security-urgency       | login alert, fraud alert, password reset you requested |
| `internal__`      | internal-business      | payroll/deadline/IT-notice from your org |

e.g. `security__real_bank_login_alert.eml`, `transactional__dpd_delivery.txt`,
`marketing__retailer_flash_sale.txt`, `internal__payroll_cutoff.txt`.
(No recognised prefix → defaults to `transactional-urgency` with a warning.)

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

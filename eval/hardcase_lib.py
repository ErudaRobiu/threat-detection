#!/usr/bin/env python3
"""
eval/hardcase_lib.py — shared helpers for the hard-case (borderline) corpus.

Parses SpamAssassin corpus messages into (subject, body) plain text and scores
them for legit-urgent signal. Used by mine_ham.py (survey) and
build_hardcases.py (assembly). No external deps.
"""

import email
import email.policy
import re
from html.parser import HTMLParser


class _Strip(HTMLParser):
    def __init__(self):
        super().__init__()
        self.buf = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip += 1

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if not self._skip:
            self.buf.append(data)

    def text(self):
        return re.sub(r"[ \t]+", " ", "".join(self.buf))


def strip_html(html):
    p = _Strip()
    try:
        p.feed(html)
    except Exception:
        return re.sub(r"<[^>]+>", " ", html)
    return p.text()


def parse_message(raw_bytes):
    """Return (subject, body_text). body_text is plain text, HTML stripped."""
    msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)
    subject = str(msg.get("Subject", "") or "").replace("\n", " ").strip()

    plain, html = [], []
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if part.get_content_disposition() == "attachment":
                continue
            if ct == "text/plain":
                plain.append(_part_text(part))
            elif ct == "text/html":
                html.append(_part_text(part))
    else:
        ct = msg.get_content_type()
        (plain if ct == "text/plain" else html).append(_part_text(msg))

    body = "\n".join(t for t in plain if t).strip()
    if len(body) < 20 and html:
        body = strip_html("\n".join(html)).strip()
    body = re.sub(r"\n{3,}", "\n\n", body)
    return subject, body


def _part_text(part):
    try:
        payload = part.get_content()
        if isinstance(payload, bytes):
            payload = payload.decode(part.get_content_charset() or "latin-1", "replace")
        return payload
    except Exception:
        try:
            return part.get_payload(decode=True).decode("latin-1", "replace")
        except Exception:
            return ""


# --- Legit-urgent signal scoring -------------------------------------------

URGENCY = re.compile(
    r"\b(act now|hurry|expire|expires|expiring|ends?|ending|last chance|limited time|"
    r"today only|don'?t miss|deadline|final|immediately|urgent|before (it'?s )?too late|"
    r"only \d+ (days?|hours?) left|closing soon|while (stocks?|supplies) last|now)\b",
    re.I,
)
OFFER = re.compile(
    r"(\d+% ?off|\bdiscount\b|\bsale\b|\bfree\b|\boffer\b|\bsave (up to |now|\$)|"
    r"\bdeal\b|\bcoupon\b|\bsubscribe\b|\blimited\b|\bexclusive\b|\bbonus\b|guarantee)",
    re.I,
)
TRANSACT = re.compile(
    r"\b(shipp(ed|ing)|your order|tracking (number|#)|delivery|out for delivery|"
    r"invoice|payment (due|received)|receipt|confirm your|password|reset your|"
    r"account (statement|notice|activity|security)|reminder|due (date|by|on)|"
    r"renew|subscription (expir|renew)|verify)\b",
    re.I,
)


def urgent_score(subject, body):
    """Heuristic counts of urgency/offer/transactional signal in subject+body."""
    text = f"{subject}\n{body}"
    return {
        "urgency": len(URGENCY.findall(text)),
        "offer": len(OFFER.findall(text)),
        "transact": len(TRANSACT.findall(text)),
    }


def alnum_len(text):
    return len(re.sub(r"[^A-Za-z0-9]", "", text))

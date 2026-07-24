#!/usr/bin/env python3
"""
eval/build_hardcases.py — assemble the hard-case (borderline) corpus into
eval/hardcases.jsonl and print the yield breakdown by source/category/label.

The hard-case corpus exists to supply what the main 1,600 corpus lacks: items in
the flip zone — legitimate mail an urgent/alarming tone makes the semantic layer
nervous about (high A) but whose structure vouches for it (low R). Those are the
false positives the agreement gate is meant to suppress, and the smoke/gamma
sweep on this corpus is the honest test of whether the gate does measurable work.

Sources (label 1 = threat, 0 = legitimate):

  nazario      real phishing ADVERSARIAL TWINS — fake invoice/billing, fake
               delivery, fake security alert, fake account suspension. Crude 419
               / lottery / inheritance scams are excluded (they are not the hard
               case; the rule/AI layers already crush them).            label 1
  spamassassin real legitimate urgent mail mined from hard_ham/easy_ham:
               marketing-urgency and transactional-urgency.             label 0
  calibration  the 6 legit-urgent calibration seeds.                    label 0
  authored     legit-urgent emails written to fill the modern categories the 2002
               corpus lacks (security/transactional/internal). synthetic. NOT
               curated by score; kept at real label regardless of A/H.  label 0
  real-redacted anything the user dropped in hardcases_real/ (.eml/.txt); usually
               empty — SpamAssassin is the primary legit-urgent source.  label 0

Messages are reconstructed as `From:/Reply-To:/Subject:/<plain body>` so the rule
engine reads real sender structure (reply-to mismatch, sender domain) while the
AI reads clean body text. No network, no API — assembly only.

  python3 eval/build_hardcases.py            # write hardcases.jsonl + report
"""

import email
import email.policy
import glob
import hashlib
import json
import mailbox
import os
import re

from hardcase_lib import parse_message, urgent_score, alnum_len
from authored_hardcases import authored_items

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
OUT_PATH = os.path.join(HERE, "hardcases.jsonl")
REAL_DIR = os.path.join(HERE, "hardcases_real")

MIN_ALNUM, MAX_ALNUM = 60, 2500          # drop stubs and giant digests
NAZ_PER_CATEGORY = 12                     # cap twins per category for balance
MARKETING_CAP, TRANSACT_CAP = 18, 10

# ---- Nazario adversarial-twin categories (label 1) ------------------------
TWIN = {
    "invoice": re.compile(r"\b(invoice|payment (due|overdue|required)|billing|"
                          r"receipt|order (confirmation|#|number)|transaction)\b", re.I),
    "delivery": re.compile(r"\b(deliver(y|ed)|shipp(ing|ed)|parcel|package|tracking|"
                           r"courier|dispatch|customs|held)\b", re.I),
    "security": re.compile(r"\b(sign-?in|log-?in|unusual (activity|sign)|new device|"
                           r"verify your (account|identity)|security alert|password|"
                           r"unauthori[sz]ed)\b", re.I),
    "suspension": re.compile(r"\b(suspend(ed|ision)?|limited|locked|restricted|"
                             r"deactivat|closed|on hold|disabled)\b", re.I),
}
CRUDE_419 = re.compile(r"\b(lottery|winner|inheritance|next of kin|barrister|"
                       r"beneficiary|million (dollars|usd)|western union|widow|"
                       r"prince|fund transfer)\b", re.I)


def _headers(raw_bytes):
    msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)
    return (str(msg.get("From", "") or "").replace("\n", " ").strip(),
            str(msg.get("Reply-To", "") or "").replace("\n", " ").strip())


def _reconstruct(frm, reply_to, subject, body):
    lines = []
    if frm:
        lines.append(f"From: {frm}")
    if reply_to:
        lines.append(f"Reply-To: {reply_to}")
    lines.append(f"Subject: {subject}")
    return "\n".join(lines) + "\n\n" + body.strip()


def _norm_subject(s):
    return re.sub(r"[^a-z0-9]+", " ", s.lower()).strip()[:60]


# ---- collectors -----------------------------------------------------------

def collect_nazario():
    path = os.path.join(DATA, "naz_phishing3.mbox")
    if not os.path.exists(path):
        return []
    seen, per_cat = set(), {k: [] for k in TWIN}
    for m in mailbox.mbox(path):
        try:
            raw = m.as_bytes()
            subject, body = parse_message(raw)
        except Exception:
            continue
        if not (MIN_ALNUM <= alnum_len(body) <= MAX_ALNUM):
            continue
        text = f"{subject}\n{body}"
        if CRUDE_419.search(text):
            continue
        key = _norm_subject(subject)
        if not key or key in seen:
            continue
        for cat, rx in TWIN.items():
            if rx.search(subject) or len(rx.findall(text)) >= 2:
                if len(per_cat[cat]) >= NAZ_PER_CATEGORY:
                    break
                frm, reply_to = _headers(raw)
                per_cat[cat].append({
                    "content": _reconstruct(frm, reply_to, subject, body),
                    "label": 1, "category": f"{cat}-phish",
                    "source": "nazario", "synthetic": False})
                seen.add(key)
                break
    out = []
    for cat in TWIN:
        out.extend(per_cat[cat])
    return out


def _mine_ham(dirs, cap, matcher, category):
    out, seen = [], set()
    for d in dirs:
        for p in sorted(glob.glob(os.path.join(DATA, d, "*"))):
            if os.path.basename(p) in ("cmds",):
                continue
            try:
                with open(p, "rb") as f:
                    raw = f.read()
                subject, body = parse_message(raw)
            except Exception:
                continue
            if not (MIN_ALNUM <= alnum_len(body) <= MAX_ALNUM):
                continue
            # drop mailing-list digests: many links or explicit digest markers
            if body.count("http") > 8 or re.search(r"\b(digest|newsletter|unsubscribe list|vol\.)\b", subject, re.I):
                continue
            if not matcher(urgent_score(subject, body)):
                continue
            key = _norm_subject(subject)
            if not key or key in seen:
                continue
            frm, reply_to = _headers(raw)
            out.append({"content": _reconstruct(frm, reply_to, subject, body),
                        "label": 0, "category": category,
                        "source": f"spamassassin/{d}", "synthetic": False})
            seen.add(key)
            if len(out) >= cap:
                return out
    return out


def collect_marketing():
    return _mine_ham(["hard_ham"], MARKETING_CAP,
                     lambda s: (s["urgency"] >= 1 and s["offer"] >= 1) or s["offer"] >= 3,
                     "marketing-urgency")


def collect_transactional():
    return _mine_ham(["easy_ham", "easy_ham_2"], TRANSACT_CAP,
                     lambda s: s["transact"] >= 2 or (s["transact"] >= 1 and s["urgency"] >= 1),
                     "transactional-urgency")


# The 6 legit-urgent calibration seeds (label 0). Threats (1,2,3) and the plain
# non-urgent control (7) are excluded; these six are the borderline legit cases.
CALIBRATION_SEEDS = [
    ("marketing-urgency", "Subject: Senior Backend Engineer role — quick chat this week?",
     "Hi Daniel, I came across your profile and think you'd be a strong fit for a "
     "Senior Backend Engineer position with one of our clients. The team is moving "
     "fast and interview slots are filling up for this week, so it would be great "
     "to connect soon. Are you open to a 15-minute call tomorrow or Thursday? Let "
     "me know a time that works."),
    ("marketing-urgency", "Subject: Our Summer Sale ends Sunday — 20% off everything",
     "Hi Sarah! Our Summer Sale ends this Sunday at midnight. Take an extra 20% off "
     "everything with code SUN20 — don't miss out before these deals are gone. Shop "
     "now while your favourites are still in stock. You're receiving this because "
     "you subscribed to Bloom & Co updates. Unsubscribe any time."),
    ("security-urgency", "Subject: New sign-in to your account",
     "We noticed a new sign-in to your account from a new device. If this was you, "
     "no action is needed and you can ignore this message. If you don't recognise "
     "this activity, please call the number on the back of your card to speak with "
     "our support team. For your security, we will never ask for your password or "
     "PIN by email."),
    ("security-urgency", "Subject: Reset your password",
     "You recently requested to reset your password. Click the link below to choose "
     "a new one. This link will expire in 30 minutes for your security. If you "
     "didn't request a password reset, you can safely ignore this email and your "
     "password will remain unchanged.\nhttps://accounts.example.com/reset?token=abc123"),
    ("security-urgency", "Subject: Suspicious transaction blocked — action required",
     "We blocked a transaction of N85,000 on your account. If this was not you, "
     "call us immediately on the number on the back of your card. Your account has "
     "been frozen and will remain restricted until you confirm this activity. For "
     "your protection, do not share your PIN or password with anyone."),
    ("internal-business", "Subject: Payroll cutoff is 5pm TODAY",
     "Reminder: the payroll cutoff is 5pm TODAY. If your timesheet is not submitted "
     "by then, you will not be paid this month. There are no exceptions. Submit your "
     "timesheet now at:\nhttps://hr.internal.example.com/timesheet"),
]


def collect_calibration():
    return [{"content": f"{subj}\n\n{body}", "label": 0, "category": cat,
             "source": "calibration-seed", "synthetic": True}
            for cat, subj, body in CALIBRATION_SEEDS]


def collect_authored():
    return [{"content": content, "label": 0, "category": category,
             "source": "authored", "synthetic": True}
            for content, category in authored_items()]


# Realistic authored THREATS (label 1) on a REAL, clean domain with a FABRICATED
# path — the "path blind spot" case (see NOTES.md). The domain is genuine and
# passes every URL indicator; the lure lives entirely in the unexamined path, so
# the engine clears it at R=0.000. Included as a measured false negative.
AUTHORED_REALISTIC = [
    # (content, category) — real domain kwasu.edu.ng, path 'schooll' (two Ls) authored.
    ("https://kwasu.edu.ng/schooll-fee-payment", "url-path-lure"),
]


def collect_authored_realistic():
    return [{"content": content, "label": 1, "category": category,
             "source": "authored-realistic", "synthetic": True}
            for content, category in AUTHORED_REALISTIC]


# filename prefix -> (label, category). Legit prefixes keep label 0; threat
# prefixes (spam/phish/scam) set label 1 so a real threat email — e.g. the
# "Brunette Ready to Share Life's Joys" adult-dating spam — can be dropped in as
# a genuine label-1 item, not only a legit one. Convention: <prefix>__anything.eml
REAL_PREFIX = {
    "marketing":     (0, "marketing-urgency"),
    "transactional": (0, "transactional-urgency"),
    "security":      (0, "security-urgency"),
    "internal":      (0, "internal-business"),
    "spam":          (1, "spam-real"),
    "phish":         (1, "phish-real"),
    "scam":          (1, "scam-real"),
}


def collect_real_redacted():
    """User-dropped real emails in hardcases_real/ (usually empty).

    label + category come from the filename prefix (see REAL_PREFIX). A
    `spam__`/`phish__`/`scam__` prefix marks the drop as a real THREAT (label 1);
    anything else defaults to legit transactional-urgency (label 0), preserving
    the original behaviour."""
    out = []
    for p in sorted(glob.glob(os.path.join(REAL_DIR, "*"))):
        base = os.path.basename(p)
        if base == "README.md":
            continue
        prefix = base.split("__", 1)[0] if "__" in base else ""
        label, cat = REAL_PREFIX.get(prefix, (0, "transactional-urgency"))
        try:
            with open(p, "rb") as f:
                raw = f.read()
        except Exception:
            continue
        if base.endswith(".eml"):
            subject, body = parse_message(raw)
            frm, reply_to = _headers(raw)
            content = _reconstruct(frm, reply_to, subject, body)
        else:
            content = raw.decode("utf-8", "replace")
        out.append({"content": content, "label": label, "category": cat,
                    "source": "real-redacted", "synthetic": False})
    return out


def main():
    groups = {
        "nazario (twins)": collect_nazario(),
        "spamassassin marketing": collect_marketing(),
        "spamassassin transactional": collect_transactional(),
        "calibration seeds": collect_calibration(),
        "authored": collect_authored(),
        "authored-realistic (path lure)": collect_authored_realistic(),
        "real-redacted": collect_real_redacted(),
    }

    items = []
    for g in groups.values():
        items.extend(g)
    # stable id per item (content hash), and drop any exact-content dupes
    seen, deduped = set(), []
    for it in items:
        cid = hashlib.sha256(it["content"].encode("utf-8", "replace")).hexdigest()
        if cid in seen:
            continue
        seen.add(cid)
        deduped.append({"cid": cid, **it})

    with open(OUT_PATH, "w") as fh:
        for it in deduped:
            fh.write(json.dumps(it) + "\n")

    # ---- yield report -----------------------------------------------------
    legit = sum(1 for it in deduped if it["label"] == 0)
    threat = sum(1 for it in deduped if it["label"] == 1)
    real = sum(1 for it in deduped if not it["synthetic"])
    synth = sum(1 for it in deduped if it["synthetic"])
    print("=" * 70)
    print("HARD-CASE CORPUS — mined yield")
    print("=" * 70)
    print(f"{'source':<30}{'items':>7}{'label':>8}")
    print("-" * 45)
    for name, g in groups.items():
        if not g:
            print(f"{name:<30}{0:>7}{'—':>8}")
            continue
        lbl = g[0]["label"]
        print(f"{name:<30}{len(g):>7}{lbl:>8}")
    print("-" * 45)
    print(f"{'TOTAL':<30}{len(deduped):>7}")
    print(f"\n  legit (label 0): {legit}    threat (label 1): {threat}")
    print(f"  real: {real}    synthetic/authored: {synth}  "
          f"({100*synth/len(deduped):.0f}% synthetic)")
    from collections import Counter
    cats = Counter(it["category"] for it in deduped)
    print("\n  by category:")
    for c, n in sorted(cats.items()):
        print(f"    {c:<26}{n}")
    print(f"\nwrote {OUT_PATH} ({len(deduped)} items)")


if __name__ == "__main__":
    main()

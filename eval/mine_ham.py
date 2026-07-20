#!/usr/bin/env python3
"""
eval/mine_ham.py — SURVEY the SpamAssassin corpora for real legit-urgent mail.

Read-only. Prints candidate counts and samples so the real yield can be judged
before anything is committed to the hard-case set. Selection thresholds here are
deliberately loose; build_hardcases.py applies the final cut.

  python3 eval/mine_ham.py            # survey hard_ham + easy_ham
  python3 eval/mine_ham.py --show 30  # show more samples
"""

import argparse
import glob
import os

from hardcase_lib import parse_message, urgent_score, alnum_len

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")


def load_dir(name):
    out = []
    for p in sorted(glob.glob(os.path.join(DATA, name, "*"))):
        if os.path.basename(p) in ("cmds",):
            continue
        try:
            with open(p, "rb") as f:
                subject, body = parse_message(f.read())
        except Exception:
            continue
        if alnum_len(body) < 40:
            continue
        out.append((os.path.basename(p), subject, body))
    return out


def survey(name, kind, show):
    msgs = load_dir(name)
    cands = []
    for fn, subject, body in msgs:
        s = urgent_score(subject, body)
        if kind == "marketing":
            hit = (s["urgency"] >= 1 and s["offer"] >= 1) or s["offer"] >= 3
        else:  # transactional
            hit = s["transact"] >= 2 or (s["transact"] >= 1 and s["urgency"] >= 1)
        if hit:
            cands.append((s, fn, subject, body))
    cands.sort(key=lambda c: -(c[0]["urgency"] + c[0]["offer"] + c[0]["transact"]))

    print(f"\n{'='*78}\n{name}  ->  {kind}-urgent candidates: {len(cands)} / {len(msgs)} parsed")
    print("=" * 78)
    for s, fn, subject, body in cands[:show]:
        sig = f"u{s['urgency']} o{s['offer']} t{s['transact']}"
        snippet = " ".join(body.split())[:140]
        print(f"[{sig:<10}] {subject[:66]}")
        print(f"             {snippet}")
    return cands


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--show", type=int, default=18)
    args = ap.parse_args()
    survey("hard_ham", "marketing", args.show)
    survey("easy_ham", "transactional", args.show)
    survey("easy_ham_2", "transactional", args.show)


if __name__ == "__main__":
    main()

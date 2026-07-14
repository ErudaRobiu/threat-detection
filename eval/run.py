#!/usr/bin/env python3
"""
eval/run.py — Phase 5 evaluation harness (skeleton).

Drives POST /api/analyze over the corpora, caches every response by content hash
(so the run is resumable and reruns are free), and computes metrics for the HTSA
conditions. Conditions 3 and 4 (the two gamma settings) are recomputed from the
cached R and A with NO additional API calls, exactly as the design intends.

Conditions:
  1  Rule only          R thresholded at 0.3
  2  AI only            A thresholded at 0.3   -- EMAIL corpus only (see below)
  3  HTSA gamma = 0     ablation, recomputed from cached R, A
  4  HTSA gamma = 0.2   the deployed system (H returned by the API)
  5  Random Forest      lexical URL features -- see baseline.py (not run here)

Condition 2 is reported on the EMAIL corpus only: the AI abstains on bare URLs
(A is null), so thresholding A there is undefined. Scoring abstained URLs as
A = 0 would fabricate a perfect AI false-negative rate. See NOTES.md.

Usage:
  python3 eval/run.py --limit 50                 # stratified smoke test
  python3 eval/run.py                            # full 1,600
  EVAL_BASE_URL=https://x.vercel.app python3 eval/run.py
"""

import argparse
import glob
import hashlib
import json
import mailbox
import os
import random
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
CACHE_PATH = os.path.join(HERE, "cache.json")
BASE_URL = os.environ.get("EVAL_BASE_URL", "http://127.0.0.1:3210").rstrip("/")
MAX_CONTENT = 100_000
SEED = 42
THRESHOLD = 0.3

# Target class sizes for the full corpus.
TARGETS = {("url", 0): 500, ("url", 1): 500, ("email", 0): 300, ("email", 1): 300}


# --------------------------------------------------------------------------
# Corpus loading
# --------------------------------------------------------------------------

def _read_text(path):
    with open(path, "rb") as f:
        return f.read().decode("latin-1", "replace")


def load_items():
    """Return list of dicts: {cid, content, label, kind, src}. label 1 = threat."""
    rng = random.Random(SEED)
    buckets = {k: [] for k in TARGETS}

    # URLs (one per line)
    for fn, label in [("urls_legit.txt", 0), ("urls_phish.txt", 1)]:
        p = os.path.join(DATA, fn)
        if os.path.exists(p):
            for line in _read_text(p).splitlines():
                line = line.strip()
                if line.startswith("http"):
                    buckets[("url", label)].append((line, fn))

    # Legitimate emails: SpamAssassin easy_ham files
    ham = []
    for d in ("easy_ham", "easy_ham_2"):
        for p in glob.glob(os.path.join(DATA, d, "*")):
            if os.path.basename(p) == "cmds":
                continue
            ham.append((_read_text(p)[:MAX_CONTENT], f"spamassassin/{d}"))
    rng.shuffle(ham)
    buckets[("email", 0)] = ham

    # Phishing emails: Nazario mbox
    mbox_path = os.path.join(DATA, "naz_phishing3.mbox")
    naz = []
    if os.path.exists(mbox_path):
        for msg in mailbox.mbox(mbox_path):
            try:
                naz.append((msg.as_string()[:MAX_CONTENT], "nazario/phishing3"))
            except Exception:
                continue
    rng.shuffle(naz)
    buckets[("email", 1)] = naz

    items = []
    for (kind, label), target in TARGETS.items():
        chosen = buckets[(kind, label)][:target]
        for content, src in chosen:
            items.append(
                {"cid": hashlib.sha256(content.encode("utf-8", "replace")).hexdigest(),
                 "content": content, "label": label, "kind": kind, "src": src}
            )
    return items


def stratified_subset(items, limit):
    if limit is None or limit >= len(items):
        return items
    rng = random.Random(SEED)
    by_class = {}
    for it in items:
        by_class.setdefault((it["kind"], it["label"]), []).append(it)
    per = max(1, limit // len(by_class))
    out = []
    for cls, group in by_class.items():
        rng.shuffle(group)
        out.extend(group[:per])
    return out[:limit]


# --------------------------------------------------------------------------
# API + cache
# --------------------------------------------------------------------------

def load_cache():
    if os.path.exists(CACHE_PATH):
        with open(CACHE_PATH) as f:
            return json.load(f)
    return {}


def save_cache(cache):
    tmp = CACHE_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(cache, f)
    os.replace(tmp, CACHE_PATH)


def call_api(content):
    body = json.dumps({"content": content[:MAX_CONTENT]}).encode()
    req = urllib.request.Request(
        BASE_URL + "/api/analyze", data=body, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=90) as r:
            d = json.load(r)
            return {"R": d.get("ruleScore"), "A": d.get("aiScore"),
                    "H": d.get("hybridScore"), "cls": d.get("classification")}
    except urllib.error.HTTPError as e:
        try:
            msg = json.load(e).get("error", str(e))
        except Exception:
            msg = str(e)
        return {"error": f"{e.code}: {msg}"}
    except Exception as e:  # noqa
        return {"error": str(e)}


# --------------------------------------------------------------------------
# Fusion (mirror of core/htsa.ts) and metrics
# --------------------------------------------------------------------------

def fuse_H(R, A, gamma):
    if R is None and A is None:
        return None
    if R is None:
        return A
    if A is None:
        return R
    a = b = (1.0 - gamma) / 2.0
    return a * R + b * A + gamma * R * A


def metrics(rows, predict, applies=lambda r: True):
    tp = fp = tn = fn = 0
    for r in rows:
        if r.get("error") or not applies(r):
            continue
        p = predict(r)
        if p is None:
            continue
        y = r["label"]
        if p and y:
            tp += 1
        elif p and not y:
            fp += 1
        elif not p and not y:
            tn += 1
        else:
            fn += 1
    n = tp + fp + tn + fn
    acc = (tp + tn) / n if n else 0.0
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    return {"n": n, "acc": acc, "prec": prec, "rec": rec, "f1": f1,
            "tp": tp, "fp": fp, "tn": tn, "fn": fn}


def report(rows):
    def rule(r):
        return r["R"] is not None and r["R"] >= THRESHOLD

    def ai(r):
        return r["A"] is not None and r["A"] >= THRESHOLD

    def htsa(g):
        def f(r):
            h = fuse_H(r["R"], r["A"], g)
            return h is not None and h >= THRESHOLD
        return f

    is_email = lambda r: r["kind"] == "email"
    is_defined_A = lambda r: r["A"] is not None

    conditions = [
        ("1  Rule only            (R>=0.3)", metrics(rows, rule)),
        ("2  AI only  [email only](A>=0.3)", metrics(rows, ai, applies=lambda r: is_email(r) and is_defined_A(r))),
        ("3  HTSA gamma=0 ablation(H>=0.3)", metrics(rows, htsa(0.0))),
        ("4  HTSA gamma=0.2  real (H>=0.3)", metrics(rows, htsa(0.2))),
    ]
    hdr = f"{'condition':<34}{'n':>5}{'acc':>8}{'prec':>8}{'rec':>8}{'f1':>8}   confusion (tp fp tn fn)"
    print("\n" + hdr)
    print("-" * len(hdr))
    for name, m in conditions:
        print(f"{name:<34}{m['n']:>5}{m['acc']:>8.3f}{m['prec']:>8.3f}{m['rec']:>8.3f}{m['f1']:>8.3f}"
              f"   {m['tp']} {m['fp']} {m['tn']} {m['fn']}")

    # AI-abstention accounting — the reason Condition 2 is email-only.
    url_rows = [r for r in rows if r["kind"] == "url" and not r.get("error")]
    abstained = sum(1 for r in url_rows if r["A"] is None)
    print(f"\nAI abstained on {abstained}/{len(url_rows)} URL items "
          f"(Condition 2 is undefined for these; reported on emails only).")


# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=None, help="stratified subset size (smoke test)")
    args = ap.parse_args()

    items = load_items()
    counts = {}
    for it in items:
        counts[(it["kind"], it["label"])] = counts.get((it["kind"], it["label"]), 0) + 1
    print(f"loaded corpus: {len(items)} items  "
          f"[url legit {counts.get(('url',0),0)} / phish {counts.get(('url',1),0)} | "
          f"email legit {counts.get(('email',0),0)} / phish {counts.get(('email',1),0)}]")

    run_items = stratified_subset(items, args.limit)
    print(f"running {len(run_items)} items against {BASE_URL}\n")

    cache = load_cache()
    rows = []
    t0 = time.time()
    for i, it in enumerate(run_items, 1):
        cached = cache.get(it["cid"])
        if cached is not None and "error" not in cached:
            res = cached
        else:
            res = call_api(it["content"])
            if "error" not in res:  # never persist a failure — let it retry next run
                cache[it["cid"]] = res
                if i % 10 == 0:
                    save_cache(cache)
        rows.append({**it, **res})
        tag = res.get("error") or f"R={_f(res.get('R'))} A={_f(res.get('A'))} H={_f(res.get('H'))} {res.get('cls')}"
        print(f"[{i:>4}/{len(run_items)}] {it['kind']:<5} y={it['label']} {tag}")
    save_cache(cache)

    errors = sum(1 for r in rows if r.get("error"))
    print(f"\ndone in {time.time()-t0:.1f}s · cache: {len(cache)} entries · errors: {errors}/{len(rows)}")
    report(rows)


def _f(x):
    return "null" if x is None else f"{x:.3f}"


if __name__ == "__main__":
    main()

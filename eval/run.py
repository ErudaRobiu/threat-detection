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
import csv
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
# seconds to sleep after each LIVE (non-cached) call, to stay under the Gemini
# free-tier RPM limit. Cached items never sleep, so a resumed run flies through
# what it already has. Override with EVAL_THROTTLE_SEC.
THROTTLE = float(os.environ.get("EVAL_THROTTLE_SEC", "4.0"))

# Target class sizes for the full corpus.
TARGETS = {("url", 0): 500, ("url", 1): 500, ("email", 0): 300, ("email", 1): 300}


# --------------------------------------------------------------------------
# Corpus loading
# --------------------------------------------------------------------------

def _read_text(path):
    with open(path, "rb") as f:
        return f.read().decode("latin-1", "replace")


def load_items(url_mode="domain"):
    """Return list of dicts: {cid, content, label, kind, src}. label 1 = threat.

    url_mode: 'domain' (default) loads the registrable-domain-normalised URL
    corpus (urls_*_domain.txt, produced by normalise_urls.py) which removes the
    collection-shape artefact; 'raw' loads the as-collected full URLs
    (urls_*.txt) to reproduce the artefact-laden corpus for the Ch4 comparison.
    See NOTES.md "the URL corpus is trivially separable by a collection artefact".
    """
    rng = random.Random(SEED)
    buckets = {k: [] for k in TARGETS}

    if url_mode == "raw":
        url_files = [("urls_legit.txt", 0), ("urls_phish.txt", 1)]
    else:
        url_files = [("urls_legit_domain.txt", 0), ("urls_phish_domain.txt", 1)]

    # URLs (one per line)
    for fn, label in url_files:
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


def call_api(content, retries=4):
    """One /api/analyze call. On HTTP 429 (rate limit) back off and retry.
    Returns aiAvailable so the caller can refuse to cache a DEGRADED (A=R)
    result — a rate-limited item must retry on the next run, never poison the
    cache with a fabricated A."""
    body = json.dumps({"content": content[:MAX_CONTENT]}).encode()
    backoff = 10.0
    for attempt in range(retries + 1):
        req = urllib.request.Request(
            BASE_URL + "/api/analyze", data=body, headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=90) as r:
                d = json.load(r)
                return {"R": d.get("ruleScore"), "A": d.get("aiScore"),
                        "H": d.get("hybridScore"), "cls": d.get("classification"),
                        "aiAvailable": d.get("aiAvailable")}
        except urllib.error.HTTPError as e:
            # 429 = rate limit; 404/5xx from a route that DOES exist (health OK,
            # GET gives 405) is a transient next-dev hiccup over a long run, not a
            # real miss. Retry both with backoff before giving up on the item.
            if e.code in (429, 404, 500, 502, 503, 504) and attempt < retries:
                time.sleep(backoff)
                backoff *= 2
                continue
            try:
                msg = json.load(e).get("error", str(e))
            except Exception:
                msg = str(e)
            return {"error": f"{e.code}: {msg}"}
        except Exception as e:  # noqa
            if attempt < retries:
                time.sleep(backoff)
                backoff *= 2
                continue
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


def binary(pairs, t):
    """Confusion + rates for scored (score, label) pairs thresholded at t."""
    p = [(s, y) for s, y in pairs if s is not None]
    tp = sum(1 for s, y in p if s >= t and y == 1)
    fp = sum(1 for s, y in p if s >= t and y == 0)
    P = sum(1 for _, y in p if y == 1)
    N = len(p) - P
    fn, tn = P - tp, N - fp
    n = len(p)
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / P if P else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    return {"n": n, "acc": (tp + tn) / n if n else 0.0, "prec": prec, "rec": rec, "f1": f1,
            "fpr": fp / N if N else 0.0, "fnr": fn / P if P else 0.0,
            "tp": tp, "fp": fp, "tn": tn, "fn": fn}


def auc(pairs):
    """Rank-based ROC AUC (Mann-Whitney)."""
    p = [(s, y) for s, y in pairs if s is not None]
    pos = [s for s, y in p if y == 1]
    neg = [s for s, y in p if y == 0]
    if not pos or not neg:
        return None
    c = 0.0
    for a in pos:
        for b in neg:
            c += 1.0 if a > b else (0.5 if a == b else 0.0)
    return c / (len(pos) * len(neg))


def sweep(pairs, step=0.01):
    """(t, prec, rec, f1, fpr) across thresholds 0..1."""
    rows, t = [], 0.0
    while t <= 1.0 + 1e-9:
        m = binary(pairs, t)
        rows.append((round(t, 2), m["prec"], m["rec"], m["f1"], m["fpr"]))
        t += step
    return rows


def report(rows):
    os.makedirs(os.path.join(HERE, "out"), exist_ok=True)
    ok = [r for r in rows if not r.get("error")]
    is_email = lambda r: r["kind"] == "email"

    conds = {
        "1 rule       ": [(r["R"], r["label"]) for r in ok],
        "2 ai [email] ": [(r["A"], r["label"]) for r in ok if is_email(r) and r["A"] is not None],
        "3 HTSA gamma0": [(fuse_H(r["R"], r["A"], 0.0), r["label"]) for r in ok],
        "4 HTSA gam0.2": [(fuse_H(r["R"], r["A"], 0.2), r["label"]) for r in ok],
    }

    # --- Binary @0.3 with FP/FN rates and threshold-free AUC ---
    print(f"\n{'condition':<14}{'n':>5}{'acc':>7}{'prec':>7}{'rec':>7}{'f1':>7}{'fpr':>7}{'fnr':>7}{'auc':>7}   (tp fp tn fn)")
    print("-" * 92)
    metric_rows = []
    for name, pairs in conds.items():
        m = binary(pairs, THRESHOLD)
        a = auc(pairs)
        astr = f"{a:>7.3f}" if a is not None else f"{'--':>7}"
        print(f"{name:<14}{m['n']:>5}{m['acc']:>7.3f}{m['prec']:>7.3f}{m['rec']:>7.3f}{m['f1']:>7.3f}"
              f"{m['fpr']:>7.3f}{m['fnr']:>7.3f}{astr}   {m['tp']} {m['fp']} {m['tn']} {m['fn']}")
        metric_rows.append({"condition": name.strip(), "n": m["n"], "acc": m["acc"],
                            "prec": m["prec"], "rec": m["rec"], "f1": m["f1"],
                            "fpr": m["fpr"], "fnr": m["fnr"],
                            "auc": "" if a is None else f"{a:.4f}",
                            "tp": m["tp"], "fp": m["fp"], "tn": m["tn"], "fn": m["fn"]})

    # machine-readable per-condition metrics for charts.py (Condition 5/RF is
    # merged in by charts.py from baseline_preds.csv; run.py never calls the RF).
    with open(os.path.join(HERE, "out", "metrics.csv"), "w", newline="") as fh:
        cols = ["condition", "n", "acc", "prec", "rec", "f1", "fpr", "fnr", "auc",
                "tp", "fp", "tn", "fn"]
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        for row in metric_rows:
            w.writerow(row)

    # --- Threshold sweep: F1 at each condition's OWN optimal threshold ---
    print("\nF1 at each condition's optimal threshold (full 0..1 sweep):")
    sw = {}
    for name, pairs in conds.items():
        s = sweep(pairs)
        sw[name] = s
        best = max(s, key=lambda r: r[3])
        print(f"  {name}: best F1 {best[3]:.3f} at t={best[0]:.2f}  (prec {best[1]:.3f}, rec {best[2]:.3f}, fpr {best[4]:.3f})")
    # write gamma sweeps for plotting
    with open(os.path.join(HERE, "out", "sweep.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["t", "g0_prec", "g0_rec", "g0_f1", "g0_fpr", "g02_prec", "g02_rec", "g02_f1", "g02_fpr"])
        for g0, g02 in zip(sw["3 HTSA gamma0"], sw["4 HTSA gam0.2"]):
            w.writerow([g0[0], *g0[1:], *g02[1:]])

    # --- Gate suppression and the flip zone (both from cache, no API calls) ---
    both = [r for r in ok if r["R"] is not None and r["A"] is not None]
    supp = [((r["R"] + r["A"]) / 2 - fuse_H(r["R"], r["A"], 0.2)) for r in both]
    band = [r for r in both if 0.25 <= (r["R"] + r["A"]) / 2 <= 0.40]
    print("\ngate suppression  mean(R,A) - H(gamma=0.2):")
    print(f"  items with both R and A: {len(both)}")
    print(f"  mean suppression: {sum(supp)/len(supp):.4f}" if supp else "  mean suppression: n/a")
    print(f"  max  suppression: {max(supp):.4f}" if supp else "  max  suppression: n/a")
    print(f"  flip-zone 0.25<=mean(R,A)<=0.40: {len(band)} items  "
          f"(if empty, more data will NOT create a gate effect)")

    # scatter data: |R-A| vs suppression, and per-item R/A/H
    with open(os.path.join(HERE, "out", "scatter.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["abs_R_minus_A", "suppression", "R", "A", "H", "label", "kind"])
        for r in both:
            s = (r["R"] + r["A"]) / 2 - fuse_H(r["R"], r["A"], 0.2)
            w.writerow([abs(r["R"] - r["A"]), s, r["R"], r["A"], r["H"], r["label"], r["kind"]])

    url_rows = [r for r in ok if r["kind"] == "url"]
    abstained = sum(1 for r in url_rows if r["A"] is None)
    print(f"\nAI abstained on {abstained}/{len(url_rows)} URL items (Condition 2 is email-only, by design).")
    print(f"wrote eval/out/sweep.csv and eval/out/scatter.csv for charts.py")


# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=None, help="stratified subset size (smoke test)")
    ap.add_argument("--url-mode", choices=["domain", "raw"], default="domain",
                    help="'domain' (default, artefact-free) or 'raw' (as-collected full URLs)")
    ap.add_argument("--email-first", action="store_true",
                    help="process EMAIL items before URL items (resume the rate-limit-"
                         "starved email class first; emails need no WHOIS/TLS so they are fast)")
    args = ap.parse_args()

    # optional wall-clock cap (env), for a resume the author wants bounded to N hours.
    max_runtime = float(os.environ.get("EVAL_MAX_RUNTIME_SEC", "0"))  # 0 = no cap

    print(f"url-mode: {args.url_mode}")
    items = load_items(url_mode=args.url_mode)
    counts = {}
    for it in items:
        counts[(it["kind"], it["label"])] = counts.get((it["kind"], it["label"]), 0) + 1
    print(f"loaded corpus: {len(items)} items  "
          f"[url legit {counts.get(('url',0),0)} / phish {counts.get(('url',1),0)} | "
          f"email legit {counts.get(('email',0),0)} / phish {counts.get(('email',1),0)}]")

    run_items = stratified_subset(items, args.limit)
    if args.email_first:
        # stable reorder: emails first, then urls, then text. Cached items are
        # skipped instantly, so this puts the UNCACHED email work at the front.
        order = {"email": 0, "url": 1, "text": 2}
        run_items = sorted(run_items, key=lambda it: order.get(it["kind"], 3))
        print("EMAIL-FIRST ordering: emails re-scored before any remaining URLs.")
    if max_runtime:
        print(f"wall-clock cap: {max_runtime/3600:.1f}h (graceful stop, cache saved).")
    print(f"running {len(run_items)} items against {BASE_URL}\n")

    cache = load_cache()
    rows = []
    live = degraded = 0
    t0 = time.time()
    for i, it in enumerate(run_items, 1):
        cached = cache.get(it["cid"])
        if cached is not None and "error" not in cached:
            res = cached
        else:
            res = call_api(it["content"])
            live += 1
            # Only persist a genuine result. A DEGRADED result (Gemini failed ->
            # A=R, aiAvailable false) is not a real A; skip caching so it retries
            # next run instead of fabricating the semantic layer for this item.
            if "error" not in res and res.get("aiAvailable") is not False:
                cache[it["cid"]] = res
                if i % 10 == 0:
                    save_cache(cache)
            elif res.get("aiAvailable") is False:
                degraded += 1
            if THROTTLE > 0:
                time.sleep(THROTTLE)  # live calls only; cached items don't sleep
        rows.append({**it, **res})
        tag = res.get("error") or f"R={_f(res.get('R'))} A={_f(res.get('A'))} H={_f(res.get('H'))} {res.get('cls')}"
        deg = " DEGRADED(A=R)" if res.get("aiAvailable") is False else ""
        print(f"[{i:>4}/{len(run_items)}] {it['kind']:<5} y={it['label']} {tag}{deg}")
        # progress summary every 50 items
        if i % 50 == 0:
            errs = sum(1 for r in rows if r.get("error"))
            print(f"  --- progress {i}/{len(run_items)} · {time.time()-t0:.0f}s · "
                  f"live {live} · degraded {degraded} · errors {errs} · cache {len(cache)} ---")
            save_cache(cache)
        # graceful wall-clock cap: stop, save, report on what we have
        if max_runtime and time.time() - t0 > max_runtime:
            print(f"\n*** wall-clock cap {max_runtime/3600:.1f}h reached at item {i}; "
                  f"stopping gracefully (partial). ***")
            break
    save_cache(cache)

    errors = sum(1 for r in rows if r.get("error"))
    print(f"\ndone in {time.time()-t0:.1f}s · cache: {len(cache)} entries · "
          f"live: {live} · degraded(not cached): {degraded} · errors: {errors}/{len(rows)}")
    report(rows)


def _f(x):
    return "null" if x is None else f"{x:.3f}"


if __name__ == "__main__":
    main()

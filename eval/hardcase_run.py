#!/usr/bin/env python3
"""
eval/hardcase_run.py — drive the hard-case corpus (hardcases.jsonl) against the
deployed API and report the gate-relevant metrics. Separate cache
(hardcases_cache.json, gitignored) so it never mixes with the main run.

Reports, per the handoff:
  binary metrics @0.3 with PRECISION and RECALL kept SEPARATE (never F1 alone)
  AUC (threshold-free)
  best-F1 over a full threshold sweep
  gamma sweep 0.0..0.9 (recomputed from cached R,A — the gate's own test here)
  mean / max gate suppression
  flip-zone count (borderline items where the gate can actually act)

  python3 eval/hardcase_run.py            # needs the dev server on :3210
  EVAL_BASE_URL=https://x.vercel.app python3 eval/hardcase_run.py
"""

import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import run  # call_api, binary, auc, sweep, fuse_H, THRESHOLD

HARD_PATH = os.path.join(HERE, "hardcases.jsonl")
CACHE_PATH = os.path.join(HERE, "hardcases_cache.json")
OUT = os.path.join(HERE, "out")
THRESHOLD = run.THRESHOLD


def load_cache():
    if os.path.exists(CACHE_PATH):
        with open(CACHE_PATH) as f:
            return json.load(f)
    return {}


def save_cache(c):
    tmp = CACHE_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(c, f)
    os.replace(tmp, CACHE_PATH)


def main():
    if not os.path.exists(HARD_PATH):
        sys.exit("no hardcases.jsonl — run eval/build_hardcases.py first.")
    items = [json.loads(l) for l in open(HARD_PATH) if l.strip()]
    print(f"hard-case corpus: {len(items)} items "
          f"(legit {sum(1 for i in items if i['label']==0)} / "
          f"threat {sum(1 for i in items if i['label']==1)})")
    print(f"driving {run.BASE_URL}\n")

    cache = load_cache()
    rows, errors = [], 0
    t0 = time.time()
    for i, it in enumerate(items, 1):
        c = cache.get(it["cid"])
        if c is not None and "error" not in c:
            res = c
        else:
            res = run.call_api(it["content"])
            if "error" not in res:
                cache[it["cid"]] = res
                if i % 10 == 0:
                    save_cache(cache)
        if "error" in res:
            errors += 1
        rows.append({**it, **res})
        tag = res.get("error") or (f"R={run._f(res.get('R'))} A={run._f(res.get('A'))} "
                                   f"H={run._f(res.get('H'))} {res.get('cls')}")
        print(f"[{i:>3}/{len(items)}] y={it['label']} {it['category']:<22} {tag}")
    save_cache(cache)

    ok = [r for r in rows if not r.get("error")]
    print(f"\ndone in {time.time()-t0:.1f}s · errors {errors}/{len(rows)} · scored {len(ok)}")
    if not ok:
        sys.exit("no scored items — is the dev server up with GEMINI creds?")

    # ---- binary @0.3, precision and recall SEPARATE, plus AUC -------------
    conds = {
        "rule R        ": [(r["R"], r["label"]) for r in ok],
        "AI A          ": [(r["A"], r["label"]) for r in ok if r["A"] is not None],
        "HTSA gamma=0  ": [(run.fuse_H(r["R"], r["A"], 0.0), r["label"]) for r in ok],
        "HTSA gamma=0.2": [(run.fuse_H(r["R"], r["A"], 0.2), r["label"]) for r in ok],
    }
    print(f"\n{'condition':<15}{'n':>4}{'prec':>7}{'rec':>7}{'f1':>7}{'fpr':>7}"
          f"{'fnr':>7}{'auc':>7}   (tp fp tn fn)")
    print("-" * 76)
    for name, pairs in conds.items():
        m = run.binary(pairs, THRESHOLD)
        a = run.auc(pairs)
        astr = f"{a:>7.3f}" if a is not None else f"{'--':>7}"
        print(f"{name:<15}{m['n']:>4}{m['prec']:>7.3f}{m['rec']:>7.3f}{m['f1']:>7.3f}"
              f"{m['fpr']:>7.3f}{m['fnr']:>7.3f}{astr}   {m['tp']} {m['fp']} {m['tn']} {m['fn']}")

    print("\nbest-F1 over full threshold sweep:")
    for name, pairs in conds.items():
        best = max(run.sweep(pairs), key=lambda x: x[3])
        print(f"  {name}: F1 {best[3]:.3f} @t={best[0]:.2f} (prec {best[1]:.3f}, rec {best[2]:.3f})")

    # ---- gamma sweep 0.0..0.9 (the gate's real test on borderline data) ----
    both = [r for r in ok if r["R"] is not None and r["A"] is not None]
    print(f"\ngamma sweep (items with both R and A: {len(both)}):")
    print(f"{'gamma':>6}{'bestF1':>8}{'@t':>6}{'AUC':>8}{'FPR@.3':>8}"
          f"{'meanSup':>9}{'maxSup':>8}{'FPsuppressed':>13}")
    base_fp = None
    g = 0.0
    while g <= 0.9 + 1e-9:
        pairs = [(run.fuse_H(r["R"], r["A"], g), r["label"]) for r in ok]
        best = max(run.sweep(pairs), key=lambda x: x[3])
        a = run.auc(pairs)
        m = run.binary(pairs, THRESHOLD)
        supp = [((r["R"] + r["A"]) / 2 - run.fuse_H(r["R"], r["A"], g)) for r in both]
        ms = sum(supp) / len(supp) if supp else 0.0
        mx = max(supp) if supp else 0.0
        if base_fp is None:
            base_fp = m["fp"]
        fp_supp = base_fp - m["fp"]  # false positives removed vs gamma=0
        astr = f"{a:.3f}" if a is not None else "--"
        print(f"{g:>6.2f}{best[3]:>8.3f}{best[0]:>6.2f}{astr:>8}{m['fpr']:>8.3f}"
              f"{ms:>9.4f}{mx:>8.4f}{fp_supp:>13}")
        g += 0.05

    # ---- suppression + flip zone -----------------------------------------
    supp = [((r["R"] + r["A"]) / 2 - run.fuse_H(r["R"], r["A"], 0.2)) for r in both]
    band = [r for r in both if 0.25 <= (r["R"] + r["A"]) / 2 <= 0.40]
    band_legit = sum(1 for r in band if r["label"] == 0)
    print(f"\ngate suppression @gamma=0.2:  mean {sum(supp)/len(supp):.4f}  "
          f"max {max(supp):.4f}" if supp else "no dual-layer items")
    print(f"flip zone 0.25<=mean(R,A)<=0.40: {len(band)} items "
          f"({band_legit} legit / {len(band)-band_legit} threat)")
    print("  -> legit items in the flip zone are exactly what the gate suppresses; "
          "if >0 and\n     FPsuppressed>0 above, the gate does measurable work on this corpus.")

    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "hardcase_scatter.csv"), "w") as fh:
        fh.write("abs_R_minus_A,suppression,R,A,H,label,category,source,synthetic\n")
        for r in both:
            s = (r["R"] + r["A"]) / 2 - run.fuse_H(r["R"], r["A"], 0.2)
            fh.write(f"{abs(r['R']-r['A']):.4f},{s:.4f},{r['R']:.4f},{r['A']:.4f},"
                     f"{run._f(r.get('H'))},{r['label']},{r['category']},{r['source']},"
                     f"{r['synthetic']}\n")
    print(f"\nwrote out/hardcase_scatter.csv")


if __name__ == "__main__":
    main()

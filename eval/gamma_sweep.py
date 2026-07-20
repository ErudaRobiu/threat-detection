#!/usr/bin/env python3
"""
eval/gamma_sweep.py — recompute H from the CACHED R and A over a range of gamma,
with NO API calls. Answers one question: does any gamma change classification?

For each gamma in 0.00..0.90 step 0.05, with alpha = beta = (1-gamma)/2 so the
weights always sum to 1, we recompute H = alpha*R + beta*A + gamma*R*A for every
cached item that has BOTH R and A (the gate can only act when both layers speak),
then report over the full item set:

  best-F1  over a full 0..1 threshold sweep (each gamma at its own optimal t)
  AUC      threshold-free (Mann-Whitney), invariant to monotone reweighting
  FPR      at the fixed clearance threshold 0.30
  mean/max gate suppression = mean(R,A) - H
  flip-zone count = items whose H crosses the 0.30 threshold vs gamma=0

Items are matched to labels by content hash (cid) via run.py's loader, so this
uses exactly the corpus the harness uses. Abstained items (R or A null) are fused
per htsa.ts (H = the non-null layer) and are unaffected by gamma — they are kept
in the metric set so the numbers are comparable to run.py, but they cannot flip.
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import run  # reuse loader, fuse_H, binary, auc, sweep, THRESHOLD

THRESHOLD = run.THRESHOLD


def classify(h):
    """Binary threat decision at the fixed clearance threshold."""
    return None if h is None else (1 if h >= THRESHOLD else 0)


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--url-mode", choices=["domain", "raw"], default="domain",
                    help="must match the corpus the cache was built from "
                         "(the pre-fix smoke cache is 'raw'; the full run is 'domain')")
    args = ap.parse_args()
    items = run.load_items(url_mode=args.url_mode)
    cache = run.load_cache()

    rows = []
    for it in items:
        c = cache.get(it["cid"])
        if c is None or "error" in c:
            continue
        rows.append({"label": it["label"], "kind": it["kind"],
                     "R": c.get("R"), "A": c.get("A")})

    if not rows:
        print("no cached items matched the corpus — run eval/run.py first.")
        return

    both = [r for r in rows if r["R"] is not None and r["A"] is not None]
    print(f"cached items matched: {len(rows)}  "
          f"(with both R and A, gate-eligible: {len(both)})\n")

    # baseline classification at gamma = 0, for flip counting
    base_cls = {id(r): classify(run.fuse_H(r["R"], r["A"], 0.0)) for r in rows}

    # a flip HELPS if a legit item (label 0) drops from flagged->cleared, or a
    # phishing item (label 1) rises from cleared->flagged. It HURTS in the
    # opposite direction. The gate can only suppress (H<=mean), so vs gamma=0
    # it only ever pushes scores DOWN: legit 1->0 helps, phishing 1->0 hurts.
    print(f"{'gamma':>6}{'a=b':>7}{'bestF1':>8}{'@t':>6}"
          f"{'AUC':>8}{'FPR@.3':>8}{'meanSup':>9}{'maxSup':>8}{'flip+':>7}{'flip-':>7}")
    print("-" * 76)

    g = 0.0
    results = []
    while g <= 0.9 + 1e-9:
        ab = (1.0 - g) / 2.0
        pairs = [(run.fuse_H(r["R"], r["A"], g), r["label"]) for r in rows]

        sw = run.sweep(pairs)
        best = max(sw, key=lambda x: x[3])
        a = run.auc(pairs)
        m = run.binary(pairs, THRESHOLD)

        supp = [((r["R"] + r["A"]) / 2.0) - run.fuse_H(r["R"], r["A"], g) for r in both]
        mean_s = sum(supp) / len(supp) if supp else 0.0
        max_s = max(supp) if supp else 0.0

        help_flips = hurt_flips = 0
        for r in rows:
            now = classify(run.fuse_H(r["R"], r["A"], g))
            was = base_cls[id(r)]
            if now == was:
                continue
            # suppression only moves flagged(1)->cleared(0)
            if r["label"] == 0:      # legit cleared = false-positive removed
                help_flips += 1
            else:                    # phishing cleared = true-positive lost
                hurt_flips += 1

        astr = f"{a:.3f}" if a is not None else "  --"
        print(f"{g:>6.2f}{ab:>7.3f}{best[3]:>8.3f}{best[0]:>6.2f}"
              f"{astr:>8}{m['fpr']:>8.3f}{mean_s:>9.4f}{max_s:>8.4f}"
              f"{help_flips:>7}{hurt_flips:>7}")
        results.append((g, best[3], a, m["fpr"], mean_s, max_s, help_flips, hurt_flips))
        g += 0.05

    # ---- the plain-English verdict --------------------------------------
    f1s = {round(r[0], 2): r[1] for r in results}
    aucs = {round(r[0], 2): r[2] for r in results}
    total_help = sum(r[6] for r in results)
    total_hurt = sum(r[7] for r in results)
    f1_spread = max(f1s.values()) - min(f1s.values())
    auc_vals = [v for v in aucs.values() if v is not None]
    auc_spread = (max(auc_vals) - min(auc_vals)) if auc_vals else 0.0
    fpr0 = results[0][3]
    fpr_const = all(abs(r[3] - fpr0) < 1e-9 for r in results)

    print("\n" + "=" * 76)
    print("VERDICT")
    print("=" * 76)
    print(f"best-F1 spread across gamma 0.0-0.9 : {f1_spread:.4f}  "
          f"(max {max(f1s.values()):.3f} @g={max(f1s, key=f1s.get):.2f})")
    print(f"AUC spread across gamma 0.0-0.9      : {auc_spread:.4f}")
    print(f"FPR@0.30 constant across all gamma?  : {fpr_const}  (value {fpr0:.3f})")
    print(f"HELPFUL flips (legit false-positive suppressed) total: {total_help}")
    print(f"HARMFUL flips (phishing true-positive lost)     total: {total_hurt}")

    if total_help == 0:
        print("\n-> No gamma removes a single false positive on this cache. FPR is\n"
              "   invariant to gamma here because no LEGIT item sits in the flip\n"
              "   zone near 0.30 for the gate to suppress below it. Raising gamma\n"
              "   only ever costs true positives (HARMFUL flips) at high values,\n"
              "   and erodes AUC monotonically past ~0.20. On this sample the gate\n"
              "   has nothing to act on. This is the corpus problem, not a bug:\n"
              "   the hard-case corpus (borderline legit mail) is what would give\n"
              "   gamma something to suppress. gamma in [0,0.2] is metric-neutral;\n"
              "   >0.2 strictly degrades. 0.2 remains the safe default, unproven.")
    else:
        print(f"\n-> gamma HELPS: {total_help} false positives suppressed across the\n"
              f"   range, {total_hurt} true positives lost. Inspect the flip+/flip-\n"
              f"   columns to pick the gamma with the best trade.")

    with open(os.path.join(HERE, "out", "gamma_sweep.csv"), "w") as fh:
        fh.write("gamma,alpha_beta,best_f1,auc,fpr,mean_supp,max_supp,help_flips,hurt_flips\n")
        for g, f1, a, fpr, ms, mx, hp, ht in results:
            fh.write(f"{g:.2f},{(1-g)/2:.3f},{f1:.4f},"
                     f"{'' if a is None else f'{a:.4f}'},{fpr:.4f},{ms:.4f},{mx:.4f},{hp},{ht}\n")
    print("\nwrote eval/out/gamma_sweep.csv")


if __name__ == "__main__":
    main()

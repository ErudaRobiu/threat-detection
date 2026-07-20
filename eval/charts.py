#!/usr/bin/env python3
"""
eval/charts.py — render the Chapter 4 figures from the harness CSV output.

Requires matplotlib + numpy:  pip install matplotlib numpy
Reads from eval/out/ (written by run.py / baseline.py / gamma_sweep.py) and saves
PNGs alongside them. Each figure degrades gracefully: a missing input is skipped
with a note rather than aborting the whole run, so partial results still plot.

  1. gate-sweep.png     F1 vs threshold for gamma=0 and gamma=0.2 (threshold-
                        independent; coinciding curves = gate changes nothing on
                        this corpus, reported as such rather than hidden at t=0.3).
  2. suppression.png    gate suppression [mean(R,A) - H] vs |R - A| — the gate
                        doing its job: suppression grows with disagreement.
  3. conditions-bar.png grouped bar of acc/prec/rec/F1 across the five conditions
                        (1 rule, 2 AI[email], 3 HTSA g0, 4 HTSA g0.2, 5 RF[5c]).
  4. confusion.png      confusion matrices for every condition, one panel each.
  5. gamma-curve.png    best-F1 / AUC / mean-suppression vs gamma (0..0.9), the
                        figure behind "no gamma helps on this corpus".
  6. rf-diagnosis.png   the three RF rows (5a artefact -> 5b -> 5c honest) with
                        top feature importances, i.e. the collection-artefact story.

Sources: sweep.csv, scatter.csv, metrics.csv (run.py); baseline_preds.csv,
baseline_importances.csv (baseline.py); gamma_sweep.csv (gamma_sweep.py).
"""

import csv
import math
import os
import sys

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np
except ImportError:
    sys.exit("matplotlib + numpy required: pip install matplotlib numpy")

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "out")

# consistent, colour-blind-safe palette across every figure
C_LEGIT, C_THREAT = "#2f9e6f", "#d64550"
C_G0, C_G02 = "#8896a6", "#3b5bdb"
BAR_COLOURS = ["#3b5bdb", "#2f9e6f", "#e08a1e", "#9c36b5"]  # acc, prec, rec, f1


def _exists(name):
    return os.path.exists(os.path.join(OUT, name))


def read_csv(name):
    with open(os.path.join(OUT, name)) as f:
        return list(csv.DictReader(f))


def _binary_from_preds(rows, score_key, label_key="label", t=0.3):
    """Confusion counts from (score,label) rows at threshold t. Skips blanks."""
    tp = fp = tn = fn = 0
    for r in rows:
        s = r.get(score_key, "")
        if s == "" or s is None:
            continue
        s = float(s); y = int(r[label_key])
        hit = s >= t
        if hit and y == 1: tp += 1
        elif hit and y == 0: fp += 1
        elif not hit and y == 0: tn += 1
        else: fn += 1
    P, N = tp + fn, tn + fp
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / P if P else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    return {"acc": (tp + tn) / (tp + fp + tn + fn) if (tp + fp + tn + fn) else 0.0,
            "prec": prec, "rec": rec, "f1": f1,
            "tp": tp, "fp": fp, "tn": tn, "fn": fn}


def gate_sweep():
    if not _exists("sweep.csv"):
        print("skip gate-sweep.png (no sweep.csv — run eval/run.py)"); return
    rows = read_csv("sweep.csv")
    t = [float(r["t"]) for r in rows]
    plt.figure(figsize=(7, 4.5))
    plt.plot(t, [float(r["g0_f1"]) for r in rows], label="gamma = 0 (ablation)", lw=2)
    plt.plot(t, [float(r["g02_f1"]) for r in rows], label="gamma = 0.2 (HTSA)", lw=2)
    plt.axvline(0.3, ls="--", c="0.6", lw=1, label="t = 0.3")
    plt.xlabel("classification threshold")
    plt.ylabel("F1")
    plt.title("F1 vs threshold — agreement gate ablation")
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(OUT, "gate-sweep.png"), dpi=140)
    print("wrote out/gate-sweep.png")


def suppression():
    if not _exists("scatter.csv"):
        print("skip suppression.png (no scatter.csv — run eval/run.py)"); return
    rows = read_csv("scatter.csv")
    plt.figure(figsize=(7, 4.5))
    for label, colour, name in [("0", C_LEGIT, "legitimate"), ("1", C_THREAT, "threat")]:
        xs = [float(r["abs_R_minus_A"]) for r in rows if r["label"] == label]
        ys = [float(r["suppression"]) for r in rows if r["label"] == label]
        plt.scatter(xs, ys, s=18, alpha=0.6, c=colour, label=name)
    plt.xlabel("|R - A|  (disagreement between layers)")
    plt.ylabel("gate suppression  mean(R,A) - H")
    plt.title("Agreement gate: suppression grows with disagreement")
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(OUT, "suppression.png"), dpi=140)
    print("wrote out/suppression.png")


# Human-readable condition labels, in reporting order. Condition 5 is the RF's
# 5c (domain-only) headline — the honest, artefact-free baseline.
COND_ORDER = [
    ("1 rule", "1 rule"),
    ("2 ai [email]", "2 AI (email)"),
    ("3 HTSA gamma0", "3 HTSA gamma=0"),
    ("4 HTSA gam0.2", "4 HTSA gamma=0.2"),
    ("5 RF", "5 RF (domain-only)"),
]


def _condition_metrics():
    """Merge run.py's metrics.csv (cond 1-4) with the RF 5c from baseline_preds.csv."""
    out = {}
    if _exists("metrics.csv"):
        for r in read_csv("metrics.csv"):
            out[r["condition"]] = r
    if _exists("baseline_preds.csv"):
        rf = _binary_from_preds(read_csv("baseline_preds.csv"), "prob_5c", t=0.5)
        out["5 RF"] = {"condition": "5 RF", **{k: rf[k] for k in
                        ("acc", "prec", "rec", "f1", "tp", "fp", "tn", "fn")}}
    return out


def conditions_bar():
    m = _condition_metrics()
    present = [(key, lbl) for key, lbl in COND_ORDER if key in m]
    if not present:
        print("skip conditions-bar.png (no metrics.csv/baseline_preds.csv)"); return
    metrics = ["acc", "prec", "rec", "f1"]
    labels = [lbl for _, lbl in present]
    x = np.arange(len(present)); w = 0.2
    plt.figure(figsize=(10, 5))
    for i, met in enumerate(metrics):
        vals = [float(m[k][met]) for k, _ in present]
        plt.bar(x + (i - 1.5) * w, vals, w, label=met.upper(), color=BAR_COLOURS[i])
    plt.xticks(x, labels, rotation=15, ha="right")
    plt.ylim(0, 1.0); plt.ylabel("score")
    plt.title("Detection metrics across the five conditions (threshold 0.3)")
    plt.legend(ncol=4, loc="lower center")
    plt.tight_layout()
    plt.savefig(os.path.join(OUT, "conditions-bar.png"), dpi=140)
    print("wrote out/conditions-bar.png")


def confusion():
    m = _condition_metrics()
    present = [(key, lbl) for key, lbl in COND_ORDER if key in m]
    if not present:
        print("skip confusion.png (no metrics.csv/baseline_preds.csv)"); return
    n = len(present)
    cols = min(3, n); rows = math.ceil(n / cols)
    fig, axes = plt.subplots(rows, cols, figsize=(4 * cols, 3.4 * rows), squeeze=False)
    for ax in axes.flat:
        ax.axis("off")
    for idx, (key, lbl) in enumerate(present):
        ax = axes[idx // cols][idx % cols]; ax.axis("on")
        d = m[key]
        mat = np.array([[int(d["tn"]), int(d["fp"])],
                        [int(d["fn"]), int(d["tp"])]], dtype=float)
        ax.imshow(mat, cmap="Blues")
        ax.set_xticks([0, 1]); ax.set_xticklabels(["pred legit", "pred threat"])
        ax.set_yticks([0, 1]); ax.set_yticklabels(["true legit", "true threat"])
        thresh = mat.max() / 2 if mat.max() else 0.5
        for i in range(2):
            for j in range(2):
                ax.text(j, i, int(mat[i, j]), ha="center", va="center",
                        color="white" if mat[i, j] > thresh else "black", fontsize=13)
        ax.set_title(f"{lbl}\nF1 {float(d['f1']):.3f}", fontsize=10)
    fig.suptitle("Confusion matrices by condition (threshold 0.3)", y=1.0)
    fig.tight_layout()
    fig.savefig(os.path.join(OUT, "confusion.png"), dpi=140)
    print("wrote out/confusion.png")


def gamma_curve():
    if not _exists("gamma_sweep.csv"):
        print("skip gamma-curve.png (no gamma_sweep.csv — run eval/gamma_sweep.py)"); return
    rows = read_csv("gamma_sweep.csv")
    g = [float(r["gamma"]) for r in rows]
    fig, ax1 = plt.subplots(figsize=(8, 4.5))
    ax1.plot(g, [float(r["best_f1"]) for r in rows], "-o", ms=3, c=C_G02, label="best-F1")
    ax1.plot(g, [float(r["auc"]) for r in rows if r["auc"] != ""], "-s", ms=3,
             c=C_LEGIT, label="AUC")
    ax1.set_xlabel("gamma (interaction weight)"); ax1.set_ylabel("best-F1 / AUC")
    ax1.axvline(0.2, ls="--", c="0.6", lw=1)
    ax1.text(0.205, ax1.get_ylim()[0], " deployed gamma=0.2", fontsize=8, va="bottom")
    ax2 = ax1.twinx()
    ax2.plot(g, [float(r["mean_supp"]) for r in rows], "-^", ms=3, c=C_THREAT,
             label="mean suppression")
    ax2.set_ylabel("mean gate suppression", color=C_THREAT)
    ax2.tick_params(axis="y", labelcolor=C_THREAT)
    lines = ax1.get_lines() + ax2.get_lines()
    ax1.legend(lines, [l.get_label() for l in lines], loc="center right", fontsize=8)
    plt.title("Effect of gamma: suppression rises, detection does not improve")
    fig.tight_layout()
    fig.savefig(os.path.join(OUT, "gamma-curve.png"), dpi=140)
    print("wrote out/gamma-curve.png")


def rf_diagnosis():
    if not _exists("baseline_importances.csv"):
        print("skip rf-diagnosis.png (no baseline_importances.csv — run eval/baseline.py)"); return
    imp = read_csv("baseline_importances.csv")
    # top-8 features for the headline (5c) row
    dom = [(r["feature"], float(r["importance"])) for r in imp
           if r["condition"].startswith("5c")]
    dom.sort(key=lambda p: -p[1]); dom = dom[:8][::-1]
    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.barh([f for f, _ in dom], [v for _, v in dom], color=C_G02)
    ax.set_xlabel("mean Gini importance (5-fold)")
    ax.set_title("RF 5c (domain-only) — lexical signal that survives artefact removal")
    fig.tight_layout()
    fig.savefig(os.path.join(OUT, "rf-diagnosis.png"), dpi=140)
    print("wrote out/rf-diagnosis.png")


if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    for fn in (gate_sweep, suppression, conditions_bar, confusion, gamma_curve, rf_diagnosis):
        try:
            fn()
        except Exception as e:  # one broken figure must not block the rest
            print(f"skip {fn.__name__}: {e}")

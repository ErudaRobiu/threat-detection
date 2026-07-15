#!/usr/bin/env python3
"""
eval/charts.py — render the Chapter 4 figures from run.py's CSV output.

Requires matplotlib:  pip install matplotlib
Reads eval/out/sweep.csv and eval/out/scatter.csv (written by run.py) and saves
PNGs alongside them.

  1. gate-sweep.png    F1 vs threshold for gamma=0 and gamma=0.2 (the honest,
                       threshold-independent comparison — if the curves coincide
                       the gate changes nothing on this corpus, and that is
                       reported as such rather than hidden behind t=0.3).
  2. suppression.png   gate suppression [mean(R,A) - H] vs |R - A|, the figure
                       that shows the agreement gate doing its job: suppression
                       grows with disagreement.
"""

import csv
import os
import sys

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
except ImportError:
    sys.exit("matplotlib is required: pip install matplotlib")

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "out")


def read_csv(name):
    with open(os.path.join(OUT, name)) as f:
        return list(csv.DictReader(f))


def gate_sweep():
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
    rows = read_csv("scatter.csv")
    plt.figure(figsize=(7, 4.5))
    for label, colour, name in [("0", "#22b573", "legitimate"), ("1", "#f04438", "threat")]:
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


if __name__ == "__main__":
    gate_sweep()
    suppression()

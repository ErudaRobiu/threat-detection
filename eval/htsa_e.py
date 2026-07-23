#!/usr/bin/env python3
"""
eval/htsa_e.py — HTSA-E (escalation) as a SEPARATE evaluation condition.

Motivation (see NOTES.md "the structural-cleanliness CAP"): plain HTSA is a
weighted sum of R and A, so a structurally clean email (R~0) is capped at
H = beta*A = 0.40 (gamma=0.2) regardless of A — Medium by construction. That lets
WEAK safety evidence (low R = "SPF passed" = sender controls the domain, nothing
more) veto STRONG threat evidence (high A = unambiguously fraudulent language). It
inverts deny-by-default.

The posture committed to in Chapter 1 is: EITHER LAYER CAN CONVICT, BOTH MUST
ACQUIT — conjunctive for clearance (the agreement gate already does this),
disjunctive for escalation (missing). HTSA-E adds the second half:

    H_e = max( H_htsa , A if A >= tau , R if R >= tau )

tau is a high-confidence escalation threshold. It is NOT hand-picked: it is
derived from data as the lowest value at which NO legitimate TRAINING item
escalates — the empirical ceiling of legitimate confidence. If no clean
separation exists (a legitimate item scores at/above every threat we would want
to escalate), that is reported, not forced.

This module computes everything from cached R,A (no API, no core change). It is a
proposal for review; core/htsa.ts is untouched until the numbers are approved.
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import run  # fuse_H, binary, auc, sweep, THRESHOLD

THRESHOLD = run.THRESHOLD
GAMMA = 0.2  # the deployed HTSA the escalation wraps


def fuse_He(R, A, tau, gamma=GAMMA):
    """HTSA-E: escalate the HTSA score if either layer is independently certain.

    Escalation only uses a layer that is PRESENT (not None). A missing layer
    cannot convict — abstention is not evidence. When both are present this
    reduces to max(H_htsa, A>=tau ? A, R>=tau ? R)."""
    base = run.fuse_H(R, A, gamma)          # None only if both None
    if base is None:
        return None
    candidates = [base]
    if A is not None and A >= tau:
        candidates.append(A)
    if R is not None and R >= tau:
        candidates.append(R)
    return max(candidates)


def escalation_score(R, A):
    """The value HTSA-E compares against tau: the strongest present layer."""
    vals = [v for v in (R, A) if v is not None]
    return max(vals) if vals else None


def tier(H, medium=0.3, high=0.6, critical=0.8):
    """Classification tier — HTSA-E acts at the Medium/High boundary, which the
    binary threshold at 0.3 cannot see, so tier movement is the real metric."""
    if H is None:
        return None
    if H >= critical:
        return "Critical"
    if H >= high:
        return "High"
    if H >= medium:
        return "Medium"
    return "Low"


def derive_tau(train_rows, eps=0.01):
    """Lowest tau at which NO legitimate training item escalates.

    A legit item escalates iff max(R,A) >= tau, so the smallest safe tau is just
    above the highest legit escalation_score. Returns (tau, ceiling, margin_info)
    or (None, ceiling, reason) if the legit ceiling touches the threat range so no
    clean separation exists.
    """
    legit = [r for r in train_rows if r["label"] == 0]
    threat = [r for r in train_rows if r["label"] == 1]
    legit_scores = [(escalation_score(r["R"], r["A"]), r) for r in legit]
    legit_scores = [(s, r) for s, r in legit_scores if s is not None]
    threat_scores = [escalation_score(r["R"], r["A"]) for r in threat]
    threat_scores = [s for s in threat_scores if s is not None]
    if not legit_scores:
        return None, None, "no legitimate training items with a score"

    ceiling, top_row = max(legit_scores, key=lambda p: p[0])
    tau = ceiling + eps
    # separate the two arms: which layer sets the legit ceiling matters. A high
    # legit R (structural false positive) dragging tau down is a different problem
    # from a high legit A (genuine urgent mail). Report both ceilings.
    legit_A = [r["A"] for r in legit if r["A"] is not None]
    legit_R = [r["R"] for r in legit if r["R"] is not None]
    ceiling_A = max(legit_A) if legit_A else None
    ceiling_R = max(legit_R) if legit_R else None
    # how many threats would this tau escalate? (the benefit)
    would_catch = sum(1 for s in threat_scores if s >= tau)
    info = {
        "legit_ceiling_maxRA": ceiling,
        "legit_ceiling_A": ceiling_A,
        "legit_ceiling_R": ceiling_R,
        "ceiling_set_by": "R-arm (structural FP)" if top_row["R"] is not None
                          and top_row["R"] >= (top_row["A"] or 0) else "A-arm (urgent legit)",
        "ceiling_item": {k: top_row.get(k) for k in ("label", "category", "source", "R", "A")},
        "tau": tau,
        "margin_above_ceiling": eps,
        "threats_at_or_above_tau": would_catch,
        "n_threats": len(threat_scores),
        "clean_separation": would_catch > 0,
    }
    if would_catch == 0:
        # tau is above every threat's escalation score too -> escalation never
        # fires for threats either; no useful separation.
        return None, ceiling, info
    return tau, ceiling, info


def metrics_block(rows, score_fn, name):
    pairs = [(score_fn(r), r["label"]) for r in rows]
    pairs = [(s, y) for s, y in pairs if s is not None]
    m = run.binary(pairs, THRESHOLD)
    a = run.auc(pairs)
    best = max(run.sweep(pairs), key=lambda x: x[3])
    return {"name": name, "m": m, "auc": a, "best": best}


def print_block(b):
    m, a = b["m"], b["auc"]
    astr = f"{a:.3f}" if a is not None else "--"
    print(f"{b['name']:<16}{m['n']:>4}{m['prec']:>7.3f}{m['rec']:>7.3f}{m['f1']:>7.3f}"
          f"{m['fpr']:>7.3f}{m['fnr']:>7.3f}{astr:>7}   {m['tp']} {m['fp']} {m['tn']} {m['fn']}"
          f"   bestF1 {b['best'][3]:.3f}@{b['best'][0]:.2f}")


def load_scored():
    """Every cached item joined to its label, from both caches."""
    rows = []
    # hard-case corpus
    hc_cache = os.path.join(HERE, "hardcases_cache.json")
    hc_jsonl = os.path.join(HERE, "hardcases.jsonl")
    if os.path.exists(hc_cache) and os.path.exists(hc_jsonl):
        cache = json.load(open(hc_cache))
        for line in open(hc_jsonl):
            it = json.loads(line)
            c = cache.get(it["cid"])
            if c and "error" not in c:
                rows.append({"label": it["label"], "category": it["category"],
                             "source": it["source"], "corpus": "hardcase",
                             "R": c.get("R"), "A": c.get("A"), "H": c.get("H")})
    # main smoke corpus (labels from raw loader)
    main_cache = os.path.join(HERE, "cache.json")
    if os.path.exists(main_cache):
        cache = json.load(open(main_cache))
        lab = {it["cid"]: it for it in run.load_items(url_mode="raw")}
        for cid, c in cache.items():
            if "error" in c or cid not in lab:
                continue
            it = lab[cid]
            rows.append({"label": it["label"], "category": it["kind"],
                         "source": it["src"], "corpus": "main",
                         "R": c.get("R"), "A": c.get("A"), "H": c.get("H")})
    return rows


def main():
    import random
    rows = load_scored()
    print(f"scored items available: {len(rows)} "
          f"(legit {sum(1 for r in rows if r['label']==0)} / "
          f"threat {sum(1 for r in rows if r['label']==1)})\n")
    if not rows:
        sys.exit("no scored items — run the smoke/full run first.")

    # --- 1. algebra (restated for the record) ------------------------------
    print("1. ALGEBRA: with R=0, H = beta*A = ((1-gamma)/2)*A.")
    for g in (0.2, 0.0):
        print(f"     gamma={g}: R=0,A=1.0 -> H={ (1-g)/2:.2f}  (Medium; High needs 0.6)")

    # --- 2. defect size: R<0.15 AND A>0.8 ----------------------------------
    band = [r for r in rows if r["R"] is not None and r["A"] is not None
            and r["R"] < 0.15 and r["A"] > 0.8]
    print(f"\n2. DEFECT SIZE  R<0.15 & A>0.8 (capped at Medium): {len(band)} items, "
          f"{sum(1 for r in band if r['label']==1)} threats / "
          f"{sum(1 for r in band if r['label']==0)} legit")

    # --- 3. derive tau on a TRAINING split ---------------------------------
    rng = random.Random(run.SEED)
    idx = list(range(len(rows)))
    rng.shuffle(idx)
    cut = int(len(rows) * 0.6)
    train = [rows[i] for i in idx[:cut]]
    test = [rows[i] for i in idx[cut:]]
    tau, ceiling, info = derive_tau(train)
    print(f"\n3. TAU DERIVATION (train split, {len(train)} items; test {len(test)}):")
    print(f"     highest legit escalation score (ceiling): {ceiling}")
    print(f"     derived tau: {tau}")
    print(f"     detail: {json.dumps(info, default=str)}")
    if tau is None:
        print("     -> NO CLEAN SEPARATION on this split. Reported, not forced.")
        print("        (A legitimate item scores at/above the escalation range.)")
        tau_used = None
    else:
        tau_used = tau

    # --- 4/6. Conditions side by side on the TEST split --------------------
    print(f"\n4/6. CONDITIONS on test split ({len(test)} items), threshold {THRESHOLD}:")
    print(f"{'condition':<16}{'n':>4}{'prec':>7}{'rec':>7}{'f1':>7}{'fpr':>7}{'fnr':>7}{'auc':>7}   (tp fp tn fn)")
    print("-" * 92)
    print_block(metrics_block(test, lambda r: r["R"], "1 rule"))
    print_block(metrics_block([r for r in test if r["A"] is not None], lambda r: r["A"], "2 AI"))
    print_block(metrics_block(test, lambda r: run.fuse_H(r["R"], r["A"], 0.0), "3 HTSA g0"))
    print_block(metrics_block(test, lambda r: run.fuse_H(r["R"], r["A"], 0.2), "4 HTSA g0.2"))
    if tau_used is not None:
        print_block(metrics_block(test, lambda r: fuse_He(r["R"], r["A"], tau_used), "6 HTSA-E"))
        print("   (binary metrics @0.3 barely move vs HTSA: HTSA-E acts at the "
              "Medium/High tier\n    boundary, above 0.3, so the clearance-line "
              "confusion matrix cannot see it.)")

        # The real metric: tier movement under HTSA-E vs HTSA(gamma=0.2), whole corpus.
        moves = {"threat_M_to_H": [], "threat_other_up": [], "legit_up": []}
        for r in rows:
            h = run.fuse_H(r["R"], r["A"], 0.2)
            he = fuse_He(r["R"], r["A"], tau_used)
            if h is None or he is None:
                continue
            t0, t1 = tier(h), tier(he)
            if t0 == t1:
                continue
            if r["label"] == 1 and t0 == "Medium" and t1 in ("High", "Critical"):
                moves["threat_M_to_H"].append(r)
            elif r["label"] == 1:
                moves["threat_other_up"].append(r)
            else:
                moves["legit_up"].append(r)
        print(f"\n   TIER MOVEMENT HTSA-E vs HTSA (whole corpus, {len(rows)} items):")
        print(f"     BENEFIT  threats Medium->High/Critical : {len(moves['threat_M_to_H'])}")
        print(f"     benefit  threats other upward tier     : {len(moves['threat_other_up'])}")
        print(f"     COST     legitimate items moved up a tier: {len(moves['legit_up'])}")
        for r in moves["legit_up"]:
            print(f"       LEGIT ESCALATED: {r['category']}/{r['source']} "
                  f"R={r['R']} A={r['A']} -> {tier(fuse_He(r['R'],r['A'],tau_used))}")

    # --- calibration guard: marketing (A~0.40) and bank alert (A~0.78) -----
    if tau_used is not None:
        print(f"\n   GUARD (must NOT escalate): with tau={tau_used:.3f}")
        for lbl, A in [("marketing A=0.40", 0.40), ("bank alert A=0.78", 0.78)]:
            esc = A >= tau_used
            print(f"     {lbl}: escalates? {esc}  {'*** tau too low' if esc else 'OK'}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
eval/baseline.py — Condition 5: Random Forest on lexical URL features, THREE rows.

The URL corpus is trivially separable by a collection artefact (legit = bare
Tranco domains, phish = full captured URLs; see NOTES.md). Reporting a single RF
number would flatter the baseline on that artefact. Instead this reports the
diagnostic trail:

  5a  RF, ALL lexical features            -- artefact-laden, labelled as such
  5b  RF, length/path features REMOVED    -- honest comparator, artefact damped
  5c  RF, DOMAIN-ONLY (registrable domain) -- HEADLINE: every URL stripped to its
        registrable domain before featurising, both classes, equalising input
        shape entirely. Isolates whether ANY lexical signal survives in the
        domain string once the collection artefact is gone.

5c is the Condition-5 number that goes head-to-head with the rule/AI/hybrid
conditions; 5a and 5b are the trail showing how it was reached. This finding
(a benchmark separable by artefact) is itself a Chapter 4 methodological result.

Corpus: the 1,000-URL set loaded via run.py --url-mode raw (full URLs; 5c strips
them here). Evaluation: stratified 5-fold CV, OUT-OF-FOLD predictions, seed 42.
Outputs eval/out/baseline_{preds,importances}.csv for charts.py.
"""

import csv
import math
import os
import re
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import run  # loader

try:
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import StratifiedKFold
    from sklearn.metrics import roc_auc_score
    import tldextract
except ImportError as e:  # pragma: no cover
    print(f"baseline.py needs scikit-learn + numpy + tldextract: {e}")
    print("install: python3 -m pip install scikit-learn numpy tldextract")
    sys.exit(1)

SEED = 42
N_FOLDS = 5
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())  # offline

_IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_SHORTENERS = {"bit.ly", "goo.gl", "t.co", "tinyurl.com", "ow.ly", "is.gd",
               "buff.ly", "cutt.ly", "rebrand.ly", "bit.do", "shorturl.at"}
_SUSPICIOUS = ("login", "secure", "account", "update", "verify", "signin",
               "bank", "confirm", "password", "webscr", "ebayisapi", "wp",
               "admin", "pay", "free", "bonus", "gift", "click")
_BRANDS = ("paypal", "apple", "microsoft", "google", "amazon", "netflix",
           "facebook", "instagram", "whatsapp", "bank", "chase", "wellsfargo")

FEATURES = [
    "url_len", "host_len", "path_len", "query_len", "num_dots", "num_hyphens",
    "num_underscore", "num_slash", "num_qmark", "num_equals", "num_at",
    "num_pct", "num_digits", "num_subdomains", "has_ip", "has_https",
    "has_port", "is_shortener", "digit_ratio", "host_entropy", "longest_token",
    "num_suspicious_words", "has_brand_token", "tld_len",
]

# Features that directly encode "how long / how much path" — the artefact carriers.
# Removed in 5b. (digit_ratio/host_entropy are scale-free and kept.)
LENGTH_PATH = {"url_len", "host_len", "path_len", "query_len", "num_slash",
               "num_dots", "num_qmark", "num_equals", "num_pct", "longest_token"}
KEEP_5B = [i for i, f in enumerate(FEATURES) if f not in LENGTH_PATH]


def _entropy(s):
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def _split_url(url):
    m = re.match(r"^(https?)://([^/?#]*)([^?#]*)(?:\?([^#]*))?", url, re.I)
    if not m:
        return "", "", url, "", ""
    scheme, host = m.group(1), m.group(2).split("@")[-1]
    return scheme, host, host.split(":")[0], m.group(3), m.group(4) or ""


def featurize(url):
    scheme, host, hostname, path, query = _split_url(url)
    labels = [x for x in hostname.split(".") if x]
    tld = labels[-1] if labels else ""
    reg = ".".join(labels[-2:]) if len(labels) >= 2 else hostname
    digits = sum(c.isdigit() for c in url)
    tokens = re.split(r"[\W_]+", url.lower())
    low = url.lower()
    return [
        len(url), len(host), len(path), len(query), url.count("."),
        url.count("-"), url.count("_"), url.count("/"), url.count("?"),
        url.count("="), url.count("@"), url.count("%"), digits,
        max(0, len(labels) - 2),
        1 if _IP_RE.match(hostname) else 0,
        1 if scheme.lower() == "https" else 0,
        1 if ":" in host else 0,
        1 if reg in _SHORTENERS else 0,
        digits / len(url) if url else 0.0,
        _entropy(hostname),
        max((len(t) for t in tokens), default=0),
        sum(1 for w in _SUSPICIOUS if w in low),
        1 if any(b in low for b in _BRANDS) else 0,
        len(tld),
    ]


def to_domain(url):
    m = re.match(r"^https?://([^/?#]*)", url, re.I)
    host = (m.group(1) if m else url).split("@")[-1].split(":")[0]
    ex = _EXTRACT(host)
    return "https://" + (ex.top_domain_under_public_suffix or host)


def cv_oof(X, y):
    """Stratified 5-fold out-of-fold probabilities + mean feature importances."""
    skf = StratifiedKFold(n_splits=N_FOLDS, shuffle=True, random_state=SEED)
    prob = np.zeros(len(y))
    imp = np.zeros(X.shape[1])
    for tr, te in skf.split(X, y):
        clf = RandomForestClassifier(
            n_estimators=300, min_samples_leaf=2, class_weight="balanced",
            random_state=SEED, n_jobs=-1)
        clf.fit(X[tr], y[tr])
        prob[te] = clf.predict_proba(X[te])[:, 1]
        imp += clf.feature_importances_
    return prob, imp / N_FOLDS


def metrics(y, prob, t=0.5):
    pred = (prob >= t).astype(int)
    tp = int(((pred == 1) & (y == 1)).sum()); fp = int(((pred == 1) & (y == 0)).sum())
    tn = int(((pred == 0) & (y == 0)).sum()); fn = int(((pred == 0) & (y == 1)).sum())
    P, N = tp + fn, tn + fp
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / P if P else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    auc = roc_auc_score(y, prob) if (P and N) else float("nan")
    return {"acc": (tp + tn) / len(y), "prec": prec, "rec": rec, "f1": f1,
            "fpr": fp / N if N else 0.0, "fnr": fn / P if P else 0.0, "auc": auc,
            "tp": tp, "fp": fp, "tn": tn, "fn": fn}


def best_f1(y, prob):
    best = (0.5, metrics(y, prob)["f1"]); t = 0.0
    while t <= 1.0 + 1e-9:
        f1 = metrics(y, prob, t)["f1"]
        if f1 > best[1]:
            best = (round(t, 2), f1)
        t += 0.01
    return best


def main():
    items = [it for it in run.load_items(url_mode="raw") if it["kind"] == "url"]
    if not items:
        print("no URL items — run eval/fetch_corpora.sh first."); return
    urls = [it["content"] for it in items]
    y = np.array([it["label"] for it in items])
    print("Condition 5 — Random Forest on lexical URL features (three rows)")
    print(f"corpus: {len(items)} URLs  (legit {(y==0).sum()} / phish {(y==1).sum()})")
    print(f"{N_FOLDS}-fold stratified CV, out-of-fold predictions, seed {SEED}\n")

    X_all = np.array([featurize(u) for u in urls], dtype=float)
    X_dom = np.array([featurize(to_domain(u)) for u in urls], dtype=float)

    rows = {
        "5a all-features (ARTEFACT)": (X_all, list(range(len(FEATURES)))),
        "5b no length/path         ": (X_all[:, KEEP_5B], KEEP_5B),
        "5c domain-only (HEADLINE)  ": (X_dom, list(range(len(FEATURES)))),
    }

    print(f"{'condition':<28}{'acc':>7}{'prec':>7}{'rec':>7}{'f1':>7}{'fpr':>7}"
          f"{'fnr':>7}{'auc':>7}{'bestF1':>8}   (tp fp tn fn)")
    print("-" * 108)
    out = {}
    for name, (X, cols) in rows.items():
        prob, imp = cv_oof(X, y)
        m = metrics(y, prob)
        bt, bf = best_f1(y, prob)
        out[name] = (prob, imp, cols)
        print(f"{name:<28}{m['acc']:>7.3f}{m['prec']:>7.3f}{m['rec']:>7.3f}{m['f1']:>7.3f}"
              f"{m['fpr']:>7.3f}{m['fnr']:>7.3f}{m['auc']:>7.3f}{bf:>8.3f}   "
              f"{m['tp']} {m['fp']} {m['tn']} {m['fn']}")

    # headline importances (5c)
    prob_c, imp_c, cols_c = out["5c domain-only (HEADLINE)  "]
    print("\n5c domain-only — top features (what signal survives the artefact removal):")
    for name, i in sorted(zip([FEATURES[c] for c in cols_c], imp_c), key=lambda p: -p[1])[:8]:
        print(f"  {name:<22}{i:.4f}")
    print("\n5a all-features — top features (should be dominated by length/path):")
    _, imp_a, _ = out["5a all-features (ARTEFACT)"]
    for name, i in sorted(zip(FEATURES, imp_a), key=lambda p: -p[1])[:6]:
        print(f"  {name:<22}{i:.4f}")

    os.makedirs(os.path.join(HERE, "out"), exist_ok=True)
    # headline predictions for charts (confusion matrix / ROC use 5c)
    with open(os.path.join(HERE, "out", "baseline_preds.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["url", "label", "prob_5c", "pred_5c", "prob_5a", "prob_5b"])
        pa = out["5a all-features (ARTEFACT)"][0]
        pb = out["5b no length/path         "][0]
        for u, lab, pc, a, b in zip(urls, y, prob_c, pa, pb):
            w.writerow([u, int(lab), f"{pc:.4f}", int(pc >= 0.5), f"{a:.4f}", f"{b:.4f}"])
    with open(os.path.join(HERE, "out", "baseline_importances.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["condition", "feature", "importance"])
        for cname, (_, imp, cols) in out.items():
            for i, c in enumerate(cols):
                w.writerow([cname.strip(), FEATURES[c], f"{imp[i]:.5f}"])
    print("\nwrote eval/out/baseline_preds.csv and baseline_importances.csv")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
eval/confound_check.py — is the URL corpus trivially separable by collection
artefact, and does the RULE ENGINE ride that artefact the way the RF does?

Offline, string-only. No network, no dev server, no API. Mirrors core/rules.ts
and core/preprocess.ts exactly for the three indicators that read URL SHAPE:

  subdomain_depth  fails when subdomain has > MAX_SUBDOMAIN_DEPTH (3) labels
                   (preprocess: p.subdomain.split('.').filter length)
  url_ip_address   fails when host is a bare IP
  url_shortener    fails when registrable domain is a known shortener

brand_similarity, domain_age (WHOIS) and TLS are NOT shape artefacts — brand
reads the SLD label (unchanged by path/subdomain stripping) and WHOIS/TLS read
the host over the network; they are out of scope for this offline check and are
measured by the full run. The point here is narrow: quantify how much of the
URL corpus's structural discriminability is an artefact of legit=bare-domain
vs phish=full-captured-URL, and whether it survives normalising both to shape.

Reports, per class, full-URL vs registrable-domain-stripped:
  median url/host/path length      (the table that goes in NOTES.md verbatim)
  subdomain_depth distribution and >3 fail-rate
  IP-host rate, shortener rate
and states plainly which structural signal is real and which is collection shape.
"""

import os
import re
import statistics as st
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import run  # loader

try:
    import tldextract
except ImportError:
    print("needs tldextract: python3 -m pip install tldextract"); sys.exit(1)

# mirror core/rules.ts
MAX_SUBDOMAIN_DEPTH = 3
SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "rebrand.ly", "bl.ink",
    "short.io", "lnkd.in", "t.ly", "s.id", "shorte.st", "adf.ly", "bitly.com",
}
_IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
# tldextract without network (bundled snapshot); suppress the private-domain noise
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())


def parse(url):
    m = re.match(r"^https?://([^/?#]*)([^?#]*)(?:\?([^#]*))?", url, re.I)
    host = (m.group(1) if m else url).split("@")[-1].split(":")[0]
    path = m.group(2) if m else ""
    query = (m.group(3) or "") if m else ""
    ex = _EXTRACT(host)
    reg = ex.top_domain_under_public_suffix or host
    depth = len([l for l in ex.subdomain.split(".") if l]) if ex.subdomain else 0
    is_ip = bool(_IP_RE.match(host))
    return {"host": host, "path": path, "query": query, "reg": reg,
            "depth": depth, "is_ip": is_ip, "url": url}


def shape_row(label, urls, stripped):
    """Return metrics for one class, optionally after stripping to registrable domain."""
    P = [parse(u) for u in urls]
    if stripped:
        # rebuild each URL as bare https://<registrable-domain>, reparse
        P = [parse("https://" + p["reg"]) for p in P if not p["is_ip"]]
        # IP hosts have no registrable domain; keep them as-is so the count is honest
        P += [parse(u) for u, p in zip(urls, [parse(u) for u in urls]) if p["is_ip"]]
    n = len(P)
    ulen = [len(p["url"]) for p in P]
    plen = [len(p["path"]) for p in P]
    depths = [p["depth"] for p in P]
    deep = sum(1 for d in depths if d > MAX_SUBDOMAIN_DEPTH)
    ips = sum(1 for p in P if p["is_ip"])
    short = sum(1 for p in P if p["reg"].lower() in SHORTENERS)
    return {
        "n": n, "med_url": st.median(ulen), "med_path": st.median(plen),
        "mean_depth": sum(depths) / n if n else 0, "max_depth": max(depths) if depths else 0,
        "deep_rate": deep / n if n else 0, "ip_rate": ips / n if n else 0,
        "short_rate": short / n if n else 0,
        "depth_hist": {d: depths.count(d) for d in sorted(set(depths))},
    }


def main():
    # raw = as-collected full URLs; analysing the collection shape is the point here
    items = [it for it in run.load_items(url_mode="raw") if it["kind"] == "url"]
    legit = [it["content"] for it in items if it["label"] == 0]
    phish = [it["content"] for it in items if it["label"] == 1]
    print(f"URL corpus: legit {len(legit)} / phish {len(phish)}\n")

    print("=" * 78)
    print("TABLE 1 — URL SHAPE BY CLASS (full URL, as collected)  [-> NOTES.md]")
    print("=" * 78)
    fl, fp = shape_row(0, legit, False), shape_row(1, phish, False)
    print(f"{'class':<8}{'n':>5}{'med_urllen':>12}{'med_pathlen':>13}"
          f"{'mean_depth':>12}{'>3 depth':>10}{'ip%':>7}{'short%':>8}")
    for name, r in [("legit", fl), ("phish", fp)]:
        print(f"{name:<8}{r['n']:>5}{r['med_url']:>12.0f}{r['med_path']:>13.0f}"
              f"{r['mean_depth']:>12.2f}{r['deep_rate']*100:>9.1f}%"
              f"{r['ip_rate']*100:>6.1f}%{r['short_rate']*100:>7.1f}%")

    print("\nsubdomain_depth histogram (full URL):")
    print(f"  legit: {fl['depth_hist']}")
    print(f"  phish: {fp['depth_hist']}")

    print("\n" + "=" * 78)
    print("TABLE 2 — SAME, AFTER STRIPPING BOTH CLASSES TO REGISTRABLE DOMAIN")
    print("=" * 78)
    sl, sp = shape_row(0, legit, True), shape_row(1, phish, True)
    print(f"{'class':<8}{'n':>5}{'med_urllen':>12}{'med_pathlen':>13}"
          f"{'mean_depth':>12}{'>3 depth':>10}{'ip%':>7}{'short%':>8}")
    for name, r in [("legit", sl), ("phish", sp)]:
        print(f"{name:<8}{r['n']:>5}{r['med_url']:>12.0f}{r['med_path']:>13.0f}"
              f"{r['mean_depth']:>12.2f}{r['deep_rate']*100:>9.1f}%"
              f"{r['ip_rate']*100:>6.1f}%{r['short_rate']*100:>7.1f}%")

    # ---- verdict ----
    print("\n" + "=" * 78)
    print("VERDICT — does the RULE ENGINE ride the collection artefact?")
    print("=" * 78)
    print("subdomain_depth (>3 fail rate):")
    print(f"  full URL : legit {fl['deep_rate']*100:.1f}%  vs  phish {fp['deep_rate']*100:.1f}%"
          f"   gap {abs(fp['deep_rate']-fl['deep_rate'])*100:.1f} pts")
    print(f"  stripped : legit {sl['deep_rate']*100:.1f}%  vs  phish {sp['deep_rate']*100:.1f}%"
          f"   gap {abs(sp['deep_rate']-sl['deep_rate'])*100:.1f} pts")
    print("url_ip_address (IP-host rate):")
    print(f"  full URL : legit {fl['ip_rate']*100:.1f}%  vs  phish {fp['ip_rate']*100:.1f}%"
          f"   gap {abs(fp['ip_rate']-fl['ip_rate'])*100:.1f} pts")
    print("url_shortener:")
    print(f"  full URL : legit {fl['short_rate']*100:.1f}%  vs  phish {fp['short_rate']*100:.1f}%"
          f"   gap {abs(fp['short_rate']-fl['short_rate'])*100:.1f} pts")

    depth_gap_full = abs(fp['deep_rate'] - fl['deep_rate'])
    depth_gap_strip = abs(sp['deep_rate'] - sl['deep_rate'])
    print()
    if depth_gap_full > 0.05 and depth_gap_strip < depth_gap_full / 2:
        print("-> subdomain_depth's discrimination is SUBSTANTIALLY the artefact: the\n"
              "   gap collapses once both classes are normalised to registrable domain.")
    elif depth_gap_full <= 0.05:
        print("-> subdomain_depth barely discriminates even on full URLs; it is NOT a\n"
              "   major driver of Condition 1 either way. IP and shortener gaps above\n"
              "   show whether any real structural signal exists.")
    else:
        print("-> subdomain_depth's gap survives stripping: it is genuine signal, not\n"
              "   purely the collection artefact.")
    print("\nNote: this covers only the three SHAPE indicators. brand_similarity,\n"
          "domain_age (WHOIS) and TLS are measured live in the full run; brand reads\n"
          "the SLD label and is not a shape artefact. The definitive Condition-1\n"
          "comparison (R on full URL vs R on stripped domain) comes from running the\n"
          "engine both ways in the full run — this offline check is the pre-flight.")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
eval/normalise_urls.py — corpus fix (a): strip BOTH URL classes to registrable
domain so neither class is separable by collection shape (see NOTES.md, "the URL
corpus is trivially separable by a collection artefact").

Reads data/urls_legit.txt and data/urls_phish.txt (raw, as collected), and writes
data/urls_legit_domain.txt and data/urls_phish_domain.txt as bare
`https://<registrable-domain>`, one per line, with:

  - dedup to UNIQUE registrable domains per class (no double-counting shared hosts)
  - drop the registrable domains that appear in BOTH classes (ambiguous after
    stripping — a shared host is neither inherently phish nor legit)

first-occurrence order preserved for determinism. Prints the resulting counts.
run.py --url-mode domain (the default) consumes these files. The raw files are
left untouched so --url-mode raw reproduces the artefact-laden corpus.
"""

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")

try:
    import tldextract
except ImportError:
    print("needs tldextract: python3 -m pip install tldextract"); sys.exit(1)

# offline: use the bundled suffix snapshot, no network fetch
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())


def registrable(url):
    m = re.match(r"^https?://([^/?#]*)", url, re.I)
    host = (m.group(1) if m else url).split("@")[-1].split(":")[0]
    ex = _EXTRACT(host)
    return (ex.top_domain_under_public_suffix or host).lower()


def unique_regdomains(path):
    seen, out = set(), []
    with open(path, "rb") as f:
        for line in f.read().decode("latin-1", "replace").splitlines():
            line = line.strip()
            if not line.startswith("http"):
                continue
            rd = registrable(line)
            if rd and rd not in seen:
                seen.add(rd)
                out.append(rd)
    return out


def main():
    legit = unique_regdomains(os.path.join(DATA, "urls_legit.txt"))
    phish = unique_regdomains(os.path.join(DATA, "urls_phish.txt"))

    collisions = set(legit) & set(phish)
    legit_f = [d for d in legit if d not in collisions]
    phish_f = [d for d in phish if d not in collisions]

    for fn, domains in [("urls_legit_domain.txt", legit_f),
                        ("urls_phish_domain.txt", phish_f)]:
        with open(os.path.join(DATA, fn), "w") as f:
            for d in domains:
                f.write(f"https://{d}\n")

    print("normalised URL corpus (registrable domain, deduped, collisions dropped):")
    print(f"  legit: {len(legit)} unique -> {len(legit_f)} after dropping collisions")
    print(f"  phish: {len(phish)} unique -> {len(phish_f)} after dropping collisions")
    print(f"  dropped {len(collisions)} cross-label domains: {sorted(collisions)}")
    print(f"  wrote data/urls_legit_domain.txt ({len(legit_f)}) and "
          f"data/urls_phish_domain.txt ({len(phish_f)})")


if __name__ == "__main__":
    main()

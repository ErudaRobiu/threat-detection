#!/usr/bin/env bash
# eval/fetch_corpora.sh — reproduce the evaluation corpora into eval/data/.
# All sources are freely downloadable, no registration. See eval/NOTES.md for
# provenance, sample sizes, and the two documented substitutions.
set -euo pipefail
cd "$(dirname "$0")/data" 2>/dev/null || { mkdir -p "$(dirname "$0")/data" && cd "$(dirname "$0")/data"; }

echo "[1/4] Tranco (legitimate URLs)"
curl -sL -o tranco.zip "https://tranco-list.eu/top-1m.csv.zip"
unzip -o -q tranco.zip
awk -F',' 'NR<=500{print "https://" $2}' top-1m.csv > urls_legit.txt

echo "[2/4] Phishing.Database (phishing URLs; PhishTank substitute — see NOTES.md)"
curl -sL -o phishdb.txt "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt"
grep '^http' phishdb.txt | sort -R | head -500 > urls_phish.txt

echo "[3/4] Nazario (phishing emails)"
curl -sL -o naz_phishing3.mbox "https://monkey.org/~jose/phishing/phishing3.mbox"

echo "[4/4] SpamAssassin easy_ham (legitimate emails; Enron substitute — see NOTES.md)"
curl -sL -o easy_ham.tar.bz2   "https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2"
curl -sL -o easy_ham_2.tar.bz2 "https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham_2.tar.bz2"
tar xjf easy_ham.tar.bz2
tar xjf easy_ham_2.tar.bz2

echo "done. urls_legit=$(wc -l < urls_legit.txt) urls_phish=$(wc -l < urls_phish.txt)"
echo "nazario=$(grep -a -c '^From ' naz_phishing3.mbox) ham=$(( $(ls easy_ham|grep -vc cmds) + $(ls easy_ham_2|grep -vc cmds) ))"

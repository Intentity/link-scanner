# Link Scanner

A small Python/Flask tool that scans a URL and flags what kind of threat it
might be — phishing, disguised executables, ransomware pages, crypto wallet
drainers, and more — using ~19 offline heuristics.

**Fully offline.** No external APIs, no third-party services, no data ever
leaves your machine.

## What it checks for

- Raw IP addresses instead of domains
- Punycode / homograph domains
- Brand impersonation & typosquatting (edit-distance + substring matching)
- Suspicious TLDs and URL shorteners
- High-entropy / DGA-style subdomains (common in malware C2 infrastructure)
- Direct links to executables (`.exe`, `.apk`, `.jar`, `.ps1`, ...)
- Disguised double file extensions (`invoice.pdf.exe`)
- Credential-harvesting, ransomware, and crypto-drainer wording
- Open-redirect style query parameters

Every check reports its own severity and reasoning — the UI shows a full
"scan log" so every flag is explainable, not a single opaque score.

## Running it locally


python3 -m venv venv
source venv/bin/activate     
pip install flask
python3 app.py


Then open `http://127.0.0.1:5000`.

## Known limitations

This is heuristic pattern-matching, not a live threat-intelligence feed. It
can't catch a brand-new phishing domain that has no structural red flags but
is already reported/blocklisted elsewhere. Treat it as a first-pass triage
tool, not a certified verdict — pairing it with a live reputation API
(Google Safe Browsing, VirusTotal) is a planned next step.

## Stack

Python, Flask, vanilla JS/CSS. No frontend framework, no build step.

"""
analyzer.py
Offline heuristic engine for scoring a URL's maliciousness and guessing
the likely threat category. No network calls, no API keys required.

The scoring model is intentionally transparent: every rule that fires is
returned with its own severity and explanation, so the UI can show a
"scan log" rather than a black-box score.
"""

import re
import math
from collections import Counter
from urllib.parse import urlparse, parse_qs

# --------------------------------------------------------------------------
# Reference data
# --------------------------------------------------------------------------

SEVERITY_WEIGHTS = {
    "critical": 30,
    "high": 20,
    "medium": 10,
    "low": 5,
}

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "click", "link",
    "support", "gdn", "loan", "men", "date", "party", "review", "zip",
    "mov", "country", "stream", "download", "fit",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "cutt.ly", "shorturl.at", "rebrand.ly", "rb.gy", "s.id",
    "tiny.cc", "bl.ink",
}

# extension -> (severity, category label)
SUSPICIOUS_EXTENSIONS = {
    ".exe": ("critical", "Windows executable / Trojan dropper"),
    ".scr": ("critical", "Screensaver executable (common Trojan disguise)"),
    ".msi": ("high", "Windows installer package"),
    ".bat": ("high", "Batch script (dropper/loader)"),
    ".cmd": ("high", "Batch script (dropper/loader)"),
    ".ps1": ("high", "PowerShell script (dropper/loader)"),
    ".vbs": ("high", "VBScript (common macro-malware payload)"),
    ".js": ("medium", "JavaScript payload"),
    ".jar": ("high", "Java archive (cross-platform dropper)"),
    ".apk": ("high", "Android package (mobile malware)"),
    ".dll": ("high", "Windows library (often side-loaded malware)"),
    ".iso": ("medium", "Disk image (used to smuggle payloads past filters)"),
    ".lnk": ("high", "Windows shortcut (LNK-based loader)"),
    ".zip": ("low", "Archive (could contain a payload)"),
    ".rar": ("low", "Archive (could contain a payload)"),
    ".hta": ("critical", "HTML Application (classic malware loader)"),
}

PHISHING_KEYWORDS = {
    "login", "signin", "verify", "secure", "account", "update", "confirm",
    "password", "banking", "billing", "invoice", "suspended", "unlock",
    "security-alert", "reset",
}

BRAND_KEYWORDS_FOR_TYPOSQUAT = [
    "paypal", "google", "microsoft", "apple", "amazon", "facebook",
    "instagram", "netflix", "bankofamerica", "wellsfargo", "chase",
    "linkedin", "dropbox", "office365", "outlook", "coinbase", "binance",
]

CRYPTO_KEYWORDS = {"wallet", "seed-phrase", "airdrop", "claim-token", "miner", "metamask-connect"}
RANSOM_KEYWORDS = {"decrypt", "ransom", "restore-files", "your-files-are-encrypted", "pay-bitcoin"}
REDIRECT_PARAMS = {"redirect", "url", "next", "return", "goto", "dest", "continue"}


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _is_ip_address(host: str) -> bool:
    return bool(re.match(r"^(\d{1,3}\.){3}\d{1,3}$", host)) or bool(
        re.match(r"^[0-9a-fA-F:]+$", host) and ":" in host
    )


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) == 0:
        return len(b)
    if len(b) == 0:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
        prev = cur
    return prev[-1]


def analyze_url(raw_url: str) -> dict:
    findings = []

    def add(id_, label, severity, detail, triggered, category=None):
        findings.append({
            "id": id_,
            "label": label,
            "severity": severity if triggered else "info",
            "detail": detail,
            "triggered": triggered,
            "category": category if triggered else None,
        })

    url = raw_url.strip()
    if not re.match(r"^[a-zA-Z]+://", url):
        url = "http://" + url  # allow bare domains, parse consistently

    parsed = urlparse(url)
    host = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    full_lower = url.lower()

    # 1. IP address instead of domain name
    is_ip = _is_ip_address(host)
    add("ip_host", "Domain is a raw IP address", "high",
        "Legitimate services almost always use a registered domain name, not a bare IP.",
        is_ip, "Malware hosting / C2 infrastructure")

    # 2. '@' symbol trick
    has_at = "@" in parsed.netloc
    add("at_symbol", "'@' symbol in URL", "medium",
        "Everything before '@' is ignored by browsers, a classic way to disguise the real destination.",
        has_at, "Phishing (disguised destination)")

    # 3. Suspicious TLD
    tld = host.split(".")[-1].lower() if "." in host else ""
    bad_tld = tld in SUSPICIOUS_TLDS
    add("suspicious_tld", f"Uncommon/high-abuse TLD (.{tld})", "medium",
        "This top-level domain is frequently used in phishing/malware campaigns due to low registration cost.",
        bad_tld, "Phishing / disposable malware infrastructure")

    # 4. Overall URL length
    long_url = len(url) > 100
    add("url_length", "Unusually long URL", "low",
        f"URL is {len(url)} characters. Long URLs are sometimes used to hide the real domain or bury payload paths.",
        long_url)

    # 5. Excess subdomains
    subdomain_count = max(host.count("."), 0)
    many_subs = subdomain_count >= 4
    add("subdomains", "Excessive subdomains", "medium",
        f"Host has {subdomain_count} dot-separated segments. Attackers stack subdomains to bury a fake brand name deep in the string.",
        many_subs)

    # 6. Punycode / IDN homograph
    has_punycode = "xn--" in host
    add("punycode", "Punycode (internationalized domain) detected", "high",
        "Punycode can render as lookalike characters (e.g. Cyrillic 'а' vs Latin 'a'), used for homograph phishing.",
        has_punycode, "Homograph phishing / brand impersonation")

    # 7. URL shortener
    is_shortener = host in URL_SHORTENERS
    add("shortener", "Known URL-shortening service", "medium",
        "Shorteners hide the real destination until the link is clicked, commonly used to bypass link filters.",
        is_shortener, "Obfuscated redirect")

    # 8. Phishing keywords in path/query
    matched_kw = [k for k in PHISHING_KEYWORDS if k in full_lower]
    add("phish_keywords", "Credential/account-themed wording", "medium",
        f"Found term(s): {', '.join(matched_kw)}." if matched_kw else "",
        bool(matched_kw), "Phishing (credential harvesting)")

    # 9/10. Suspicious file extension (incl. double-extension disguise)
    ext_match = re.search(r"(\.[a-z0-9]{2,4})(?:\?|$)", path.lower())
    ext_hit = None
    if ext_match and ext_match.group(1) in SUSPICIOUS_EXTENSIONS:
        ext_hit = ext_match.group(1)
    double_ext = bool(re.search(r"\.(pdf|doc|docx|xls|jpg|png)\.(exe|scr|bat|js|vbs|cmd|hta)(?:\?|$)", path.lower()))

    if ext_hit:
        sev, cat = SUSPICIOUS_EXTENSIONS[ext_hit]
        add("file_ext", f"Direct link to executable-type file ({ext_hit})", sev,
            "The URL points straight at a file type commonly used to deliver malware payloads.",
            True, cat)
    else:
        add("file_ext", "Direct link to executable-type file", "high", "", False)

    add("double_ext", "Disguised double file extension", "critical",
        "Filename hides a real executable behind a fake document/image extension (e.g. invoice.pdf.exe).",
        double_ext, "Disguised executable / Trojan")

    # 11. Non-standard port
    odd_port = parsed.port is not None and parsed.port not in (80, 443)
    add("port", "Non-standard port", "low",
        f"URL specifies port {parsed.port}, unusual for normal web traffic.",
        odd_port)

    # 12. Plain HTTP
    is_http = parsed.scheme == "http"
    add("no_https", "No HTTPS encryption", "low",
        "Traffic isn't encrypted; on its own this is common but it removes a layer of trust signal.",
        is_http)

    # 13. Heavy percent-encoding
    pct_count = full_lower.count("%")
    heavy_encoding = pct_count >= 4
    add("encoding", "Heavy percent-encoding", "medium",
        f"Found {pct_count} encoded characters, sometimes used to obscure suspicious text from quick review.",
        heavy_encoding)

    # 14. Typosquatting against common brands
    domain_core = host.split(".")[-2] if host.count(".") >= 1 else host
    typo_hits = []
    for brand in BRAND_KEYWORDS_FOR_TYPOSQUAT:
        if domain_core == brand:
            continue
        dist = _levenshtein(domain_core, brand)
        if 0 < dist <= 2 and len(domain_core) >= 4:
            typo_hits.append(brand)
    add("typosquat", "Possible brand typosquatting", "high",
        f"Domain '{domain_core}' closely resembles: {', '.join(typo_hits)}." if typo_hits else "",
        bool(typo_hits), "Phishing / brand impersonation")

    # 15. Open-redirect style query params
    qs = parse_qs(query)
    redirect_param_hits = [p for p in qs if p in REDIRECT_PARAMS]
    redirect_hit = bool(redirect_param_hits)
    add("redirect_param", "Redirect-style query parameter", "medium",
        f"Query includes a parameter like '{redirect_param_hits[0]}' that can forward to another site." if redirect_hit else "",
        redirect_hit, "Open redirect abuse")

    # 16. data: URI scheme
    is_data_uri = url.lower().startswith("data:")
    add("data_uri", "data: URI scheme", "critical",
        "Embeds executable content directly in the link itself rather than linking to a page.",
        is_data_uri, "Embedded payload")

    # 17. High-entropy / DGA-like subdomain
    first_label = host.split(".")[0] if host else ""
    entropy = _shannon_entropy(first_label)
    dga_like = len(first_label) >= 10 and entropy >= 3.6
    add("entropy", "High-entropy / random-looking subdomain", "medium",
        f"Subdomain '{first_label}' looks machine-generated (entropy {entropy:.2f}), a pattern seen in malware C2 domains.",
        dga_like, "Malware distribution / DGA-based C2")

    # 18. Crypto-drainer keywords
    crypto_hit = [k for k in CRYPTO_KEYWORDS if k in full_lower]
    add("crypto", "Crypto-wallet drainer wording", "high",
        f"Found term(s): {', '.join(crypto_hit)}." if crypto_hit else "",
        bool(crypto_hit), "Cryptocurrency wallet drainer / scam")

    # 19. Ransomware-themed wording
    ransom_hit = [k for k in RANSOM_KEYWORDS if k in full_lower]
    add("ransom", "Ransomware-themed wording", "high",
        f"Found term(s): {', '.join(ransom_hit)}." if ransom_hit else "",
        bool(ransom_hit), "Ransomware notice / extortion page")

    # --- Aggregate score -----------------------------------------------
    triggered = [f for f in findings if f["triggered"]]
    score = sum(SEVERITY_WEIGHTS[f["severity"]] for f in triggered)
    score = min(score, 100)

    if score >= 70:
        risk_level = "critical"
    elif score >= 45:
        risk_level = "high"
    elif score >= 15:
        risk_level = "medium"
    else:
        risk_level = "low"

    categories = []
    for f in triggered:
        if f["category"] and f["category"] not in categories:
            categories.append(f["category"])

    return {
        "input_url": raw_url,
        "normalized_url": url,
        "host": host,
        "score": score,
        "risk_level": risk_level,
        "findings": findings,
        "likely_categories": categories,
    }

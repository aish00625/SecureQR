"""Rule-based URL security analysis.

These checks are deterministic, explainable signals that are reported
SEPARATELY from the machine-learning prediction. No network request is ever
made to the scanned URL (no fetching, no DNS lookups), which removes any
SSRF risk and avoids alerting an attacker that their link was scanned.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass

from ..ml.features import SHORTENER_DOMAINS, split_host

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "work", "click", "country",
    "kim", "loan", "rest", "support", "cam", "icu", "buzz", "monster", "quest", "sbs",
    "cfd", "lol", "fit", "bid", "win", "review", "date", "racing", "download", "stream",
}
BRANDS = {
    "paypal", "apple", "icloud", "microsoft", "office365", "outlook", "google", "gmail",
    "amazon", "netflix", "facebook", "instagram", "whatsapp", "linkedin", "dropbox",
    "chase", "wellsfargo", "bankofamerica", "hsbc", "sbi", "hdfc", "icici", "axisbank",
    "paytm", "phonepe", "gpay", "flipkart", "ebay", "dhl", "fedex", "usps", "adobe", "coinbase",
    "binance", "metamask", "steam", "irctc", "aadhaar", "incometax",
}
SUSPICIOUS_WORDS = ("login", "log-in", "signin", "sign-in", "verify", "verification", "account",
                    "update", "secure", "banking", "confirm", "password", "wallet", "suspend",
                    "unlock", "kyc", "reward", "prize", "winner", "gift", "claim", "otp",
                    "webscr", "credential", "refund")
RISKY_EXTENSIONS = (".exe", ".apk", ".scr", ".bat", ".cmd", ".msi", ".jar", ".vbs", ".ps1",
                    ".dmg", ".pkg", ".hta", ".lnk", ".iso", ".appx", ".xapk")
REDIRECT_PARAMS = re.compile(r"(?i)[?&](url|redirect|redir|next|target|dest|destination|continue|"
                             r"return|returnurl|goto|out)=(https?%3a|https?:|//|%2f%2f)")
LOCAL_NETS = [ipaddress.ip_network(n) for n in
              ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")]
SECOND_LEVEL = {"co", "com", "net", "org", "ac", "gov", "edu", "nic", "or", "ne", "go"}


@dataclass
class Finding:
    id: str
    severity: str
    title: str
    detail: str
    points: int


def registered_domain(host: str) -> str:
    labels = [p for p in host.split(".") if p]
    if len(labels) >= 3 and labels[-2] in SECOND_LEVEL and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:]) if labels else host


def _ip_kind(host: str) -> str | None:
    h = host.strip("[]")
    try:
        ip = ipaddress.ip_address(h)
        local = ip.is_loopback or ip.is_link_local or any(ip in n for n in LOCAL_NETS if n.version == ip.version)
        return "private" if local else "public"
    except ValueError:
        pass
    if re.fullmatch(r"0x[0-9a-f]{1,8}|\d{8,10}", h) or re.fullmatch(r"(0x[0-9a-f]+|0\d+)(\.(0x[0-9a-f]+|\d+)){3}", h):
        return "obfuscated"
    return None


def analyze_url(url: str) -> dict:
    """Run every heuristic and return score (0-100), findings and URL facts."""
    findings: list[Finding] = []

    def add(fid, sev, title, detail, pts):
        findings.append(Finding(fid, sev, title, detail, pts))

    raw = url.strip()
    m = re.match(r"^([a-zA-Z][a-zA-Z0-9+.\-]*):(//)?", raw)
    scheme = m.group(1).lower() if m else ""
    has_authority = bool(m and m.group(2))
    rest = raw[m.end():] if (m and has_authority) else (raw if not m else raw[m.end():])
    host, path, query = split_host(rest)
    authority = re.match(r"^[^/?#]*", rest).group(0)
    ip_kind = _ip_kind(host)
    reg = host if ip_kind else registered_domain(host)
    labels = [p for p in host.split(".") if p]

    # --- scheme ----------------------------------------------------------
    if scheme in {"javascript", "data", "vbscript", "file", "blob", "intent", "jar",
                  "ms-msdt", "search-ms", "ms-officecmd"}:
        add("dangerous_scheme", "critical", f"Dangerous '{scheme}:' scheme",
            "This scheme can run script, open local files or launch apps instead of a web page.", 70)
    elif scheme == "http":
        add("no_https", "medium", "Unencrypted HTTP",
            "The link does not use HTTPS, so traffic (including passwords) can be read or altered in transit.", 12)
    elif scheme == "":
        add("no_scheme", "low", "No scheme specified",
            "Without https:// a browser will usually fall back to unencrypted HTTP.", 5)

    # --- host --------------------------------------------------------------
    if ip_kind == "obfuscated":
        add("obfuscated_ip", "high", "Obfuscated IP address",
            "The host is an IP written in hex/decimal/octal form - a classic trick to hide the destination.", 35)
    elif ip_kind:
        add("ip_host", "high", "Raw IP address instead of a domain",
            "Legitimate services use domain names; a bare IP address hides who runs the server"
            + (" and points to a local/private network." if ip_kind == "private" else "."), 25)

    if "@" in authority:
        add("userinfo_at", "high", "'@' in the address",
            "Everything before '@' is ignored by the browser, so 'bank.com@evil.com' really opens evil.com.", 30)

    if "xn--" in host:
        add("punycode", "high", "Punycode (internationalised) domain",
            "Look-alike Unicode characters can impersonate real brands (homograph attack).", 25)
    elif any(ord(ch) > 127 for ch in host):
        add("unicode_host", "high", "Non-ASCII characters in domain",
            "The domain contains Unicode characters that may imitate a familiar brand.", 25)

    if host in SHORTENER_DOMAINS or reg in SHORTENER_DOMAINS:
        add("shortener", "medium", "URL shortener / redirect service",
            f"'{reg}' hides the final destination. The real target cannot be verified without visiting it.", 15)

    if not ip_kind and len(labels) - len(reg.split(".")) >= 3:
        add("many_subdomains", "medium", "Excessive subdomains",
            f"{len(labels) - len(reg.split('.'))} subdomain levels - often used to push the real domain out of view.", 10)

    tld = labels[-1] if labels else ""
    if tld in SUSPICIOUS_TLDS:
        add("suspicious_tld", "medium", f"High-abuse top-level domain (.{tld})",
            "This TLD is disproportionately used for phishing and malware campaigns.", 10)

    if host.count("-") >= 3:
        add("hyphenated_host", "medium", "Heavily hyphenated domain",
            "Domains like secure-login-account-verify.com imitate trustworthy wording.", 10)
    if not ip_kind and re.search(r"\d", reg.split(".")[0] if reg else "") and len(re.findall(r"\d", host)) >= 4:
        add("digits_in_domain", "low", "Many digits in domain", "Randomised domains are common in throw-away phishing sites.", 5)

    port_m = re.match(r"^[^/?#@]*@?[^/?#:]*:(\d+)", authority)
    if port_m and port_m.group(1) not in {"80", "443"}:
        add("nonstandard_port", "medium", f"Non-standard port :{port_m.group(1)}",
            "Web services normally use port 80/443; custom ports are common on compromised or temporary servers.", 10)

    # --- brand impersonation ------------------------------------------------
    reg_core = reg.split(".")[0] if reg else ""
    elsewhere = (".".join(labels[:-len(reg.split('.'))]) + " " + path + " " + query).lower()
    hit = sorted(b for b in BRANDS if b in elsewhere and b not in reg_core)
    if hit and not ip_kind:
        add("brand_impersonation", "high", "Brand name outside the real domain",
            f"Mentions '{hit[0]}' but the actual registered domain is '{reg}'.", 25)
    elif hit and ip_kind:
        add("brand_on_ip", "high", "Brand name on an IP-address host",
            f"Mentions '{hit[0]}' while being hosted on a raw IP address.", 15)

    # --- path / query -------------------------------------------------------
    lower = raw.lower()
    words = sorted({w for w in SUSPICIOUS_WORDS if w in lower})
    if words:
        add("suspicious_keywords", "low" if len(words) < 3 else "medium",
            "Credential-related keywords",
            "Contains: " + ", ".join(words[:6]) + ".", min(4 * len(words), 15))

    if any(path.lower().endswith(ext) for ext in RISKY_EXTENSIONS):
        add("executable_download", "high", "Direct download of an executable/app",
            "The link points to an installer or script file that could contain malware.", 30)

    if "//" in path or REDIRECT_PARAMS.search(raw):
        add("open_redirect", "medium", "Embedded redirect",
            "The URL forwards to another address - often used to bounce victims through a trusted domain.", 10)

    if raw.count("%") >= 5 or re.search(r"%[0-9a-f]{2}", authority, re.I):
        add("encoded_chars", "low", "Heavy percent-encoding", "Encoded characters can hide the real content of a link.", 5)

    if len(raw) > 200:
        add("very_long_url", "medium", "Very long URL", f"{len(raw)} characters - long URLs can bury the real destination.", 8)
    elif len(raw) > 100:
        add("long_url", "low", "Long URL", f"{len(raw)} characters.", 4)

    score = min(sum(f.points for f in findings), 100)
    critical = any(f.severity == "critical" for f in findings)
    findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], -f.points))
    return {
        "score": score,
        "critical": critical,
        "findings": [asdict(f) for f in findings],
        "facts": {
            "scheme": scheme or None,
            "https": scheme == "https",
            "host": host,
            "registered_domain": reg,
            "subdomain_count": max(len(labels) - len(reg.split(".")), 0) if not ip_kind else 0,
            "tld": tld if not ip_kind else None,
            "is_ip": bool(ip_kind),
            "length": len(raw),
        },
    }

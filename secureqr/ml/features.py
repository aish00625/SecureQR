"""Shared URL feature pipeline used by BOTH training and inference.

Everything the model sees goes through :func:`canonicalize_url` and the
transformers defined here, and the fitted pipeline is serialised as a single
scikit-learn object. This guarantees that training and prediction use exactly
the same preprocessing.
"""
from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter

import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin

# --------------------------------------------------------------------------
# Canonicalisation
# --------------------------------------------------------------------------
_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")


def canonicalize_url(url: str) -> str:
    """Normalise a URL into the format used by the training dataset.

    The Kaggle ``phishing_site_urls.csv`` dataset stores URLs *without* a
    scheme (``example.com/path``); the only 107 rows that do carry
    ``http://`` / ``https://`` are all labelled *bad*. QR codes, on the other
    hand, almost always contain ``https://``. Feeding the raw scheme to the
    model would therefore teach it "https means phishing". We strip the
    scheme for ML purposes; HTTPS is evaluated separately by the heuristic
    engine.
    """
    if url is None:
        return ""
    url = str(url).strip()
    url = _SCHEME_RE.sub("", url, count=1)
    # Lower-case only the host part; paths are case sensitive.
    slash = url.find("/")
    if slash == -1:
        return url.lower()
    return url[:slash].lower() + url[slash:]


def split_host(canonical: str) -> tuple[str, str, str]:
    """Return (host, path, query) for a scheme-less canonical URL.

    Implemented by hand rather than with ``urllib.parse`` because real-world
    phishing URLs are frequently malformed (unbalanced ``[``, bad ports...)
    and ``urlsplit`` raises on them.
    """
    m = re.match(r"^([^/?#]*)([^?#]*)(?:\?([^#]*))?", canonical or "")
    authority, path, query = m.group(1), m.group(2) or "", m.group(3) or ""
    host = authority.rsplit("@", 1)[-1]          # drop user-info
    if host.startswith("["):                      # IPv6 literal
        host = host[1:host.find("]")] if "]" in host else host[1:]
    elif host.count(":") == 1:                    # strip :port
        host = host.split(":", 1)[0]
    return host.lower().rstrip("."), path, query


# --------------------------------------------------------------------------
# Hand-crafted lexical features
# --------------------------------------------------------------------------
SUSPICIOUS_WORDS = (
    "login", "signin", "sign-in", "verify", "verification", "account", "update",
    "secure", "security", "banking", "confirm", "password", "webscr", "ebayisapi",
    "paypal", "wallet", "suspend", "unlock", "billing", "invoice", "free", "bonus",
    "lucky", "admin", "wp-", ".php", "cmd=",
)

SHORTENER_DOMAINS = frozenset({
    "bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "bit.do", "cutt.ly", "shorturl.at", "rebrand.ly", "tiny.cc",
    "rb.gy", "s.id", "t.ly", "v.gd", "qrco.de", "qr-codes.io", "qr.io",
    "lnkd.in", "trib.al", "shorte.st", "bl.ink", "short.io", "tr.im",
    "x.co", "u.to", "clck.ru", "soo.gd", "surl.li", "q-r.to", "qr.net",
})

FEATURE_NAMES = [
    "url_length", "host_length", "path_length", "query_length",
    "num_dots", "num_hyphens", "num_digits", "digit_ratio",
    "num_at", "num_question", "num_equals", "num_ampersand", "num_percent",
    "num_slashes", "num_underscores", "num_tilde", "num_uppercase",
    "num_subdomains", "is_ip_host", "has_port", "tld_length",
    "host_has_digits", "host_hyphens", "host_entropy", "is_punycode",
    "double_slash_in_path", "suspicious_word_count", "is_shortener",
    "path_depth", "longest_token",
]


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _is_ip(host: str) -> bool:
    if not host:
        return False
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        # Hex / decimal encoded IPs such as 0x7f000001 or 3232235777
        return bool(re.fullmatch(r"(0x[0-9a-f]+|\d{8,10})", host))


def lexical_features(url: str) -> list[float]:
    """Compute the hand-crafted feature vector for one URL (raw or canonical)."""
    c = canonicalize_url(url)
    host, path, query = split_host(c)
    host_no_port = host
    has_port = 1 if re.match(r"^[^/]*:\d+", c) else 0
    labels = [p for p in host_no_port.split(".") if p]
    tld = labels[-1] if labels else ""
    lower = c.lower()
    tokens = re.split(r"[^A-Za-z0-9]+", c)
    return [
        len(c),
        len(host_no_port),
        len(path),
        len(query),
        c.count("."),
        c.count("-"),
        sum(ch.isdigit() for ch in c),
        (sum(ch.isdigit() for ch in c) / len(c)) if c else 0.0,
        c.count("@"),
        c.count("?"),
        c.count("="),
        c.count("&"),
        c.count("%"),
        c.count("/"),
        c.count("_"),
        c.count("~"),
        sum(ch.isupper() for ch in c),
        max(len(labels) - 2, 0),
        1 if _is_ip(host_no_port) else 0,
        has_port,
        len(tld),
        1 if any(ch.isdigit() for ch in host_no_port) else 0,
        host_no_port.count("-"),
        _entropy(host_no_port),
        1 if "xn--" in host_no_port else 0,
        1 if "//" in path else 0,
        sum(lower.count(w) for w in SUSPICIOUS_WORDS),
        1 if host_no_port in SHORTENER_DOMAINS else 0,
        len([p for p in path.split("/") if p]),
        max((len(t) for t in tokens), default=0),
    ]


class LexicalFeatures(BaseEstimator, TransformerMixin):
    """Stateless sklearn transformer: iterable of URLs -> dense feature matrix."""

    def fit(self, X, y=None):  # noqa: D401 - sklearn API
        return self

    def transform(self, X):
        rows = [lexical_features(u) for u in X]
        arr = np.asarray(rows, dtype=np.float64)
        # log1p compresses heavy-tailed counts so a linear model is not
        # dominated by a handful of extremely long URLs.
        return np.log1p(np.clip(arr, 0, None))

    def get_feature_names_out(self, input_features=None):
        return np.asarray(FEATURE_NAMES, dtype=object)


class Canonicalizer(BaseEstimator, TransformerMixin):
    """First pipeline step: map raw URLs to their canonical form."""

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        return [canonicalize_url(u) for u in X]


# Original 6 features from the first version of SecureQR (kept for the
# baseline reproduction in the evaluation report).
def legacy_features(url: str) -> list[int]:
    return [
        len(url),
        url.count("."),
        url.count("-"),
        sum(ch.isdigit() for ch in url),
        1 if "@" in url else 0,
        1 if url.startswith("https") else 0,
    ]

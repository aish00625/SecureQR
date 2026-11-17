"""Classify decoded QR payloads and extract URLs from them.

QR codes carry far more than web links: Wi-Fi credentials, UPI payment
requests, phone numbers, SMS, e-mail, vCards, plain text. Only URL-like
payloads are sent to the ML model; everything else is described to the user
with type-specific warnings.
"""
from __future__ import annotations

import re
import unicodedata
from urllib.parse import parse_qs, urlsplit

URL_IN_TEXT = re.compile(r"""(?i)\b((?:https?://|www\.)[^\s<>"'`]+)""")
BARE_DOMAIN = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}(?::\d{1,5})?(?:[/?#][^\s]*)?$", re.I)
BARE_IP = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?(?:[/?#][^\s]*)?$")
DANGEROUS_SCHEMES = {"javascript", "data", "vbscript", "file", "blob", "intent", "jar", "ms-msdt",
                     "search-ms", "ms-officecmd"}
CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def clean_text(text: str, max_len: int = 4096) -> str:
    """Strip control characters and normalise Unicode; truncate."""
    text = unicodedata.normalize("NFC", text or "")
    text = CONTROL_CHARS.sub("", text).strip()
    return text[:max_len]


def classify_payload(payload: str) -> dict:
    """Return ``{"type", "url", "label", "details", "notes"}`` for a QR payload."""
    text = clean_text(payload)
    low = text.lower()
    info = {"type": "text", "label": "Plain text", "url": None, "details": {}, "notes": []}
    if not text:
        info.update(type="empty", label="Empty payload")
        return info

    scheme = low.split(":", 1)[0] if ":" in low else ""

    if re.match(r"^https?://", low):
        info.update(type="url", label="Web link", url=text)
    elif scheme in DANGEROUS_SCHEMES:
        info.update(type="dangerous_scheme", label=f"{scheme}: link", url=text)
        info["notes"].append(f"The '{scheme}:' scheme can execute code or load local content. "
                             "Legitimate QR codes almost never use it.")
    elif low.startswith("upi://"):
        q = parse_qs(urlsplit(text).query)
        info.update(type="upi", label="UPI payment request", details={
            "payee_vpa": (q.get("pa") or [""])[0], "payee_name": (q.get("pn") or [""])[0],
            "amount": (q.get("am") or [""])[0], "note": (q.get("tn") or [""])[0]})
        info["notes"].append("This QR code asks you to SEND money. You never need to scan a QR "
                             "code or enter your UPI PIN to RECEIVE money.")
    elif low.startswith("wifi:"):
        fields = dict(re.findall(r"([TSPH]):((?:\\.|[^;])*)", text[5:]))
        info.update(type="wifi", label="Wi-Fi network", details={
            "ssid": fields.get("S", ""), "security": fields.get("T", "nopass") or "nopass",
            "hidden": fields.get("H", "false")})
        if (fields.get("T") or "nopass").lower() in {"nopass", ""}:
            info["notes"].append("Open (unencrypted) Wi-Fi network - traffic can be intercepted.")
        elif fields.get("T", "").upper() == "WEP":
            info["notes"].append("WEP encryption is obsolete and easily broken.")
    elif low.startswith(("mailto:", "matmsg:")):
        info.update(type="email", label="E-mail")
    elif low.startswith("tel:"):
        info.update(type="phone", label="Phone number", details={"number": text[4:]})
    elif low.startswith(("sms:", "smsto:", "mms:")):
        info.update(type="sms", label="SMS message")
        info["notes"].append("Pre-filled SMS codes can send messages to premium-rate numbers.")
    elif low.startswith("begin:vcard") or low.startswith("mecard:"):
        info.update(type="contact", label="Contact card")
    elif low.startswith("geo:"):
        info.update(type="location", label="Geo location")
    elif BARE_DOMAIN.match(text) or BARE_IP.match(text):
        info.update(type="url", label="Web link (no scheme)", url=text)
        info["notes"].append("No http/https scheme - a browser would assume HTTP.")
    else:
        m = URL_IN_TEXT.search(text)
        if m:
            info.update(type="text_with_url", label="Text containing a link", url=m.group(1).rstrip(".,;)]"))
    return info


def extract_url(payload: str) -> str | None:
    return classify_payload(payload)["url"]


def defang(url: str) -> str:
    """Make a URL non-clickable for safe display/sharing (hxxps://example[.]com)."""
    if not url:
        return ""
    out = re.sub(r"^http", "hxxp", url, flags=re.I)
    m = re.match(r"^([a-z][a-z0-9+.\-]*://)?([^/?#]*)(.*)$", out, re.I | re.S)
    if not m:
        return out
    return (m.group(1) or "") + m.group(2).replace(".", "[.]") + m.group(3)

"""Combines payload classification, heuristics and ML into one verdict.

Risk policy (documented in docs/ARCHITECTURE.md):

  HIGH    critical heuristic finding (e.g. javascript: scheme)
          OR heuristic score >= 50
          OR ML phishing probability >= 0.80 AND at least one corroborating
             heuristic finding of medium severity or above (URL-shortener
             findings do not count: the model cannot see the real target)
  MEDIUM  ML phishing probability >= 0.50 (ML alone, no corroboration)
          OR heuristic score >= 20
          OR any HIGH-severity heuristic finding
  LOW     everything else

The ML model and the heuristics are reported separately so a user can see
*why* a link was flagged. ML alone can raise the level to MEDIUM but needs
at least one corroborating heuristic to reach HIGH - this limits the impact
of model false positives on unfamiliar-but-legitimate domains.
"""
from __future__ import annotations

from .content import classify_payload, clean_text, defang
from .heuristics import analyze_url

HIGH_ML, MED_ML = 0.80, 0.50
HIGH_H, MED_H = 50, 20
NON_CORROBORATING = {"shortener"}


def risk_level(ml: dict | None, heur: dict | None) -> tuple[str, list[str]]:
    reasons: list[str] = []
    p = ml.get("phishing_probability") if ml and ml.get("available") else None
    h = heur["score"] if heur else 0
    findings = (heur or {}).get("findings", [])
    high_sev = any(f["severity"] in {"high", "critical"} for f in findings)
    corroborated = any(f["severity"] in {"medium", "high", "critical"} and f["id"] not in NON_CORROBORATING
                       for f in findings)

    if heur and heur.get("critical"):
        reasons.append("A critical heuristic rule was triggered.")
        return "HIGH", reasons
    if h >= HIGH_H:
        reasons.append(f"Heuristic risk score {h}/100 is at or above {HIGH_H}.")
        return "HIGH", reasons
    if p is not None and p >= HIGH_ML and corroborated:
        reasons.append(f"ML phishing probability {p:.0%} is corroborated by heuristic findings.")
        return "HIGH", reasons
    if p is not None and p >= MED_ML:
        reasons.append(f"ML model classifies the URL as phishing ({p:.0%}).")
    if h >= MED_H:
        reasons.append(f"Heuristic risk score {h}/100 is at or above {MED_H}.")
    elif high_sev:
        reasons.append("At least one high-severity heuristic warning was raised.")
    if reasons:
        return "MEDIUM", reasons
    reasons.append("No significant ML or heuristic risk indicators.")
    return "LOW", reasons


RECOMMENDATIONS = {
    "HIGH": ["Do not open this link or enter any information.",
             "If it arrived on a poster, parcel or message, report it to the organisation it imitates.",
             "In India you can report cyber fraud at cybercrime.gov.in or by calling 1930."],
    "MEDIUM": ["Verify the domain carefully before opening.",
               "Navigate to the organisation's site yourself instead of using the QR link.",
               "Never enter passwords, OTPs or UPI PINs on a page reached from a QR code you do not trust."],
    "LOW": ["No strong risk indicators were found, but no scanner is perfect.",
            "Still check the domain name before entering any sensitive data."],
}


CONTENT_RECOMMENDATIONS = {
    "upi": ["Check that the payee name and UPI ID match the person or shop you intend to pay.",
            "Confirm the amount before entering your UPI PIN.",
            "If someone says you will RECEIVE money by scanning this code, it is a scam."],
    "wifi": ["Prefer networks protected with WPA2/WPA3.",
             "Avoid logging in to banking or work accounts on open networks, or use a VPN."],
    "sms": ["Check the recipient number before sending; premium-rate numbers can cost money."],
    "text": ["The code contains only text; no action is triggered by scanning it."],
}


def analyze_payload(payload: str, predictor) -> dict:
    """Full analysis of one decoded QR payload or user-entered URL."""
    content = classify_payload(payload)
    result = {
        "raw_content": clean_text(payload),
        "content_type": content["type"],
        "content_label": content["label"],
        "content_details": content["details"],
        "content_notes": content["notes"],
        "url": content["url"],
        "url_defanged": defang(content["url"]) if content["url"] else None,
        "ml": None,
        "heuristics": None,
    }

    if content["url"]:
        result["heuristics"] = analyze_url(content["url"])
        if content["type"] != "dangerous_scheme":
            result["ml"] = predictor.predict(content["url"])
            if any(f["id"] == "shortener" for f in result["heuristics"]["findings"]):
                result["content_notes"].append(
                    "This is a shortened link. The ML model only sees the short code, not the real "
                    "destination, so its prediction is less reliable here.")
        level, reasons = risk_level(result["ml"], result["heuristics"])
    elif content["type"] == "upi":
        level, reasons = "MEDIUM", ["UPI payment request - confirm the payee before paying."]
    elif content["type"] == "wifi" and content["notes"]:
        level, reasons = "MEDIUM", ["Insecure Wi-Fi configuration."]
    elif content["type"] == "sms":
        level, reasons = "MEDIUM", ["Pre-filled SMS - check the recipient number and text."]
    elif content["type"] == "empty":
        level, reasons = "LOW", ["The QR code contains no data."]
    else:
        level, reasons = "LOW", ["The QR code does not contain a web link."]

    result["risk_level"] = level
    result["risk_reasons"] = reasons
    result["recommendations"] = CONTENT_RECOMMENDATIONS.get(content["type"], RECOMMENDATIONS[level])
    return result

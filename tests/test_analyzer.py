import pytest

from secureqr.core.analyzer import analyze_payload, risk_level
from secureqr.core.predictor import Predictor


class FakePredictor:
    def __init__(self, p):
        self.p = p

    def predict(self, url):
        return {"available": True, "phishing_probability": self.p,
                "label": "PHISHING" if self.p >= 0.5 else "LEGITIMATE", "threshold": 0.5, "model": "fake"}


def H(score=0, findings=(), critical=False):
    return {"score": score, "critical": critical, "findings": list(findings)}


def F(id_, sev):
    return {"id": id_, "severity": sev}


@pytest.mark.parametrize("p,heur,level", [
    (0.05, H(0), "LOW"),
    (0.60, H(0), "MEDIUM"),                                            # ML alone -> medium
    (0.95, H(0), "MEDIUM"),                                            # ML alone never HIGH
    (0.95, H(12, [F("no_https", "medium")]), "HIGH"),                  # corroborated
    (0.95, H(15, [F("shortener", "medium")]), "MEDIUM"),               # shortener doesn't corroborate
    (0.10, H(55, [F("ip_host", "high")]), "HIGH"),                     # rules alone
    (0.10, H(25, [F("ip_host", "high")]), "MEDIUM"),
    (0.10, H(70, [F("dangerous_scheme", "critical")], True), "HIGH"),
    (None, H(5, [F("long_url", "low")]), "LOW"),
])
def test_risk_policy(p, heur, level):
    ml = None if p is None else {"available": True, "phishing_probability": p}
    assert risk_level(ml, heur)[0] == level


def test_ml_and_heuristics_reported_separately():
    r = analyze_payload("http://198.51.100.4/paypal/login.php", FakePredictor(0.99))
    assert r["ml"]["phishing_probability"] == 0.99
    assert r["heuristics"]["score"] > 0
    assert r["risk_level"] == "HIGH"
    assert r["url_defanged"].startswith("hxxp://198[.]51")
    assert r["risk_reasons"] and r["recommendations"]


def test_dangerous_scheme_skips_ml():
    r = analyze_payload("javascript:fetch('//evil')", FakePredictor(0.0))
    assert r["ml"] is None and r["risk_level"] == "HIGH"


def test_non_url_payloads():
    assert analyze_payload("Just some text", FakePredictor(0.9))["risk_level"] == "LOW"
    assert analyze_payload("upi://pay?pa=x@ybl&am=1", FakePredictor(0.9))["risk_level"] == "MEDIUM"
    assert analyze_payload("WIFI:T:nopass;S:Open;;", FakePredictor(0.9))["risk_level"] == "MEDIUM"


def test_shortener_adds_reliability_note():
    r = analyze_payload("https://bit.ly/abc123", FakePredictor(0.99))
    assert any("shortened" in n for n in r["content_notes"])
    assert r["risk_level"] == "MEDIUM"


def test_works_without_model(tmp_path):
    r = analyze_payload("https://example.com", Predictor(str(tmp_path / "none.joblib")))
    assert r["ml"]["available"] is False
    assert r["risk_level"] in {"LOW", "MEDIUM", "HIGH"}


def test_content_specific_recommendations():
    r = analyze_payload("upi://pay?pa=x@ybl&am=1", FakePredictor(0.1))
    assert any("UPI PIN" in x or "payee" in x for x in r["recommendations"])
    assert not any("domain" in x for x in r["recommendations"])

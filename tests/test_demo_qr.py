"""Every demo QR code decodes to its intended payload and gets the expected
risk level (cases chosen so the outcome is driven by deterministic rules)."""
import importlib.util

import pytest

from tests.conftest import ROOT, upload

spec = importlib.util.spec_from_file_location("gen", ROOT / "scripts" / "generate_demo_qr.py")
gen = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gen)

EXPECTED_RISK = {
    "03_ip_login_http": "HIGH", "04_brand_lookalike": "HIGH", "06_userinfo_trick": "HIGH",
    "07_apk_download": "HIGH", "08_javascript_scheme": "HIGH", "09_upi_payment": "MEDIUM",
    "10_open_wifi": "MEDIUM", "11_plain_text": "LOW",
}


@pytest.mark.parametrize("name,text", list(gen.DEMOS.items()))
def test_demo_qr(client, csrf, name, text):
    data = (ROOT / "demo_qr" / f"{name}.png").read_bytes()
    r = upload(client, csrf, data, f"{name}.png")
    assert r.status_code == 200
    res = r.json["results"][0]
    assert res["raw_content"] == text
    if name in EXPECTED_RISK:
        assert res["risk_level"] == EXPECTED_RISK[name]

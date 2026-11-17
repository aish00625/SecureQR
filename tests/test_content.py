import pytest

from secureqr.core.content import classify_payload, clean_text, defang, extract_url


@pytest.mark.parametrize("payload,ctype,url", [
    ("https://example.com/a", "url", "https://example.com/a"),
    ("HTTP://EXAMPLE.COM", "url", "HTTP://EXAMPLE.COM"),
    ("example.com/login", "url", "example.com/login"),
    ("192.168.0.1:8080/x", "url", "192.168.0.1:8080/x"),
    ("javascript:alert(1)", "dangerous_scheme", "javascript:alert(1)"),
    ("data:text/html,<script>alert(1)</script>", "dangerous_scheme", "data:text/html,<script>alert(1)</script>"),
    ("Visit https://promo.example.net/deal today!", "text_with_url", "https://promo.example.net/deal"),
    ("Hello world", "text", None),
    ("tel:+911234567890", "phone", None),
    ("mailto:a@b.com", "email", None),
    ("SMSTO:12345:hi", "sms", None),
    ("BEGIN:VCARD\nFN:Test\nEND:VCARD", "contact", None),
    ("", "empty", None),
])
def test_classify_payload(payload, ctype, url):
    info = classify_payload(payload)
    assert info["type"] == ctype
    assert info["url"] == url


def test_upi_payment_details_and_warning():
    info = classify_payload("upi://pay?pa=merchant@okaxis&pn=Shop%20Name&am=499.00&cu=INR")
    assert info["type"] == "upi"
    assert info["details"]["payee_vpa"] == "merchant@okaxis"
    assert info["details"]["amount"] == "499.00"
    assert any("UPI PIN" in n for n in info["notes"])


def test_wifi_open_network_flagged():
    info = classify_payload("WIFI:T:nopass;S:FreeAirport;;")
    assert info["type"] == "wifi" and info["details"]["ssid"] == "FreeAirport"
    assert info["notes"]


def test_wifi_wpa_not_flagged():
    assert classify_payload("WIFI:T:WPA;S:Home;P:pw;;")["notes"] == []


def test_extract_url():
    assert extract_url("see www.example.org/page.") == "www.example.org/page"
    assert extract_url("no links here") is None


def test_clean_text_strips_control_chars_and_truncates():
    assert clean_text("a\x00b\x07c\n") == "abc"
    assert len(clean_text("x" * 10000, max_len=100)) == 100


def test_defang():
    assert defang("https://evil.example.com/a.b") == "hxxps://evil[.]example[.]com/a.b"
    assert defang("example.com") == "example[.]com"

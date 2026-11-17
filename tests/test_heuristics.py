import pytest

from secureqr.core.heuristics import analyze_url, registered_domain


def ids(url):
    return {f["id"] for f in analyze_url(url)["findings"]}


def test_clean_https_url_scores_zero():
    r = analyze_url("https://www.wikipedia.org/")
    assert r["score"] == 0 and r["findings"] == []
    assert r["facts"]["https"] is True and r["facts"]["registered_domain"] == "wikipedia.org"


@pytest.mark.parametrize("url,expected", [
    ("http://example.com", "no_https"),
    ("http://203.0.113.9/login", "ip_host"),
    ("http://0x7f000001/", "obfuscated_ip"),
    ("http://3232235777/", "obfuscated_ip"),
    ("https://bit.ly/abc", "shortener"),
    ("https://google.com@evil.example/x", "userinfo_at"),
    ("https://xn--pypal-4ve.com/", "punycode"),
    ("https://a.b.c.d.example.com/", "many_subdomains"),
    ("https://cheap-deals.top/", "suspicious_tld"),
    ("https://secure-account-login-verify.com/", "hyphenated_host"),
    ("https://example.com:8443/", "nonstandard_port"),
    ("https://paypal.com.verify-account.net/", "brand_impersonation"),
    ("https://example.com/update/app.apk", "executable_download"),
    ("https://example.com/r?url=https%3A%2F%2Fevil.com", "open_redirect"),
    ("javascript:alert(document.cookie)", "dangerous_scheme"),
    ("example.com/login", "no_scheme"),
])
def test_detects(url, expected):
    assert expected in ids(url)


def test_brand_on_own_domain_is_not_impersonation():
    assert "brand_impersonation" not in ids("https://www.paypal.com/signin")
    assert "brand_impersonation" not in ids("https://accounts.google.com/")


def test_standard_ports_not_flagged():
    assert "nonstandard_port" not in ids("https://example.com:443/")


def test_dangerous_scheme_is_critical():
    r = analyze_url("javascript:alert(1)")
    assert r["critical"] is True and r["score"] >= 50


def test_score_is_capped_and_findings_sorted():
    r = analyze_url("http://paypal.secure.login.verify.198.51.100.7.example.top:8080/"
                    "webscr/login.php?cmd=_login&redirect=https://x.y/" + "a" * 200)
    assert r["score"] <= 100
    sev = ["critical", "high", "medium", "low", "info"]
    order = [sev.index(f["severity"]) for f in r["findings"]]
    assert order == sorted(order)


@pytest.mark.parametrize("host,reg", [("a.b.example.co.uk", "example.co.uk"), ("www.nie.ac.in", "nie.ac.in"),
                                      ("x.example.com", "example.com"), ("localhost", "localhost")])
def test_registered_domain(host, reg):
    assert registered_domain(host) == reg


def test_ip_host_facts_and_private_detection():
    r = analyze_url("http://198.51.100.23:8080/login")
    assert r["facts"]["registered_domain"] == "198.51.100.23" and r["facts"]["is_ip"]
    assert "digits_in_domain" not in {f["id"] for f in r["findings"]}
    assert "local/private" not in r["findings"][0]["detail"]
    assert "local/private" in analyze_url("http://192.168.0.10/")["findings"][0]["detail"]

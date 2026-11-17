import json

import pytest

from tests.conftest import ROOT, blank_png, make_qr, upload


# ---------------------------------------------------------------- pages
@pytest.mark.parametrize("path", ["/", "/scan", "/history", "/analytics", "/about"])
def test_pages_render(client, path):
    r = client.get(path)
    assert r.status_code == 200
    assert b'name="csrf-token"' in r.data


def test_unknown_page_html_404(client):
    r = client.get("/does-not-exist")
    assert r.status_code == 404 and b"Not Found" in r.data


def test_unknown_api_json_404(client):
    r = client.get("/api/nope")
    assert r.status_code == 404 and r.is_json


def test_security_headers(client):
    h = client.get("/").headers
    assert "default-src 'self'" in h["Content-Security-Policy"]
    assert "script-src 'self'" in h["Content-Security-Policy"]
    assert h["X-Content-Type-Options"] == "nosniff"
    assert h["X-Frame-Options"] == "DENY"
    assert h["Referrer-Policy"] == "no-referrer"


def test_session_cookie_flags(client):
    client.get("/scan")
    cookie = client.get_cookie("secureqr_session")
    assert cookie is not None and cookie.http_only and cookie.same_site == "Lax"


def test_health(client):
    j = client.get("/api/health").json
    assert j["status"] == "ok" and j["model_loaded"] is True and "opencv" in j["decoders"]


# ----------------------------------------------------------------- CSRF
def test_post_without_csrf_rejected(client):
    r = client.post("/api/scan/url", json={"url": "https://example.com"})
    assert r.status_code == 400 and "CSRF" in r.json["message"]


def test_post_with_wrong_csrf_rejected(client, csrf):
    r = client.post("/api/scan/url", json={"url": "https://example.com"}, headers={"X-CSRF-Token": "x" + csrf})
    assert r.status_code == 400


def test_delete_without_csrf_rejected(client):
    assert client.delete("/api/history").status_code == 400


# ------------------------------------------------------------ image scan
def test_scan_valid_qr(client, csrf):
    r = upload(client, csrf, make_qr("http://198.51.100.23/paypal/login.php"))
    assert r.status_code == 200
    res = r.json["results"][0]
    assert res["url"] == "http://198.51.100.23/paypal/login.php"
    assert res["risk_level"] == "HIGH"
    assert res["ml"]["available"] and res["heuristics"]["score"] > 0
    assert isinstance(res["id"], int)


def test_scan_stylised_repo_sample(client, csrf, app):
    app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024
    data = (ROOT / "demo_qr" / "sample_stylised_qr.webp").read_bytes()
    r = upload(client, csrf, data, "sample.webp")
    assert r.status_code == 200 and r.json["results"][0]["url"] == "https://qr-codes.io/dX97eV"


def test_scan_image_without_qr(client, csrf):
    r = upload(client, csrf, blank_png())
    assert r.status_code == 422 and r.json["found"] is False


def test_scan_rejects_wrong_type(client, csrf):
    r = upload(client, csrf, b"%PDF-1.4 fake", "doc.pdf")
    assert r.status_code == 400 and r.json["error"] == "invalid_image"


def test_scan_rejects_spoofed_extension(client, csrf):
    r = upload(client, csrf, b"MZ\x90\x00 this is an exe", "photo.png")
    assert r.status_code == 400


def test_scan_missing_file_field(client, csrf):
    r = client.post("/api/scan/image", data={}, headers={"X-CSRF-Token": csrf})
    assert r.status_code == 400 and r.json["error"] == "no_file"


def test_scan_rejects_oversized_upload(client, csrf, app):
    app.config["MAX_CONTENT_LENGTH"] = 2000
    r = upload(client, csrf, b"\x89PNG\r\n\x1a\n" + b"0" * 5000)
    assert r.status_code == 413 and "too large" in r.json["message"]


def test_webcam_frame_no_qr_is_200(client, csrf):
    r = upload(client, csrf, blank_png(), "frame.jpg".replace("jpg", "png"), endpoint="/api/scan/frame")
    assert r.status_code == 200 and r.json["found"] is False


def test_webcam_frame_with_qr_saved_as_webcam(client, csrf):
    r = upload(client, csrf, make_qr("https://example.org", fmt=".jpg"), "frame.jpg", endpoint="/api/scan/frame")
    assert r.json["found"]
    assert client.get("/api/history").json["items"][0]["source"] == "webcam"


# -------------------------------------------------------------- url scan
def test_scan_url_ok(client, csrf):
    r = client.post("/api/scan/url", json={"url": "https://en.wikipedia.org/wiki/QR_code"}, headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200
    assert r.json["results"][0]["heuristics"]["facts"]["https"] is True


@pytest.mark.parametrize("body,msg", [
    (None, "JSON"), ({"url": 5}, "JSON"), ({"url": "   "}, "empty"),
    ({"url": "https://a.com/" + "a" * 3000}, "too long"), ({"url": "not a url at all"}, "spaces"),
    ({"url": "hello"}, "does not look like a URL"),
])
def test_scan_url_validation(client, csrf, body, msg):
    kw = {"json": body} if body is not None else {"data": "x"}
    r = client.post("/api/scan/url", headers={"X-CSRF-Token": csrf}, **kw)
    assert r.status_code == 400 and msg in r.json["message"]


# -------------------------------------------------------- history/stats
def test_history_flow(client, csrf):
    for u in ["https://a.example", "http://203.0.113.9/login"]:
        client.post("/api/scan/url", json={"url": u}, headers={"X-CSRF-Token": csrf})
    h = client.get("/api/history").json
    assert h["total"] == 2
    assert client.get("/api/history?risk=HIGH").json["total"] == 1
    assert client.get("/api/history?q=a.example").json["total"] == 1
    sid = h["items"][0]["id"]
    assert client.get(f"/api/history/{sid}").json["result"]["url"]
    assert client.get(f"/history/{sid}").status_code == 200
    assert client.delete(f"/api/history/{sid}", headers={"X-CSRF-Token": csrf}).json == {"deleted": 1}
    assert client.get(f"/api/history/{sid}").status_code == 404
    assert client.delete("/api/history", headers={"X-CSRF-Token": csrf}).json == {"deleted": 1}
    assert client.get("/api/stats").json["total"] == 0


def test_history_bad_params_are_clamped(client):
    r = client.get("/api/history?limit=99999&offset=-5&risk=DROP")
    assert r.status_code == 200 and r.json["limit"] == 100 and r.json["offset"] == 0


def test_history_detail_missing(client):
    assert client.get("/history/999").status_code == 404


def test_stored_xss_payload_is_escaped(client, csrf):
    payload = "https://x.example/</script><script>alert(1)</script>"
    r = client.post("/api/scan/url", json={"url": payload}, headers={"X-CSRF-Token": csrf})
    sid = r.json["results"][0]["id"]
    html = client.get(f"/history/{sid}").data.decode()
    assert "<script>alert(1)</script>" not in html
    blob = html.split('id="scan-data">', 1)[1].split("</script>", 1)[0]
    assert json.loads(blob)["url"] == payload  # data intact, rendered via textContent


def test_rate_limit(client, csrf, app):
    app.config["RATE_LIMIT_SCAN"] = 3
    codes = [client.post("/api/scan/url", json={"url": "https://e.example"}, headers={"X-CSRF-Token": csrf}).status_code
             for _ in range(5)]
    assert codes[:3] == [200, 200, 200] and codes[3] == 429


def test_model_endpoint_without_metrics(client):
    assert client.get("/api/model").json == {}


def test_internal_errors_return_json(client, app, monkeypatch):
    import secureqr.views as views
    monkeypatch.setattr(views.db, "stats", lambda: 1 / 0)
    r = client.get("/api/stats")
    assert r.status_code == 500 and r.json["error"] == "internal_error"


def test_placeholder_secret_key_is_replaced(tmp_path, tiny_model_path):
    from secureqr import create_app
    app = create_app({"TESTING": True, "SECRET_KEY": "change-me", "DATABASE": str(tmp_path / "x.db"),
                      "MODEL_PATH": tiny_model_path, "LAZY_MODEL": True})
    assert app.config["SECRET_KEY"] not in ("", "change-me") and len(app.config["SECRET_KEY"]) == 64

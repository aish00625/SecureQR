"""HTML pages and JSON API routes."""
from __future__ import annotations

import json
from pathlib import Path

from flask import Blueprint, abort, current_app, jsonify, render_template, request

from . import db
from .core.analyzer import analyze_payload
from .core.content import clean_text
from .core.qr_decoder import ImageValidationError, backends, decode_qr, validate_image_bytes
from .security import client_ip, rate_limit

pages = Blueprint("pages", __name__)
api = Blueprint("api", __name__, url_prefix="/api")


def _predictor():
    return current_app.extensions["secureqr_predictor"]


def _log_scan(source: str, result: dict, scan_id: int) -> None:
    target = (result.get("url") or result.get("raw_content") or "")[:200]
    target = target.replace("\r", " ").replace("\n", " ")  # prevent log injection
    current_app.logger.info("scan id=%s source=%s ip=%s risk=%s type=%s target=%r",
                            scan_id, source, client_ip(), result["risk_level"],
                            result["content_type"], target)


def _model_metrics() -> dict:
    path = Path(current_app.config["METRICS_PATH"])
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


# ------------------------------------------------------------------ pages
@pages.get("/")
def landing():
    return render_template("landing.html", page="home", model=_predictor().info,
                           metrics=_model_metrics())


@pages.get("/scan")
def scan_page():
    return render_template("scan.html", page="scan",
                           max_mb=current_app.config["MAX_UPLOAD_MB"],
                           allowed=sorted(current_app.config["ALLOWED_EXTENSIONS"]))


@pages.get("/history")
def history_page():
    return render_template("history.html", page="history")


@pages.get("/history/<int:scan_id>")
def scan_detail_page(scan_id: int):
    scan = db.get_scan(scan_id)
    if scan is None:
        abort(404)
    return render_template("detail.html", page="history", scan=scan)


@pages.get("/analytics")
def analytics_page():
    return render_template("analytics.html", page="analytics", metrics=_model_metrics(),
                           model=_predictor().info)


@pages.get("/about")
def about_page():
    return render_template("about.html", page="about", metrics=_model_metrics(),
                           model=_predictor().info, backends=backends())


# -------------------------------------------------------------------- API
def _scan_image(source: str, fast: bool):
    file = request.files.get("file")
    if file is None:
        return jsonify(error="no_file", message="No file was uploaded (form field 'file')."), 400
    filename = file.filename or ("frame.jpg" if source == "webcam" else "")
    data = file.read(current_app.config["MAX_CONTENT_LENGTH"] + 1)
    cfg = current_app.config
    try:
        img = validate_image_bytes(data, filename, cfg["ALLOWED_EXTENSIONS"],
                                   cfg["MAX_CONTENT_LENGTH"], cfg["MAX_IMAGE_PIXELS"])
    except ImageValidationError as exc:
        current_app.logger.info("Rejected upload from %s: %s", client_ip(), exc)
        return jsonify(error="invalid_image", message=str(exc)), 400

    decoded = decode_qr(img, fast=fast)
    if not decoded.found:
        return jsonify(found=False, message="No QR code could be detected in the image. "
                       "Make sure the code is in focus, well lit and not cropped."), (200 if fast else 422)

    results = []
    for payload in decoded.payloads[:5]:
        result = analyze_payload(payload, _predictor())
        result["decoder"] = decoded.method
        scan_id = db.insert_scan(source, result)
        result["id"] = scan_id
        _log_scan(source, result, scan_id)
        results.append(result)
    return jsonify(found=True, count=len(results), results=results)


@api.post("/scan/image")
@rate_limit("scan", "RATE_LIMIT_SCAN")
def api_scan_image():
    return _scan_image("upload", fast=False)


@api.post("/scan/frame")
@rate_limit("frame", "RATE_LIMIT_FRAME")
def api_scan_frame():
    return _scan_image("webcam", fast=True)


@api.post("/scan/url")
@rate_limit("scan", "RATE_LIMIT_SCAN")
def api_scan_url():
    body = request.get_json(silent=True) or {}
    raw = body.get("url") if isinstance(body, dict) else None
    if not isinstance(raw, str):
        return jsonify(error="invalid_input", message="Provide a JSON body like {\"url\": \"https://...\"}."), 400
    text = clean_text(raw, max_len=current_app.config["MAX_URL_LENGTH"] + 1)
    if not text:
        return jsonify(error="invalid_input", message="URL must not be empty."), 400
    if len(text) > current_app.config["MAX_URL_LENGTH"]:
        return jsonify(error="invalid_input",
                       message=f"URL is too long (max {current_app.config['MAX_URL_LENGTH']} characters)."), 400
    if any(ch.isspace() for ch in text):
        return jsonify(error="invalid_input", message="A URL cannot contain spaces."), 400
    result = analyze_payload(text, _predictor())
    if result["content_type"] not in {"url", "dangerous_scheme"}:
        return jsonify(error="invalid_input",
                       message="That does not look like a URL (e.g. https://example.com)."), 400
    scan_id = db.insert_scan("url", result)
    result["id"] = scan_id
    _log_scan("url", result, scan_id)
    return jsonify(found=True, count=1, results=[result])


def _int_arg(name, default, lo, hi):
    try:
        return max(lo, min(hi, int(request.args.get(name, default))))
    except (TypeError, ValueError):
        return default


@api.get("/history")
@rate_limit("read")
def api_history():
    limit = _int_arg("limit", current_app.config["HISTORY_PAGE_SIZE"], 1, 100)
    offset = _int_arg("offset", 0, 0, 10_000_000)
    risk = (request.args.get("risk") or "").upper() or None
    q = clean_text(request.args.get("q") or "", max_len=200) or None
    items, total = db.list_scans(limit, offset, risk, q)
    return jsonify(items=items, total=total, limit=limit, offset=offset)


@api.get("/history/<int:scan_id>")
@rate_limit("read")
def api_history_item(scan_id: int):
    scan = db.get_scan(scan_id)
    if scan is None:
        return jsonify(error="not_found", message="Scan not found."), 404
    return jsonify(scan)


@api.delete("/history/<int:scan_id>")
@rate_limit("write")
def api_history_delete(scan_id: int):
    if not db.delete_scan(scan_id):
        return jsonify(error="not_found", message="Scan not found."), 404
    return jsonify(deleted=1)


@api.delete("/history")
@rate_limit("write")
def api_history_clear():
    n = db.clear_scans()
    current_app.logger.info("History cleared by %s (%d rows)", client_ip(), n)
    return jsonify(deleted=n)


@api.get("/stats")
@rate_limit("read")
def api_stats():
    return jsonify(db.stats())


@api.get("/health")
def api_health():
    info = _predictor().info
    return jsonify(status="ok", model_loaded=info["loaded"], model=info, decoders=backends())


@api.get("/model")
@rate_limit("read")
def api_model():
    m = _model_metrics()
    keys = ["model_version", "trained_at", "dataset", "split", "legacy_baseline", "chosen_model",
            "cross_validation", "test_metrics", "confusion_matrix", "domain_grouped_test_metrics",
            "model_comparison_validation"]
    return jsonify({k: m[k] for k in keys if k in m})

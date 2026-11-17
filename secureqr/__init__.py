"""SecureQR - Intelligent QR code security scanner (Flask application factory)."""
from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import HTTPException

from .config import Config, resolve_secret_key
from .core.predictor import Predictor
from .db import init_db
from .security import init_security

__version__ = "2.0.0"


def _configure_logging(app: Flask) -> None:
    level = getattr(logging, str(app.config.get("LOG_LEVEL", "INFO")).upper(), logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")
    root = logging.getLogger("secureqr")
    root.setLevel(level)
    app.logger.setLevel(level)
    if not app.config.get("TESTING"):
        log_dir = Path(app.config["LOG_DIR"])
        log_dir.mkdir(parents=True, exist_ok=True)
        fh = RotatingFileHandler(log_dir / "secureqr.log", maxBytes=1_000_000, backupCount=3,
                                 encoding="utf-8")
        fh.setFormatter(fmt)
        fh.setLevel(level)
        for lg in (app.logger, root):
            if not any(isinstance(h, RotatingFileHandler) for h in lg.handlers):
                lg.addHandler(fh)


def _register_errors(app: Flask) -> None:
    def wants_json() -> bool:
        return request.path.startswith("/api/")

    @app.errorhandler(HTTPException)
    def handle_http(exc: HTTPException):
        if exc.code == 413:
            msg = f"File is too large (max {app.config['MAX_UPLOAD_MB']} MB)."
        else:
            msg = exc.description or exc.name
        if wants_json():
            return jsonify(error=exc.name.lower().replace(" ", "_"), message=msg), exc.code
        return render_template("error.html", code=exc.code, title=exc.name, message=msg), exc.code

    @app.errorhandler(Exception)
    def handle_unexpected(exc: Exception):
        app.logger.exception("Unhandled error on %s %s", request.method, request.path)
        msg = "An internal error occurred. It has been logged."
        if wants_json():
            return jsonify(error="internal_error", message=msg), 500
        return render_template("error.html", code=500, title="Server error", message=msg), 500


def create_app(overrides: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)
    if overrides:
        app.config.update(overrides)
    app.config["MAX_CONTENT_LENGTH"] = app.config["MAX_UPLOAD_MB"] * 1024 * 1024

    _configure_logging(app)
    resolve_secret_key(app)
    init_security(app)
    init_db(app)

    predictor = Predictor(app.config["MODEL_PATH"])
    if not app.config.get("LAZY_MODEL"):
        predictor.load()
    app.extensions["secureqr_predictor"] = predictor

    from .views import api, pages
    app.register_blueprint(pages)
    app.register_blueprint(api)
    _register_errors(app)

    @app.context_processor
    def _globals():
        return {"app_version": __version__}

    return app

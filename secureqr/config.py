"""Application configuration, read from environment variables (.env supported)."""
from __future__ import annotations

import os
import secrets
from pathlib import Path

try:  # python-dotenv is optional
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover
    load_dotenv = None

BASE_DIR = Path(__file__).resolve().parent.parent

if load_dotenv is not None:
    load_dotenv(BASE_DIR / ".env")


def _bool(name: str, default: bool) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


class Config:
    # --- core ---------------------------------------------------------------
    SECRET_KEY = os.getenv("SECUREQR_SECRET_KEY") or ""
    DEBUG = _bool("SECUREQR_DEBUG", False)
    TESTING = False

    # --- paths --------------------------------------------------------------
    DATABASE = os.getenv("SECUREQR_DATABASE", str(BASE_DIR / "instance" / "secureqr.db"))
    MODEL_PATH = os.getenv("SECUREQR_MODEL_PATH", str(BASE_DIR / "model" / "secureqr_model.joblib"))
    METRICS_PATH = os.getenv("SECUREQR_METRICS_PATH", str(BASE_DIR / "model" / "metrics.json"))
    LOG_DIR = os.getenv("SECUREQR_LOG_DIR", str(BASE_DIR / "logs"))
    LOG_LEVEL = os.getenv("SECUREQR_LOG_LEVEL", "INFO")

    # --- uploads ------------------------------------------------------------
    MAX_UPLOAD_MB = _int("SECUREQR_MAX_UPLOAD_MB", 5)
    MAX_CONTENT_LENGTH = MAX_UPLOAD_MB * 1024 * 1024
    MAX_IMAGE_PIXELS = _int("SECUREQR_MAX_IMAGE_PIXELS", 40_000_000)
    ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp", "bmp"}
    MAX_URL_LENGTH = 2048

    # --- rate limiting (requests per window per client IP) -------------------
    RATE_LIMIT_ENABLED = _bool("SECUREQR_RATE_LIMIT_ENABLED", True)
    RATE_LIMIT_WINDOW = _int("SECUREQR_RATE_LIMIT_WINDOW", 60)
    RATE_LIMIT_SCAN = _int("SECUREQR_RATE_LIMIT_SCAN", 30)
    RATE_LIMIT_FRAME = _int("SECUREQR_RATE_LIMIT_FRAME", 150)
    RATE_LIMIT_DEFAULT = _int("SECUREQR_RATE_LIMIT_DEFAULT", 120)
    TRUST_PROXY = _bool("SECUREQR_TRUST_PROXY", False)

    # --- sessions / cookies ---------------------------------------------------
    SESSION_COOKIE_NAME = "secureqr_session"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = _bool("SECUREQR_COOKIE_SECURE", False)  # True behind HTTPS
    PERMANENT_SESSION_LIFETIME = 60 * 60 * 8

    HISTORY_PAGE_SIZE = 25


def resolve_secret_key(app) -> None:
    """Use the configured secret or fall back to an ephemeral random one."""
    if app.config.get("SECRET_KEY") in (None, "", "change-me"):
        app.config["SECRET_KEY"] = secrets.token_hex(32)
        app.logger.warning(
            "SECUREQR_SECRET_KEY is not set - using a random per-process key. "
            "Sessions will reset on restart. Set it in .env for production.")

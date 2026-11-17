"""CSRF protection, rate limiting, security headers and safe client IP."""
from __future__ import annotations

import hmac
import secrets
import threading
import time
from collections import defaultdict, deque
from functools import wraps

from flask import abort, current_app, jsonify, request, session

CSRF_SESSION_KEY = "_csrf_token"
CSRF_HEADER = "X-CSRF-Token"
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


# ---------------------------------------------------------------- CSRF
def get_csrf_token() -> str:
    token = session.get(CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        session[CSRF_SESSION_KEY] = token
    return token


def verify_csrf() -> None:
    """Synchroniser-token check for every state-changing request."""
    if request.method not in UNSAFE_METHODS:
        return
    if current_app.config.get("CSRF_DISABLED"):
        return
    expected = session.get(CSRF_SESSION_KEY)
    sent = request.headers.get(CSRF_HEADER) or request.form.get("csrf_token")
    if not expected or not sent or not hmac.compare_digest(str(expected), str(sent)):
        current_app.logger.warning("CSRF validation failed for %s %s from %s",
                                   request.method, request.path, client_ip())
        abort(400, description="Missing or invalid CSRF token. Reload the page and try again.")


# ------------------------------------------------------------ client IP
def client_ip() -> str:
    # Only trust X-Forwarded-For when explicitly configured (behind a proxy);
    # otherwise attackers could spoof it to bypass rate limiting.
    if current_app.config.get("TRUST_PROXY"):
        fwd = request.headers.get("X-Forwarded-For", "")
        if fwd:
            return fwd.split(",")[0].strip()
    return request.remote_addr or "unknown"


# ---------------------------------------------------------- rate limit
class SlidingWindowLimiter:
    """In-memory sliding-window limiter (per process). Suitable for a single
    instance; use Redis-backed limiting when scaling horizontally."""

    def __init__(self):
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def hit(self, key: str, limit: int, window: int) -> tuple[bool, int]:
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and q[0] <= now - window:
                q.popleft()
            if len(q) >= limit:
                return False, max(1, int(window - (now - q[0])) + 1)
            q.append(now)
            return True, 0

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


limiter = SlidingWindowLimiter()


def rate_limit(bucket: str, config_key: str = "RATE_LIMIT_DEFAULT"):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            cfg = current_app.config
            if cfg.get("RATE_LIMIT_ENABLED", True):
                ok, retry = limiter.hit(f"{bucket}:{client_ip()}", cfg[config_key], cfg["RATE_LIMIT_WINDOW"])
                if not ok:
                    current_app.logger.warning("Rate limit hit: bucket=%s ip=%s", bucket, client_ip())
                    resp = jsonify(error="rate_limited",
                                   message=f"Too many requests. Try again in {retry} s.")
                    resp.status_code = 429
                    resp.headers["Retry-After"] = str(retry)
                    return resp
            return fn(*args, **kwargs)
        return wrapper
    return decorator


# ------------------------------------------------------ security headers
CSP = ("default-src 'self'; "
       "script-src 'self'; "
       "style-src 'self' https://fonts.googleapis.com; "
       "font-src 'self' https://fonts.gstatic.com; "
       "img-src 'self' data: blob:; "
       "media-src 'self' blob:; "
       "connect-src 'self'; "
       "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'")


def apply_security_headers(resp):
    resp.headers.setdefault("Content-Security-Policy", CSP)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("Permissions-Policy", "camera=(self), microphone=(), geolocation=()")
    resp.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    if request.path.startswith("/api/"):
        resp.headers.setdefault("Cache-Control", "no-store")
    if current_app.config.get("SESSION_COOKIE_SECURE"):
        resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return resp


def init_security(app) -> None:
    app.before_request(verify_csrf)
    app.after_request(apply_security_headers)

    @app.context_processor
    def _inject():
        return {"csrf_token": get_csrf_token}

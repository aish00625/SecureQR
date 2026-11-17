"""Pre-demo health check: Python version, packages, model, decoder, database.

    python scripts/check_setup.py
Exit code 0 = ready, 1 = something needs attention.
"""
from __future__ import annotations

import importlib
import sys
from importlib import metadata
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

OK, BAD = "[ OK ]", "[FAIL]"
problems = 0


def check(label: str, ok: bool, detail: str = "") -> None:
    global problems
    print(f"{OK if ok else BAD} {label}" + (f" - {detail}" if detail else ""))
    problems += 0 if ok else 1


v = sys.version_info
check(f"Python {v.major}.{v.minor}.{v.micro}", (3, 11) <= (v.major, v.minor) <= (3, 14),
      "" if (3, 11) <= (v.major, v.minor) <= (3, 14) else "use Python 3.11 - 3.14")

for mod, dist in [("flask", "Flask"), ("numpy", "numpy"), ("pandas", "pandas"), ("sklearn", "scikit-learn"),
                  ("joblib", "joblib"), ("cv2", "opencv-python"), ("PIL", "Pillow"), ("dotenv", "python-dotenv"),
                  ("pytest", "pytest")]:
    try:
        importlib.import_module(mod)
        try:
            ver = metadata.version(dist)
        except metadata.PackageNotFoundError:
            ver = ""
        if mod == "sklearn" and ver != "1.9.1":
            check(f"{dist} {ver}", False, "the shipped model was saved with 1.9.1; run: pip install -r requirements.txt "
                                          "(or retrain: python -m secureqr.ml.train)")
        else:
            check(f"{dist} {ver}".strip(), True)
    except Exception as exc:  # noqa: BLE001
        check(dist, False, f"not importable ({exc.__class__.__name__}); run: pip install -r requirements.txt")

try:
    from secureqr.config import Config
    from secureqr.core.predictor import Predictor
    p = Predictor(Config.MODEL_PATH)
    if p.available:
        prob = p.predict("http://paypal.com.account-verify.example.xyz/webscr?cmd=_login")["phishing_probability"]
        check("ML model loads and predicts", True, f"v{p.info['version']}, demo phishing URL -> {prob:.0%}")
    else:
        check("ML model loads", False, p.error or "")
except Exception as exc:  # noqa: BLE001
    check("ML model", False, repr(exc))

try:
    import cv2
    from secureqr.core.qr_decoder import backends, decode_qr
    demo = ROOT / "demo_qr" / "01_safe_wikipedia.png"
    img = cv2.imread(str(demo))
    res = decode_qr(img) if img is not None else None
    check("QR decoder", bool(res and res.found), f"backends: {', '.join(backends())}")
except Exception as exc:  # noqa: BLE001
    check("QR decoder", False, repr(exc))

try:
    from secureqr import create_app
    app = create_app({"TESTING": True, "DATABASE": ":memory:", "LAZY_MODEL": True})
    r = app.test_client().get("/api/health")
    check("Flask app starts", r.status_code == 200)
except Exception as exc:  # noqa: BLE001
    check("Flask app starts", False, repr(exc))

if (ROOT / ".env").exists():
    print(f"{OK} .env present")
else:
    print("[INFO] no .env file - optional: copy .env.example .env and set SECUREQR_SECRET_KEY")

print("\nReady for the demo." if problems == 0 else f"\n{problems} item(s) need attention.")
sys.exit(0 if problems == 0 else 1)

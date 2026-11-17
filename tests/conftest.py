"""Shared pytest fixtures.

A small model is trained once per test session on a sample of the real
dataset, so the suite does not depend on the large production model file
and still exercises the exact training/inference pipeline.
"""
from __future__ import annotations

import io
from pathlib import Path

import cv2
import joblib
import numpy as np
import pandas as pd
import pytest
from sklearn.calibration import CalibratedClassifierCV
from sklearn.pipeline import Pipeline

from secureqr import create_app
from secureqr.ml.pipeline import build_pipeline
from secureqr.security import limiter

ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "dataset" / "phishing_site_urls.csv"


def make_qr(text: str, scale: int = 8, border: int = 4, color=(0, 0, 0), fmt: str = ".png") -> bytes:
    """Encode ``text`` as a QR code image using OpenCV's built-in encoder."""
    enc = cv2.QRCodeEncoder.create()
    qr = enc.encode(text)  # uint8, 0 = dark module
    qr = cv2.resize(qr, None, fx=scale, fy=scale, interpolation=cv2.INTER_NEAREST)
    qr = cv2.copyMakeBorder(qr, border * scale, border * scale, border * scale, border * scale,
                            cv2.BORDER_CONSTANT, value=255)
    img = cv2.cvtColor(qr, cv2.COLOR_GRAY2BGR)
    if color != (0, 0, 0):
        img[qr == 0] = color
    ok, buf = cv2.imencode(fmt, img)
    assert ok
    return buf.tobytes()


@pytest.fixture(scope="session")
def qr_png():
    return make_qr


@pytest.fixture(scope="session")
def tiny_model_path(tmp_path_factory) -> str:
    df = pd.read_csv(DATASET).drop_duplicates("URL")
    df = pd.concat([df[df["Label"] == lab].sample(4000, random_state=1) for lab in ("good", "bad")])
    X, y = df["URL"].values, (df["Label"] == "bad").astype(int).values
    base = build_pipeline("combined_svm", 1.0)
    pipe = Pipeline([("canon", base.named_steps["canon"]), ("features", base.named_steps["features"]),
                     ("clf", CalibratedClassifierCV(base.named_steps["clf"], cv=3, ensemble=False))])
    pipe.fit(X, y)
    path = tmp_path_factory.mktemp("model") / "tiny.joblib"
    joblib.dump({"pipeline": pipe, "version": "test", "kind": "combined_svm", "threshold": 0.5,
                 "test_metrics": {}}, path)
    return str(path)


@pytest.fixture()
def app(tmp_path, tiny_model_path):
    limiter.reset()
    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "test-secret",
        "DATABASE": str(tmp_path / "test.db"),
        "MODEL_PATH": tiny_model_path,
        "METRICS_PATH": str(tmp_path / "missing-metrics.json"),
        "LOG_DIR": str(tmp_path / "logs"),
    })
    yield app
    limiter.reset()


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def csrf(client):
    """Load a page so the session gets a CSRF token, then return it."""
    client.get("/scan")
    with client.session_transaction() as sess:
        return sess["_csrf_token"]


def upload(client, csrf, data: bytes, name: str = "qr.png", endpoint="/api/scan/image"):
    return client.post(endpoint, data={"file": (io.BytesIO(data), name)},
                       headers={"X-CSRF-Token": csrf}, content_type="multipart/form-data")


def blank_png(w=400, h=300) -> bytes:
    ok, buf = cv2.imencode(".png", np.full((h, w, 3), 255, np.uint8))
    return buf.tobytes()

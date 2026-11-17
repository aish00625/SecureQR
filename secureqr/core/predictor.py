"""Loads the trained model once and serves predictions."""
from __future__ import annotations

import logging
import threading
from pathlib import Path

import joblib

log = logging.getLogger(__name__)

MODEL_NAMES = {
    "combined_svm": "Linear SVM (char n-grams + lexical features)",
    "char_svm": "Linear SVM (char n-grams)",
    "lexical_svm": "Linear SVM (lexical features)",
    "combined_logreg": "Logistic Regression",
    "lexical_hgb": "Gradient Boosting",
}


class Predictor:
    """Thread-safe, lazily loaded wrapper around the saved sklearn pipeline."""

    def __init__(self, model_path: str):
        self.model_path = Path(model_path)
        self._lock = threading.Lock()
        self._artefact = None
        self.error: str | None = None

    def load(self) -> bool:
        with self._lock:
            if self._artefact is not None:
                return True
            if not self.model_path.exists():
                self.error = (f"Model file not found at {self.model_path}. "
                              "Train it with: python -m secureqr.ml.train")
                log.error(self.error)
                return False
            try:
                art = joblib.load(self.model_path)
                if not isinstance(art, dict) or "pipeline" not in art:
                    raise ValueError("unexpected model file format")
                # Smoke test so incompatible pickles fail at start-up, not mid-request.
                art["pipeline"].predict_proba(["example.com"])
                self._artefact = art
                self.error = None
                log.info("Loaded model v%s (%s) from %s", art.get("version"), art.get("kind"), self.model_path)
                return True
            except Exception as exc:  # incompatible sklearn version, corrupt file...
                self.error = (f"Could not load model ({type(exc).__name__}: {exc}). "
                              "Re-train it with: python -m secureqr.ml.train")
                log.exception("Model load failed")
                return False

    @property
    def available(self) -> bool:
        return self._artefact is not None or self.load()

    @property
    def info(self) -> dict:
        if not self.available:
            return {"loaded": False, "error": self.error}
        a = self._artefact
        return {"loaded": True, "version": a.get("version"), "kind": a.get("kind"),
                "trained_at": a.get("trained_at"), "threshold": a.get("threshold", 0.5),
                "test_metrics": a.get("test_metrics", {})}

    def predict(self, url: str) -> dict:
        if not self.available:
            return {"available": False, "error": self.error}
        a = self._artefact
        proba = float(a["pipeline"].predict_proba([url])[0, 1])
        threshold = float(a.get("threshold", 0.5))
        return {
            "available": True,
            "label": "PHISHING" if proba >= threshold else "LEGITIMATE",
            "phishing_probability": round(proba, 4),
            "confidence": round(max(proba, 1 - proba), 4),
            "threshold": threshold,
            "model": f"{MODEL_NAMES.get(a.get('kind'), a.get('kind'))} v{a.get('version')}",
        }

from pathlib import Path

import joblib
import pandas as pd
import pytest

from secureqr.core.predictor import Predictor
from tests.conftest import DATASET, ROOT

PROD_MODEL = ROOT / "model" / "secureqr_model.joblib"


def test_predictor_loads_and_predicts(tiny_model_path):
    p = Predictor(tiny_model_path)
    assert p.available
    r = p.predict("https://example.com/")
    assert r["available"] is True
    assert 0.0 <= r["phishing_probability"] <= 1.0
    assert r["label"] in {"PHISHING", "LEGITIMATE"}
    assert r["label"] == ("PHISHING" if r["phishing_probability"] >= 0.5 else "LEGITIMATE")


def test_obvious_phishing_scores_higher_than_obvious_legit(tiny_model_path):
    p = Predictor(tiny_model_path)
    bad = p.predict("http://paypal.com.account-verify.xyz/webscr/cmd=_login-submit.php")["phishing_probability"]
    good = p.predict("https://en.wikipedia.org/wiki/Computer_security")["phishing_probability"]
    assert bad > 0.5 > good


def test_training_and_inference_use_same_pipeline(tiny_model_path):
    """The saved artefact contains canonicalisation + features + classifier,
    so raw and pre-canonicalised inputs must give identical scores."""
    pipe = joblib.load(tiny_model_path)["pipeline"]
    assert [n for n, _ in pipe.steps] == ["canon", "features", "clf"]
    a = pipe.predict_proba(["https://Example.com/Login"])[0, 1]
    b = pipe.predict_proba(["example.com/Login"])[0, 1]
    assert a == pytest.approx(b)


def test_missing_model_degrades_gracefully(tmp_path):
    p = Predictor(str(tmp_path / "nope.joblib"))
    assert not p.available
    r = p.predict("https://example.com")
    assert r["available"] is False and "Train it" in r["error"]


def test_corrupt_model_degrades_gracefully(tmp_path):
    bad = tmp_path / "bad.joblib"
    bad.write_bytes(b"not a pickle")
    p = Predictor(str(bad))
    assert not p.available and "Re-train" in p.info["error"]


@pytest.mark.skipif(not PROD_MODEL.exists(), reason="production model not trained")
def test_production_model_quality_on_sample():
    """Sanity check of the shipped model on a random sample of the dataset
    (overlaps training data, so this is a smoke test, not an evaluation)."""
    art = joblib.load(PROD_MODEL)
    df = pd.read_csv(DATASET).drop_duplicates("URL").sample(3000, random_state=7)
    pred = art["pipeline"].predict(df["URL"].values)
    acc = (pred == (df["Label"] == "bad").astype(int).values).mean()
    assert acc > 0.95
    assert Path(ROOT / "model" / "metrics.json").exists()

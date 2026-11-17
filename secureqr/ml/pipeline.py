"""Model pipeline definitions (shared by training and evaluation).

Every pipeline starts with :class:`Canonicalizer` and accepts *raw URL
strings*, so the saved artefact contains the full preprocessing chain and
inference can never drift from training.
"""
from __future__ import annotations

from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.feature_extraction.text import HashingVectorizer, TfidfTransformer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import LinearSVC

from .features import Canonicalizer, LexicalFeatures

# 2**19 hashed character n-gram buckets keeps the saved model small while
# leaving collisions rare for URL-length strings. Hashing (instead of a
# fitted vocabulary) also means the model file does not store 500k n-grams.
N_HASH_FEATURES = 2 ** 19

# The 30 dense lexical features are standard-scaled (unit variance) while each
# TF-IDF row is L2-normalised (unit length). Without down-weighting, the dense
# block dominates the margin and LinearSVC converges very slowly; 0.1 was
# chosen on a validation split (see MODEL_EVALUATION.md).
LEXICAL_WEIGHT = 0.1


def char_ngram_block() -> Pipeline:
    return Pipeline([
        ("hash", HashingVectorizer(
            analyzer="char", ngram_range=(3, 5), n_features=N_HASH_FEATURES,
            alternate_sign=False, lowercase=True, norm=None, dtype=float,
        )),
        ("tfidf", TfidfTransformer(sublinear_tf=True)),
    ])


def lexical_block() -> Pipeline:
    return Pipeline([
        ("lex", LexicalFeatures()),
        ("scale", StandardScaler()),
    ])


def combined_features() -> FeatureUnion:
    return FeatureUnion(
        [("chars", char_ngram_block()), ("lexical", lexical_block())],
        transformer_weights={"chars": 1.0, "lexical": LEXICAL_WEIGHT},
    )


def build_features(kind: str):
    if kind.startswith("lexical"):
        return lexical_block()
    if kind.startswith("char"):
        return char_ngram_block()
    return combined_features()


def build_classifier(kind: str, C: float = 0.5):
    if kind == "lexical_svm":
        # 30 dense features, many samples -> primal formulation converges fastest
        return LinearSVC(C=C, dual=False, max_iter=5000)
    if kind.endswith("_svm"):
        # ~500k sparse features -> dual formulation
        return LinearSVC(C=C, dual=True, max_iter=5000)
    if kind.endswith("_logreg"):
        return LogisticRegression(C=C * 20, max_iter=2000, solver="liblinear")
    if kind.endswith("_hgb"):
        return HistGradientBoostingClassifier(max_iter=300, random_state=42)
    raise ValueError(f"unknown classifier kind: {kind}")


def build_pipeline(kind: str = "combined_svm", C: float = 0.5) -> Pipeline:
    """Return an *unfitted* pipeline that accepts raw URL strings.

    kind: lexical_svm | lexical_hgb | char_svm | combined_svm | combined_logreg
    """
    return Pipeline([
        ("canon", Canonicalizer()),
        ("features", build_features(kind)),
        ("clf", build_classifier(kind, C)),
    ])

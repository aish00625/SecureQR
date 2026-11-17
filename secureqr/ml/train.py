"""Train and evaluate the SecureQR phishing-URL model.

Usage (from the project root):

    python -m secureqr.ml.train                 # full run (~10-20 min on a laptop)
    python -m secureqr.ml.train --quick         # 60k-row smoke run (~1 min)

Outputs (in ./model):
    secureqr_model.joblib   fitted, calibrated pipeline + metadata
    metrics.json            every number reported in MODEL_EVALUATION.md
    confusion_matrix.png    test-set confusion matrix
    evaluation_report.md    human-readable report generated from metrics.json
"""
from __future__ import annotations

import argparse
import json
import platform
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (accuracy_score, classification_report, confusion_matrix,
                             f1_score, precision_score, recall_score, roc_auc_score)
from sklearn.model_selection import (GroupShuffleSplit, StratifiedKFold, cross_validate,
                                     train_test_split)
from sklearn.pipeline import Pipeline
from sklearn.svm import LinearSVC

from .features import canonicalize_url, legacy_features, split_host
from .pipeline import build_features, build_pipeline

ROOT = Path(__file__).resolve().parents[2]
DATASET = ROOT / "dataset" / "phishing_site_urls.csv"
MODEL_DIR = ROOT / "model"
MODEL_VERSION = "2.0.0"
SEED = 42

_SECOND_LEVEL = {"co", "com", "net", "org", "ac", "gov", "edu", "nic", "or", "ne", "go"}


def registered_domain(url: str) -> str:
    """Cheap eTLD+1 approximation used only to build domain-grouped splits."""
    host, _, _ = split_host(canonicalize_url(url))
    labels = [p for p in host.split(".") if p]
    if len(labels) >= 3 and labels[-2] in _SECOND_LEVEL and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:]) if labels else host


def metrics_for(y_true, y_pred, scores=None) -> dict:
    out = {
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
    }
    if scores is not None:
        out["roc_auc"] = roc_auc_score(y_true, scores)
    return {k: round(float(v), 4) for k, v in out.items()}


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def load_dataset(path: Path, limit: int | None):
    raw = pd.read_csv(path)
    raw = raw.dropna(subset=["URL", "Label"])
    stats = {"rows_raw": int(len(raw)),
             "label_counts_raw": raw["Label"].value_counts().to_dict()}
    dedup = raw.drop_duplicates(subset="URL").reset_index(drop=True)
    stats["rows_deduplicated"] = int(len(dedup))
    stats["duplicates_removed"] = int(len(raw) - len(dedup))
    stats["label_counts_deduplicated"] = dedup["Label"].value_counts().to_dict()
    if limit:
        dedup = dedup.sample(n=min(limit, len(dedup)), random_state=SEED).reset_index(drop=True)
        stats["subsampled_to"] = int(len(dedup))
    return raw, dedup, stats


def legacy_baseline(raw: pd.DataFrame) -> dict:
    """Reproduce the ORIGINAL SecureQR experiment (6 features, LinearSVC,
    duplicates kept, unstratified 80/20 split, random_state=42)."""
    X = np.array([legacy_features(u) for u in raw["URL"]], dtype=float)
    y = raw["Label"].map({"good": 0, "bad": 1}).values
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, random_state=42)
    clf = LinearSVC(dual="auto", max_iter=5000).fit(Xtr, ytr)
    pred = clf.predict(Xte)
    res = metrics_for(yte, pred)
    res["confusion_matrix"] = confusion_matrix(yte, pred).tolist()
    return res


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--quick", action="store_true", help="60k-row smoke run")
    ap.add_argument("--limit", type=int, default=None, help="subsample N unique URLs")
    ap.add_argument("--cv-folds", type=int, default=5)
    ap.add_argument("--skip-baseline", action="store_true")
    ap.add_argument("--skip-comparison", action="store_true")
    ap.add_argument("--out", type=Path, default=MODEL_DIR)
    args = ap.parse_args(argv)
    limit = 60_000 if args.quick else args.limit
    if args.quick:
        args.cv_folds = min(args.cv_folds, 3)

    t0 = time.time()
    args.out.mkdir(parents=True, exist_ok=True)
    report: dict = {"model_version": MODEL_VERSION,
                    "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    "environment": {"python": platform.python_version(),
                                    "sklearn": sklearn.__version__},
                    "random_seed": SEED, "quick_run": bool(limit)}

    log(f"Loading {DATASET.name} ...")
    raw, df, report["dataset"] = load_dataset(DATASET, limit)
    log(f"  {report['dataset']}")

    # ---------------------------------------------------------------- baseline
    if not args.skip_baseline:
        log("Reproducing original 6-feature LinearSVC baseline ...")
        base_raw = raw if not limit else raw.sample(n=min(limit, len(raw)), random_state=SEED)
        report["legacy_baseline"] = legacy_baseline(base_raw)
        log(f"  legacy baseline: {report['legacy_baseline']}")

    X = df["URL"].astype(str).values
    y = df["Label"].map({"good": 0, "bad": 1}).values

    # --------------------------------------------------------- held-out test
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=SEED)
    report["split"] = {"train": int(len(X_train)), "test": int(len(X_test)),
                       "strategy": "stratified 80/20 after de-duplication"}

    # ----------------------------------------------- model comparison (val)
    candidates = [("lexical_svm", 1.0), ("lexical_hgb", None), ("char_svm", 1.0),
                  ("combined_svm", 0.5), ("combined_svm", 1.0), ("combined_logreg", 0.5)]
    chosen_kind, chosen_C = "combined_svm", 0.5
    if not args.skip_comparison:
        X_tr, X_val, y_tr, y_val = train_test_split(
            X_train, y_train, test_size=0.2, stratify=y_train, random_state=SEED)
        comp = []
        for kind, C in candidates:
            t = time.time()
            pipe = build_pipeline(kind, C or 1.0).fit(X_tr, y_tr)
            pred = pipe.predict(X_val)
            row = {"model": kind, "C": C, **metrics_for(y_val, pred),
                   "fit_seconds": round(time.time() - t, 1)}
            comp.append(row)
            log(f"  {row}")
        report["model_comparison_validation"] = comp
        best = max(comp, key=lambda r: r["f1"])
        chosen_kind, chosen_C = best["model"], best["C"]
    report["chosen_model"] = {"kind": chosen_kind, "C": chosen_C,
                              "selection_metric": "validation F1 (phishing class)"}
    log(f"Chosen: {chosen_kind} C={chosen_C}")

    # ------------------------------------------------------ cross-validation
    if args.cv_folds and args.cv_folds > 1:
        log(f"{args.cv_folds}-fold stratified CV on training set ...")
        cv = StratifiedKFold(n_splits=args.cv_folds, shuffle=True, random_state=SEED)
        res = cross_validate(build_pipeline(chosen_kind, chosen_C or 1.0), X_train, y_train, cv=cv,
                             scoring=["accuracy", "precision", "recall", "f1"], n_jobs=1)
        report["cross_validation"] = {
            "folds": args.cv_folds,
            **{m: {"mean": round(float(res[f"test_{m}"].mean()), 4),
                   "std": round(float(res[f"test_{m}"].std()), 4)}
               for m in ["accuracy", "precision", "recall", "f1"]}}
        log(f"  {report['cross_validation']}")

    # ------------------------------------------- final (calibrated) model
    log("Fitting final calibrated model on full training split ...")
    base = build_pipeline(chosen_kind, chosen_C or 1.0)
    clf = base.named_steps["clf"]
    final = Pipeline([
        ("canon", base.named_steps["canon"]),
        ("features", base.named_steps["features"]),
        ("clf", CalibratedClassifierCV(clf, cv=3, method="sigmoid", ensemble=False)),
    ])
    final.fit(X_train, y_train)
    proba = final.predict_proba(X_test)[:, 1]
    pred = (proba >= 0.5).astype(int)
    report["test_metrics"] = metrics_for(y_test, pred, proba)
    cm = confusion_matrix(y_test, pred)
    report["confusion_matrix"] = {"labels": ["legitimate", "phishing"], "matrix": cm.tolist(),
                                  "tn": int(cm[0, 0]), "fp": int(cm[0, 1]),
                                  "fn": int(cm[1, 0]), "tp": int(cm[1, 1])}
    report["classification_report"] = classification_report(
        y_test, pred, target_names=["legitimate", "phishing"], output_dict=True, digits=4)
    log(f"  TEST: {report['test_metrics']}  CM={cm.tolist()}")

    # ------------------------------------------- domain-grouped evaluation
    log("Domain-grouped evaluation (no registered domain shared between train/test) ...")
    groups = np.array([registered_domain(u) for u in X])
    gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=SEED)
    gi_tr, gi_te = next(gss.split(X, y, groups))
    gpipe = build_pipeline(chosen_kind, chosen_C or 1.0).fit(X[gi_tr], y[gi_tr])
    gpred = gpipe.predict(X[gi_te])
    report["domain_grouped_test_metrics"] = {
        **metrics_for(y[gi_te], gpred), "train": int(len(gi_tr)), "test": int(len(gi_te)),
        "unique_domains": int(len(set(groups)))}
    log(f"  {report['domain_grouped_test_metrics']}")

    # ----------------------------------------------- sanity spot-checks
    spot = ["https://www.google.com/", "https://github.com/aish00625/SecureQR",
            "https://www.amazon.in/", "https://en.wikipedia.org/wiki/QR_code",
            "https://www.nie.ac.in/", "https://www.sbi.co.in/",
            "http://paypal.com.account-verify-login.xyz/webscr?cmd=_login",
            "http://192.168.10.5/secure/bank/login.php",
            "http://free-gift-card-winner.top/claim-now.html",
            "https://bit.ly/3xYzAbC"]
    sp = final.predict_proba(spot)[:, 1]
    report["spot_checks"] = [{"url": u, "phishing_probability": round(float(p), 4)}
                             for u, p in zip(spot, sp)]
    for r in report["spot_checks"]:
        log(f"  spot {r['phishing_probability']:.3f}  {r['url']}")

    # -------------------------------------------------------------- save
    artefact = {"pipeline": final, "version": MODEL_VERSION, "kind": chosen_kind,
                "C": chosen_C, "threshold": 0.5, "trained_at": report["trained_at"],
                "test_metrics": report["test_metrics"], "sklearn_version": sklearn.__version__}
    model_path = args.out / "secureqr_model.joblib"
    joblib.dump(artefact, model_path, compress=3)
    report["model_file_mb"] = round(model_path.stat().st_size / 1e6, 2)
    report["total_seconds"] = round(time.time() - t0, 1)
    (args.out / "metrics.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    _plot_confusion(cm, args.out / "confusion_matrix.png")
    (args.out / "evaluation_report.md").write_text(render_report(report), encoding="utf-8")
    log(f"Saved {model_path} ({report['model_file_mb']} MB) in {report['total_seconds']} s")
    return report


def _plot_confusion(cm, path: Path) -> None:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:  # matplotlib is optional
        return
    fig, ax = plt.subplots(figsize=(5, 4.2), dpi=120)
    fig.patch.set_facecolor("#0b1324")
    ax.set_facecolor("#0b1324")
    ax.imshow(cm, cmap="Blues")
    labels = ["Legitimate", "Phishing"]
    ax.set_xticks([0, 1], labels, color="#cbd5e1")
    ax.set_yticks([0, 1], labels, color="#cbd5e1")
    ax.set_xlabel("Predicted", color="#cbd5e1")
    ax.set_ylabel("Actual", color="#cbd5e1")
    ax.set_title("SecureQR – test-set confusion matrix", color="#e2e8f0", fontsize=10)
    vmax = cm.max()
    for i in range(2):
        for j in range(2):
            ax.text(j, i, f"{cm[i, j]:,}", ha="center", va="center", fontsize=12,
                    color="#0b1324" if cm[i, j] > vmax * 0.5 else "#e2e8f0")
    for s in ax.spines.values():
        s.set_visible(False)
    fig.tight_layout()
    fig.savefig(path, facecolor=fig.get_facecolor())
    plt.close(fig)


def render_report(r: dict) -> str:
    L = ["# SecureQR model evaluation (auto-generated)", "",
         f"Generated: {r['trained_at']} · model v{r['model_version']} · "
         f"Python {r['environment']['python']} · scikit-learn {r['environment']['sklearn']}", ""]
    d = r["dataset"]
    L += ["## Dataset", "", f"- Raw rows: {d['rows_raw']:,} ({d['label_counts_raw']})",
          f"- After removing duplicate URLs: {d['rows_deduplicated']:,} "
          f"({d['duplicates_removed']:,} duplicates removed)",
          f"- Split: {r['split']['train']:,} train / {r['split']['test']:,} test ({r['split']['strategy']})", ""]
    if "legacy_baseline" in r:
        b = r["legacy_baseline"]
        L += ["## Original model (reproduced)", "",
              f"6 features + LinearSVC, duplicates kept: accuracy **{b['accuracy']:.2%}**, "
              f"precision {b['precision']:.2%}, recall {b['recall']:.2%}, F1 {b['f1']:.2%}", ""]
    if "model_comparison_validation" in r:
        L += ["## Model comparison (validation split)", "",
              "| Model | C | Accuracy | Precision | Recall | F1 | Fit (s) |", "|---|---|---|---|---|---|---|"]
        for c in r["model_comparison_validation"]:
            L.append(f"| {c['model']} | {c['C'] if c['C'] is not None else '-'} | {c['accuracy']:.4f} | "
                     f"{c['precision']:.4f} | {c['recall']:.4f} | {c['f1']:.4f} | {c['fit_seconds']} |")
        L.append("")
    L += [f"Chosen: **{r['chosen_model']['kind']}** (C={r['chosen_model']['C']}), by {r['chosen_model']['selection_metric']}.", ""]
    if "cross_validation" in r:
        cv = r["cross_validation"]
        L += [f"## {cv['folds']}-fold cross-validation (training split)", "",
              "| Metric | Mean | Std |", "|---|---|---|"]
        for m in ["accuracy", "precision", "recall", "f1"]:
            L.append(f"| {m} | {cv[m]['mean']:.4f} | {cv[m]['std']:.4f} |")
        L.append("")
    t = r["test_metrics"]
    cm = r["confusion_matrix"]
    L += ["## Held-out test set (calibrated final model, threshold 0.5)", "",
          "| Accuracy | Precision | Recall | F1 | ROC-AUC |", "|---|---|---|---|---|",
          f"| {t['accuracy']:.4f} | {t['precision']:.4f} | {t['recall']:.4f} | {t['f1']:.4f} | {t['roc_auc']:.4f} |", "",
          "Confusion matrix (rows = actual, cols = predicted):", "",
          "| | Pred. legitimate | Pred. phishing |", "|---|---|---|",
          f"| **Legitimate** | {cm['tn']:,} | {cm['fp']:,} |",
          f"| **Phishing** | {cm['fn']:,} | {cm['tp']:,} |", ""]
    g = r["domain_grouped_test_metrics"]
    L += ["## Domain-grouped split (harder, more realistic)", "",
          f"No registered domain appears in both train and test: accuracy {g['accuracy']:.4f}, "
          f"precision {g['precision']:.4f}, recall {g['recall']:.4f}, F1 {g['f1']:.4f}.", ""]
    L += ["## Spot checks", "", "| Phishing probability | URL |", "|---|---|"]
    for s in r["spot_checks"]:
        L.append(f"| {s['phishing_probability']:.3f} | `{s['url']}` |")
    L.append("")
    return "\n".join(L)


if __name__ == "__main__":
    main()

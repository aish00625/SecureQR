# SecureQR model evaluation (auto-generated)

Generated: 2026-11-17T14:26:17+00:00 · model v2.0.0 · Python 3.13.18 · scikit-learn 1.9.1

## Dataset

- Raw rows: 549,346 ({'good': 392924, 'bad': 156422})
- After removing duplicate URLs: 507,195 (42,151 duplicates removed)
- Split: 405,756 train / 101,439 test (stratified 80/20 after de-duplication)

## Original model (reproduced)

6 features + LinearSVC, duplicates kept: accuracy **77.53%**, precision 83.18%, recall 26.18%, F1 39.82%

## Model comparison (validation split)

| Model | C | Accuracy | Precision | Recall | F1 | Fit (s) |
|---|---|---|---|---|---|---|
| lexical_svm | 1.0 | 0.8801 | 0.8452 | 0.5728 | 0.6828 | 14.0 |
| lexical_hgb | - | 0.9396 | 0.9121 | 0.8100 | 0.8580 | 19.2 |
| char_svm | 1.0 | 0.9818 | 0.9790 | 0.9395 | 0.9588 | 21.9 |
| combined_svm | 0.5 | 0.9831 | 0.9817 | 0.9425 | 0.9617 | 68.3 |
| combined_svm | 1.0 | 0.9842 | 0.9817 | 0.9477 | 0.9644 | 80.5 |
| combined_logreg | 0.5 | 0.9819 | 0.9792 | 0.9399 | 0.9591 | 154.6 |

Chosen: **combined_svm** (C=1.0), by validation F1 (phishing class).

## 5-fold cross-validation (training split)

| Metric | Mean | Std |
|---|---|---|
| accuracy | 0.9839 | 0.0003 |
| precision | 0.9805 | 0.0012 |
| recall | 0.9474 | 0.0013 |
| f1 | 0.9637 | 0.0007 |

## Held-out test set (calibrated final model, threshold 0.5)

| Accuracy | Precision | Recall | F1 | ROC-AUC |
|---|---|---|---|---|
| 0.9849 | 0.9753 | 0.9574 | 0.9663 | 0.9970 |

Confusion matrix (rows = actual, cols = predicted):

| | Pred. legitimate | Pred. phishing |
|---|---|---|
| **Legitimate** | 78,024 | 555 |
| **Phishing** | 973 | 21,887 |

## Domain-grouped split (harder, more realistic)

No registered domain appears in both train and test: accuracy 0.9561, precision 0.8996, recall 0.9015, F1 0.9005.

## Spot checks

| Phishing probability | URL |
|---|---|
| 0.000 | `https://www.google.com/` |
| 0.860 | `https://github.com/aish00625/SecureQR` |
| 0.151 | `https://www.amazon.in/` |
| 0.000 | `https://en.wikipedia.org/wiki/QR_code` |
| 0.004 | `https://www.nie.ac.in/` |
| 0.304 | `https://www.sbi.co.in/` |
| 1.000 | `http://paypal.com.account-verify-login.xyz/webscr?cmd=_login` |
| 1.000 | `http://192.168.10.5/secure/bank/login.php` |
| 0.983 | `http://free-gift-card-winner.top/claim-now.html` |
| 0.999 | `https://bit.ly/3xYzAbC` |

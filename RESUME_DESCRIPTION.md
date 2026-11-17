# Resume material – SecureQR

All figures are measured results from `model/metrics.json` and the test suite.

## Project title

**SecureQR – ML-Powered QR Code Phishing Detection Platform** (Python, Flask, scikit-learn, OpenCV)

## Resume bullets (pick three)

- Built a full-stack QR code security scanner (Flask, OpenCV, SQLite) that decodes QR codes from image uploads and a live webcam, classifies the payload (URL, UPI, Wi-Fi, SMS) and rates risk as Low/Medium/High by combining a machine-learning model with 20+ explainable security rules, without ever opening the scanned link.
- Re-engineered a phishing-URL classifier on 507K de-duplicated URLs, raising accuracy from 77.5% to **98.5%** and phishing recall from 26% to **95.7%** (F1 39.8% → 96.6%, ROC-AUC 0.997). I diagnosed a train/serve skew in the data and replaced 6 hand-crafted features with a calibrated Linear SVM on character n-gram TF-IDF + 30 lexical features, validated with 5-fold CV and a domain-grouped split (F1 90% on unseen domains).
- Hardened the application against OWASP risks with CSRF tokens, per-IP rate limiting, a strict Content Security Policy, parameterised SQL, in-memory upload validation (magic bytes, size and pixel limits) and an SSRF-free design, verified by **155 automated pytest tests** and an end-to-end headless-browser webcam test.

### Alternative shorter bullets
- Improved phishing detection recall from 26% to 95.7% (accuracy 77.5% → 98.5%) on 507K URLs using a calibrated Linear SVM with character n-gram features.
- Developed a Flask QR security scanner with webcam scanning, scan history, an analytics dashboard and explainable risk scoring.
- Implemented CSRF protection, rate limiting, CSP and secure upload handling; 155 pytest tests.

## Technology stack

**Languages:** Python, JavaScript, HTML, CSS, SQL
**Backend:** Flask (app factory, blueprints), SQLite, python-dotenv, logging
**ML:** scikit-learn (LinearSVC, CalibratedClassifierCV, HashingVectorizer, TF-IDF, FeatureUnion/Pipeline, StratifiedKFold, GroupShuffleSplit), pandas, NumPy, joblib, Matplotlib
**Computer vision:** OpenCV (QRCodeDetector, Aruco detector, morphological preprocessing), Pillow
**Security:** CSRF synchroniser tokens, sliding-window rate limiting, CSP and security headers, input validation, SSRF avoidance
**Testing/tools:** pytest, Playwright (headless Chrome), Git

## GitHub repository description (≤ 350 chars)

> QR code phishing scanner: decodes QR codes from images or webcam and rates risk with a calibrated Linear SVM (98.5% accuracy, 95.7% recall on 101K held-out URLs) plus 20+ explainable security rules. Flask, scikit-learn, OpenCV, SQLite. Never opens scanned links.

**Topics:** `phishing-detection` `qr-code` `cybersecurity` `machine-learning` `svm` `flask` `opencv` `scikit-learn` `quishing` `python`

## LinkedIn project description

**SecureQR – Intelligent QR Code Security Scanner**

QR codes hide their destination until you open them, which makes them an easy lure for phishing ("quishing"). I built SecureQR, a web application that scans QR codes from an image or a live webcam and explains how risky they are before you act on them.

What I did:
• Re-built the phishing-URL model on 507,000 de-duplicated URLs. I found the original model caught only 26% of phishing links because of a train/serve skew (the dataset's only URLs with "https://" were all phishing). After fixing it and switching to a calibrated Linear SVM on character n-grams plus 30 lexical features: 98.5% accuracy, 95.7% recall and 96.6% F1 on 101,000 held-out URLs, and 90% F1 on domains never seen in training.
• Added 20+ explainable security checks (IP hosts, shorteners, look-alike brand domains, punycode, dangerous schemes, executable downloads) and a risk policy where ML alone can never produce "high risk".
• Handled UPI payment and Wi-Fi QR codes with targeted warnings.
• Secured the Flask app with CSRF protection, rate limiting, a strict CSP, parameterised SQL and in-memory upload validation, and designed it so scanned links are never fetched (no SSRF).
• Wrote 155 automated tests, including an end-to-end webcam test in headless Chrome.

Tech: Python · Flask · scikit-learn · OpenCV · SQLite · JavaScript · pytest

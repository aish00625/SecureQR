# SecureQR – Interview preparation

Every answer below matches the code in this repository and the numbers in `model/metrics.json`. If an interviewer asks about something not listed here, say what the project does and does not do. Don't stretch it.

---

## 1. Elevator pitches

### 30 seconds
SecureQR is a web app that checks QR codes for phishing before you open them. It decodes the QR code from an image or a live webcam, works out what is inside (a link, a UPI payment, Wi-Fi details), and for links combines a Linear SVM model with explainable security rules to give a low, medium or high risk rating. I took the model from 77.5% accuracy and 26% phishing recall to 98.5% accuracy and 95.7% recall, mainly by fixing a train/serve skew bug in the data and switching to character n-gram features.

### 1 minute
QR phishing works because a QR code hides its destination until you open it. SecureQR is a Flask application that scans QR codes from an upload or the webcam, never opens the link, and explains the risk.

The pipeline has three layers. First, a multi-pass OpenCV decoder, which can even read coloured, dotted "designer" QR codes. Second, a Linear SVM trained on about 507,000 unique labelled URLs, using character 3–5-gram TF-IDF plus 30 hand-crafted lexical features, with calibrated probabilities. Third, a rule engine with over 20 checks such as raw IP hosts, URL shorteners, brand names outside the real domain and `javascript:` links.

ML alone can never produce "high risk"; it needs a rule to agree. That keeps model false positives in check. The app stores history in SQLite, has an analytics dashboard, and is hardened with CSRF tokens, rate limiting, a strict CSP and in-memory upload validation. 155 pytest tests cover it.

### 3 minutes
**Problem.** "Quishing" (QR phishing) is growing: fake parking-meter stickers, fake payment QR codes at shops, QR codes in e-mails that bypass link scanners. Users can't read a QR code with their eyes, so they open links blindly.

**Starting point.** My first version had a six-feature Linear SVM at 77.5% accuracy. When I evaluated it properly, I found it caught only 26% of phishing URLs, and an "always legitimate" classifier would have scored 71.6% on the same split. So accuracy was hiding a weak model.

**Root causes.** (1) The dataset stores URLs without a scheme, and the only 107 URLs that have `http://` or `https://` are all labelled phishing. My `https` feature had learned "having a scheme means phishing", yet real QR codes almost always start with `https://`. That is a train/serve skew bug. (2) Six counts can't capture patterns like `paypal.com.` in a subdomain or `webscr?cmd=`. (3) There were 42,000 duplicate URLs that could leak between train and test.

**Fixes.** I de-duplicated the data, strip the scheme from URLs in both training and inference, and built one scikit-learn Pipeline (canonicaliser → feature union of hashed character n-gram TF-IDF and 30 scaled lexical features → calibrated LinearSVC). The whole pipeline is saved as one artefact, so inference can't drift from training. I compared six models on a validation split, ran 5-fold cross-validation, and evaluated once on a held-out test set: 98.49% accuracy, 97.53% precision, 95.74% recall, F1 96.63%. Because a random split lets the same website appear in train and test, I also evaluated with no shared domains. F1 there is 90%, and that is the number I'd quote for brand-new phishing sites.

**Product.** The ML score is shown next to explainable rule findings, and a risk policy combines them. ML alone can only reach medium. The app also handles UPI payment QR codes, which matters in India, and Wi-Fi QR codes.

**Engineering.** Flask app factory with blueprints; SQLite with parameterised queries; CSRF synchroniser tokens; a sliding-window rate limiter; strict CSP with no inline scripts; uploads validated in memory by size, extension, magic bytes and pixel count; no outbound requests at all, so there is no SSRF surface. 155 tests, plus I verified the webcam flow end to end in headless Chrome with a fake camera.

**Limitations.** The model sees only the URL text, and the dataset is old and US-centric. For example, it gives my own GitHub repo URL an 86% phishing probability because of the digit-heavy username. That's exactly why ML can't produce high risk alone.

---

## 2. Architecture

```
Browser (Jinja pages + vanilla JS; textContent only; no inline JS/CSS)
   │  fetch + X-CSRF-Token
Flask create_app()
   ├─ security.py  before_request: CSRF │ decorator: rate limit │ after_request: headers
   ├─ views.py     pages blueprint + /api blueprint
   ├─ db.py        SQLite (per-request connection in flask.g)
   └─ core/
      qr_decoder → content → heuristics ┐
                            predictor ──┴→ analyzer (risk policy) → db → JSON
ml/  features.py (shared) · pipeline.py · train.py → model/secureqr_model.joblib + metrics.json
```

Main design choices:
- **App factory** (`create_app(overrides)`) so tests can create isolated apps with a temporary database and a small model.
- **Blueprints** separate HTML pages from the JSON API.
- **Core is framework-free**, so the same modules power the web app and the Tkinter/OpenCV desktop tools.
- **One pipeline object** for ML, so preprocessing can't diverge between training and inference.

## 3. End-to-end flow (image upload)

1. The user drops an image; JS checks extension and size, then `POST /api/scan/image` with FormData and the `X-CSRF-Token` header.
2. Flask rejects bodies over `MAX_CONTENT_LENGTH` (5 MB) with 413.
3. `verify_csrf` compares the header with the session token (`hmac.compare_digest`).
4. `@rate_limit("scan")` allows 30 requests per minute per IP, otherwise 429 with `Retry-After`.
5. `validate_image_bytes`: empty? → extension allow-list → magic bytes → Pillow `verify()` → pixel limit → `cv2.imdecode`. Everything happens in memory.
6. `decode_qr`: pyzbar if installed → OpenCV `QRCodeDetector` / `QRCodeDetectorAruco` on the original, an Otsu threshold, a min-channel threshold and eroded variants (working size and full resolution). The first success wins.
7. `analyze_payload` per code (max 5): classify → rules → ML (skipped for `javascript:`/`data:`) → `risk_level`.
8. `db.insert_scan` stores a summary plus the full result JSON; the API returns JSON.
9. `renderResult()` builds the DOM with `textContent`. The URL is never rendered as a link; a defanged copy is shown.

Webcam: `getUserMedia` → every 700 ms draw a frame onto a canvas → JPEG blob → `/api/scan/frame` (fast decoding mode, 150 requests/min, returns 200 `found:false` if empty) → stop the camera on the first hit.

---

## 4. Technical questions and answers

### Python

**Q1. Why `dataclass` for `Finding` and `DecodeResult`?**
They are plain data holders. `@dataclass` gives `__init__`, `__repr__` and equality for free, `asdict()` turns findings into JSON-ready dicts, and `DecodeResult.found` is a computed `@property`.

**Q2. How do you make model loading thread-safe?**
`Predictor` loads lazily inside a `threading.Lock`, with a double check (`if self._artefact is not None: return True`). Flask's dev server is threaded, so two first requests could otherwise both load the 5 MB model. After loading, prediction is read-only and safe to share.

**Q3. What does `from __future__ import annotations` do here?**
It turns annotations into strings evaluated lazily, so I can write `str | None` types and forward references cleanly without runtime cost.

**Q4. How do you avoid problems with malformed URLs?**
`urllib.parse.urlsplit` raises `ValueError` on inputs like `[::1` (unbalanced IPv6 bracket), and the dataset contains such URLs. I replaced it with a small regex-based `split_host` that never raises. There's a parametrised test with malformed inputs (`"[::1"`, `"a:b:c"`, `"%%%"`, a 5,000-character string…).

**Q5. Why `hmac.compare_digest` for the CSRF token?**
A normal `==` can return as soon as the first differing character is found, which leaks timing information. `compare_digest` runs in constant time.

**Q6. How is the rate limiter implemented?**
A sliding window: a `defaultdict(deque)` of timestamps per `bucket:ip`. On each hit I pop timestamps older than the window, reject if `len >= limit` (and compute `Retry-After` from the oldest timestamp), otherwise append. It's guarded by a lock and uses `time.monotonic()` so clock changes don't matter.

### Flask

**Q7. Why an application factory?**
Configuration can be injected per instance (tests pass a temp database, a small model and limits), there's no global app state, and extensions/blueprints are registered in one place.

**Q8. How do you manage the database connection?**
`get_db()` stores one `sqlite3` connection in `flask.g` per request, and `teardown_appcontext(close_db)` closes it. The schema is created idempotently (`CREATE TABLE IF NOT EXISTS`) at start-up.

**Q9. How do errors work for HTML and API routes?**
One `HTTPException` handler: if the path starts with `/api/` it returns JSON `{error, message}`, otherwise it renders `error.html`. A catch-all `Exception` handler logs the stack trace and returns a generic 500, so internals aren't leaked. 413 gets a friendly "file too large" message.

**Q10. How did you implement CSRF without Flask-WTF?**
Synchroniser-token pattern: `get_csrf_token()` creates `secrets.token_urlsafe(32)` in the session and exposes it to templates (as a `<meta>` tag). A `before_request` hook checks every POST/PUT/PATCH/DELETE for the `X-CSRF-Token` header or a form field. The session cookie is signed by Flask (`SECRET_KEY`) and `SameSite=Lax`, which is a second layer.

**Q11. Which security headers do you send, and why?**
CSP `default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'…` (blocks injected scripts and framing), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer` (a scanned URL never leaks via Referer), `Permissions-Policy: camera=(self)`, `Cache-Control: no-store` on the API, and HSTS when cookies are marked Secure.

**Q12. Why is there no inline JavaScript?**
So the CSP can use `script-src 'self'` without `'unsafe-inline'`. Even if an attacker got markup into a page, inline `<script>` and `onerror=` handlers would not run. Inline `style=""` attributes are blocked too, so I used utility classes; setting `element.style.width` from JS (CSSOM) is still allowed.

### Machine learning and SVM

**Q13. Explain how a Linear SVM works.**
It finds the hyperplane `w·x + b = 0` that separates the classes with the largest margin. It minimises `½‖w‖² + C Σ hinge_loss`, where hinge loss is `max(0, 1 − y(w·x+b))`. Points inside the margin or misclassified are penalised, and C trades margin width against training errors.

**Q14. Why a linear kernel rather than RBF?**
The feature space is about 524,000 dimensions (2¹⁹ hashed n-grams + 30). In very high-dimensional sparse text data, classes are usually close to linearly separable, and kernel SVMs scale roughly O(n²) to O(n³) with 400,000 samples, which is impractical. LinearSVC (liblinear) trains in about a minute.

**Q15. What does C do and how did you choose it?**
C controls regularisation: high C fits the training data harder (narrower margin), low C regularises more. I compared C=0.5 and C=1.0 on a validation split; 1.0 had the better F1 (0.9644 vs 0.9617).

**Q16. LinearSVC has no `predict_proba`. How do you get probabilities?**
`CalibratedClassifierCV(LinearSVC, method="sigmoid", cv=3, ensemble=False)`. Platt scaling fits a sigmoid on the SVM decision scores using cross-validated predictions, then one final SVM is trained on all the data, which keeps the model file small.

**Q17. What are character n-grams and why do they work for URLs?**
Overlapping substrings of length 3–5 (e.g. `pay`, `aypa`, `paypa`). They capture sub-word patterns without a tokenizer: brand fragments in the wrong position (`.com.`), `webscr`, `.php?`, random hex strings, digit runs. TF-IDF down-weights n-grams that appear everywhere (`www`, `.com`), and sublinear TF dampens repeats.

**Q18. Why `HashingVectorizer` instead of `TfidfVectorizer`?**
Hashing maps n-grams to 2¹⁹ buckets with a hash function, so there's no vocabulary to store (the model is 4.9 MB rather than tens of MB), it's memory-efficient, and it handles unseen n-grams at inference. The cost is occasional collisions and no reverse mapping from feature to n-gram. `TfidfTransformer` still learns the IDF weights.

**Q19. What are the 30 lexical features?**
Lengths (URL, host, path, query); counts of `.` `-` digits `@` `?` `=` `&` `%` `/` `_` `~` and uppercase letters; digit ratio; number of subdomains; IP host; port; TLD length; digits in host; hyphens in host; Shannon entropy of the host; punycode; `//` in the path; suspicious-word count; shortener domain; path depth; longest token. They are `log1p`-transformed and standard-scaled.

**Q20. Why weight the lexical block by 0.1?**
The TF-IDF rows are L2-normalised (length 1) while the scaled lexical features each have variance 1, so unweighted they dominated the margin and LinearSVC converged very slowly. In an experiment on 120k training URLs, the unweighted union took 347 s (with convergence warnings) and scored *worse* than char n-grams alone. Down-weighted (0.05 and 0.15 tested), it trained in 16–49 s and scored *better*, so I used 0.1. On the full validation split the combined model beat char-only on F1, 0.9644 vs 0.9588.

**Q21. How do you guarantee training and inference use the same features?**
The saved artefact is one sklearn `Pipeline`: `Canonicalizer → FeatureUnion → CalibratedClassifier`. Inference passes the raw URL string to `pipeline.predict_proba`. A unit test asserts `https://Example.com/Login` and `example.com/Login` get identical probabilities, and another asserts the step names.

**Q22. Why remove duplicates before splitting?**
42,151 rows were exact duplicates. With a random split, the same URL can be in train and test, so the model is partly tested on memorised data, which inflates scores.

**Q23. Why report precision, recall and F1 instead of only accuracy?**
The classes are imbalanced (22.5% phishing after de-duplication). The old model had 77.5% accuracy but 26% recall. For a security tool, recall (phishing caught) and precision (alerts that are real) matter more. I selected the model by F1 on the phishing class.

**Q24. Read your confusion matrix.**
On 101,439 test URLs: 78,024 true negatives, 555 false positives (0.71% of legitimate URLs flagged), 973 false negatives (4.26% of phishing missed) and 21,887 true positives.

**Q25. What's the difference between your random-split and domain-grouped results?**
Random split: F1 96.63%. Grouped so no registered domain appears in both train and test: F1 90.05% (precision 89.96%). The random split lets the model recognise known sites; the grouped split simulates new domains. That's the realistic estimate for zero-day phishing.

**Q26. Did you consider other models?**
Yes, on the same validation split: LinearSVC on 30 lexical features (F1 0.683), HistGradientBoosting on lexical features (0.858), LinearSVC on char n-grams (0.959), LinearSVC on combined features (0.964, chosen), and logistic regression on combined features (0.959, about 2× slower). The representation mattered far more than the algorithm, so I kept the Linear SVM.

**Q27. How did you cross-validate?**
`StratifiedKFold(n_splits=5, shuffle=True, random_state=42)` on the training split only, scoring accuracy, precision, recall and F1. Result: accuracy 98.39% ± 0.03%, F1 96.37% ± 0.07%. The test set was used only once, for the final model.

**Q28. What is ROC-AUC and what was yours?**
The probability that a random phishing URL scores higher than a random legitimate one, independent of threshold. 0.997 on the test set.

### Cybersecurity

**Q29. What is quishing, and why are QR codes attractive to attackers?**
Phishing via QR codes. The destination is invisible to humans; QR codes in images bypass e-mail link scanners; and they appear on physical surfaces (stickers over real codes) where people trust them. Payment QR codes are abused for "scan to receive money" scams.

**Q30. Why does the app never open the URL? Wouldn't fetching the page give better detection?**
Fetching would create an **SSRF** risk: a QR code containing `http://169.254.169.254/` or `http://localhost:6379` would make my server attack internal services. It would also confirm to the attacker that the link was scanned, and could trigger drive-by downloads. Doing it safely needs an isolated sandbox with egress filtering, DNS-rebinding protection and redirect limits. I listed that as future work instead of doing it unsafely.

**Q31. Explain the `@` trick your rules detect.**
In `https://www.sbi.co.in@203.0.113.50/kyc`, everything before `@` is the userinfo part, so the browser connects to `203.0.113.50`. The rule checks for `@` in the authority part.

**Q32. What is a homograph / punycode attack?**
Registering a domain with look-alike Unicode characters (e.g. Cyrillic "а" in `pаypal.com`), which is encoded as `xn--…`. The rule flags `xn--` labels and non-ASCII host characters.

**Q33. How does brand-impersonation detection work?**
The rule computes an approximate registered domain (eTLD+1 with a small second-level list such as `co.in`), then looks for known brand names in the subdomains, path or query but not in the registered domain itself. So `paypal.com.account-verify.xyz` is flagged, while `www.paypal.com/signin` is not.

**Q34. How do you prevent XSS when you display attacker-controlled QR content?**
Jinja auto-escaping for server-side templates; on the client every value goes through `textContent`, never `innerHTML`; the detail page embeds the result with `|tojson`, which escapes `<`, `>` and `&`, so `</script>` can't break out; plus the strict CSP. A test stores `</script><script>alert(1)</script>` and asserts it doesn't appear unescaped.

**Q35. How do you prevent SQL injection?**
Only `?` placeholders; user input is never concatenated into SQL. `LIKE` searches escape `%`, `_` and `\` with an `ESCAPE` clause. Enum-like columns have CHECK constraints. A test stores `'); DROP TABLE scans; --` and searches for `' OR 1=1 --`; the table survives and the search returns nothing.

**Q36. How are uploads secured?**
A size limit enforced by Flask before reading, an extension allow-list, magic-byte checks (so an EXE renamed to `.png` is rejected), Pillow `verify()`, a pixel limit against decompression bombs, and decoding in memory only. No file is ever written, so there's no path traversal and no stored malicious file.

**Q37. Why not trust `X-Forwarded-For` for rate limiting?**
Any client can set that header, so an attacker could rotate fake IPs to bypass limits. It's only honoured when `SECUREQR_TRUST_PROXY=true`, i.e. behind a proxy that overwrites it.

**Q38. What about log injection?**
Scanned content is attacker-controlled. Before logging I strip CR/LF and truncate to 200 characters, and log with `%r`, so a QR code can't forge fake log lines.

### QR-specific

**Q39. How does your decoder handle stylised QR codes?**
Designer codes with round dots and coloured modules defeat the standard detector. I take the per-pixel minimum of the colour channels (so red/blue modules become dark), erode it so neighbouring dots merge into solid modules, then Otsu-threshold, at working resolution and at full resolution. The sample in `demo_qr/` only decodes on the `opencv-full-erode5` pass, and a test locks that in.

**Q40. Why OpenCV rather than pyzbar?**
pyzbar needs the native zbar library (and the VC++ runtime on Windows), which often breaks installs. OpenCV's detector ships inside `opencv-python`. pyzbar is optional and tried first if it's installed.

**Q41. What non-URL QR payloads do you handle?**
UPI (`upi://pay?pa=…&am=…`, warning that you never need to scan to receive money), Wi-Fi (`WIFI:T:…;S:…`, warning on open/WEP), SMS (premium-rate risk), phone, e-mail, vCard/MeCard, geo, plain text, and text containing a URL (the URL is extracted and analysed).

### System design

**Q42. How would you scale this to many users?**
Run the Flask app under gunicorn/waitress behind nginx with TLS; move rate limiting to Redis; switch SQLite to PostgreSQL behind the same `db.py` interface; put image decoding (the slow part, up to a few seconds for large photos) on a task queue; load the model once per worker (it's only 5 MB); add auth so history is per user.

**Q43. How would you update the model safely?**
Version the artefact (it stores `version`, `trained_at`, `sklearn_version` and test metrics). Retrain offline, compare against the current model on the same held-out and domain-grouped sets, then do a canary or shadow deployment. The predictor smoke-tests the model at start-up and degrades gracefully: rules still work if the model fails to load.

**Q44. How would you add safe redirect expansion?**
A separate worker in an isolated network: resolve DNS once and block private, loopback, link-local and metadata IPs; connect to the resolved IP (to defeat DNS rebinding); `HEAD` with no body download; follow at most N redirects, re-checking each hop; strict timeouts; cache results.

---

## 5. Technical challenges (stories to tell)

1. **The model was secretly broken.** Accuracy looked fine (77.5%), but recall was 26%: the model barely beat "always legitimate" (71.6%). I learned to start with the confusion matrix and a majority-class baseline.
2. **Train/serve skew via the URL scheme.** I found that all 107 URLs with a scheme were labelled phishing, while production inputs always have a scheme. Fixed by canonicalising in both paths and putting it inside the pipeline.
3. **Feature scaling between sparse and dense blocks.** Combining TF-IDF with standardised features made LinearSVC slow to converge and worse. Weighting the dense block (0.1) fixed both.
4. **Decoding a designer QR code.** I iterated through preprocessing strategies until erosion at native resolution worked, then made it a fallback pass so normal codes stay fast.
5. **Malformed URLs crashing feature extraction.** `urlsplit` raised on real dataset rows, so I wrote a parser that never raises.
6. **CSP vs. styling.** A strict CSP blocks inline `style` attributes, so I refactored templates to utility classes.
7. **Honest evaluation.** Adding a domain-grouped split lowered the headline number (F1 96.6% → 90.0%), but it's the truthful estimate, and interviewers respect that.

## 6. Limitations (say these before you're asked)

- The model uses URL text only: no page content, domain age, DNS or threat-intel feeds.
- The dataset is older and US-centric; Indian and modern domains are under-represented. Known false positive: `github.com/aish00625/SecureQR` scores 0.86.
- Short links are flagged but not expanded.
- The heuristic eTLD+1 is not the full Public Suffix List.
- Rate limiter and history are single-instance; no user accounts.
- Probabilities are calibrated on the dataset distribution, not on real QR traffic.

## 7. Future improvements

Sandboxed redirect expansion; WHOIS domain age and TLS certificate features; Google Safe Browsing / PhishTank lookups (cached, privacy-aware); a fresher dataset (PhishTank, OpenPhish, Tranco top sites for negatives); a Public Suffix List via `tldextract`; user accounts; Docker + CI; a browser extension / Android app; active-learning feedback ("report false positive").

## 8. Difficult follow-up questions

**"98.5% sounds too good. Isn't it overfitting?"**
Three checks: (1) 5-fold CV std is only 0.03%, so it's stable; (2) the test set was untouched until the end; (3) I ran a stricter domain-grouped split where F1 drops to 90%. I quote 90% for unseen domains. The dataset is also fairly "easy" because old phishing URLs have very distinctive lexical patterns, which I mention as a limitation.

**"So why is your own GitHub link flagged?"**
Character n-grams associate digit-heavy random tokens with phishing, and the data has few modern developer URLs. That's why the risk policy needs a corroborating rule before HIGH; that URL shows as MEDIUM with a clear explanation.

**"Why not deep learning or a transformer?"**
With half a million short strings, a linear model on character n-grams is a strong baseline: it trains in minutes on a laptop, predicts in about 1 ms, is 5 MB, and is easier to reason about. A char-CNN or fine-tuned transformer might add a little, but I'd want a better, fresher dataset first, because data quality was the bigger problem.

**"An attacker knows your features. Can't they evade them?"**
Yes, lexical models can be evaded (e.g. a clean-looking domain with a short path). That's why there are independent layers: rules that target structural tricks, the user-facing explanation, and the fact that the app doesn't open the link. Real deployments would add reputation and page-content signals.

**"Isn't sending webcam frames to a server a privacy issue?"**
Only single JPEG frames, every 0.7 s, go to the local server; they are decoded in memory and never stored, and the camera stops at the first hit. A production version could decode in the browser (e.g. the BarcodeDetector API or WASM) and send only the payload.

**"What if the model file is tampered with?"**
joblib/pickle can execute code when loaded, so the model must come from a trusted source. Mitigation: ship a SHA-256 checksum and verify before loading, or export the linear weights to a non-executable format. I'd add the checksum next.

**"How do you know your rule weights are right?"**
They are expert-chosen, not learned, and that's their purpose: deterministic and explainable. Thresholds (50 / 20) were set so single weak signals stay LOW and combinations escalate. A next step would be to calibrate them against labelled QR samples.

**"Why SQLite?"**
Zero setup, a single file, ACID, and enough for a single-user tool. All access is in `db.py`, so moving to PostgreSQL is a contained change.

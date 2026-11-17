# SecureQR architecture

## High-level view

```
 Browser (HTML + vanilla JS, no inline scripts)
   │  Landing · Scan (image / camera / link) · History · Analytics · About
   │  fetch() + X-CSRF-Token header
   ▼
 Flask app  (secureqr/__init__.py → create_app)
   ├── security.py   CSRF check · rate limiter · security headers · client IP
   ├── views.py      page routes (Blueprint "pages") + JSON API (Blueprint "api")
   ├── db.py         SQLite scan history (parameterised SQL only)
   └── core/
        ├── qr_decoder.py  validate upload in memory → multi-pass QR decoding
        ├── content.py     classify payload (URL, UPI, Wi-Fi, SMS, …) + extract URL
        ├── heuristics.py  explainable rule engine → score 0-100 + findings
        ├── predictor.py   loads model once, thread-safe, graceful failure
        └── analyzer.py    combines everything → LOW / MEDIUM / HIGH
 ML package (secureqr/ml/)
   ├── features.py    canonicalize_url + 30 lexical features (shared train/infer)
   ├── pipeline.py    sklearn Pipeline definitions
   └── train.py       training, comparison, CV, evaluation, report generation
 Artefacts: model/secureqr_model.joblib · model/metrics.json · model/confusion_matrix.png
```

## Request flow: image upload

1. Browser posts `multipart/form-data` to `POST /api/scan/image` with the CSRF token in a header.
2. `security.verify_csrf` (a `before_request` hook) compares the header with the session token using `hmac.compare_digest`.
3. The `@rate_limit` decorator checks a per-IP sliding window.
4. Flask enforces `MAX_CONTENT_LENGTH` (default 5 MB) **before** the body is read (HTTP 413 otherwise).
5. `validate_image_bytes` checks: non-empty → extension allow-list → magic bytes → Pillow format + `verify()` → pixel limit (decompression-bomb guard) → `cv2.imdecode`. **Nothing is written to disk.**
6. `decode_qr` tries pyzbar (if installed), then OpenCV `QRCodeDetector` and `QRCodeDetectorAruco` on a series of variants: original, Otsu threshold, min-channel threshold, eroded versions at working and full resolution. The erosion passes merge the dots of "artistic" QR codes into solid modules. The first pass that decodes wins.
7. For each payload (max 5): `analyze_payload`
   - `classify_payload` → content type; only URL-like payloads continue to ML.
   - `heuristics.analyze_url` → findings + score.
   - `Predictor.predict` → phishing probability (skipped for `javascript:` / `data:` schemes).
   - `risk_level` → final level + human-readable reasons + recommendations.
8. The result is stored in SQLite and returned as JSON. The browser renders it with `textContent` only and **never** turns the URL into a link.

The camera tab uses the same path through `POST /api/scan/frame` (higher rate limit, a cheaper "fast" decoding mode, and HTTP 200 with `found:false` when no code is visible). The browser grabs one JPEG frame every 700 ms and stops the camera as soon as a code is found.

## Risk policy

| Level | Condition |
|---|---|
| HIGH | a critical rule fires (`javascript:`, `data:`, `file:` …) **or** rule score ≥ 50 **or** (ML probability ≥ 0.80 **and** at least one corroborating medium/high rule other than "URL shortener") |
| MEDIUM | ML probability ≥ 0.50 **or** rule score ≥ 20 **or** any high-severity rule **or** UPI payment request / insecure Wi-Fi / pre-filled SMS |
| LOW | everything else |

Why ML alone cannot produce HIGH: the model is trained on a 2010s-era URL dataset and does make confident mistakes on unfamiliar legitimate domains (see "Limitations" in MODEL_EVALUATION.md). Requiring a corroborating deterministic signal for the top level reduces alarm fatigue, and both signals are always shown separately.

## Machine-learning pipeline

```
raw URL ──► Canonicalizer ──► FeatureUnion ─┬─► HashingVectorizer(char 3-5-grams, 2^19) ─► TF-IDF (sublinear)  weight 1.0
           (strip scheme,                  └─► LexicalFeatures (30) ─► log1p ─► StandardScaler             weight 0.1
            lower-case host)                                   │
                                                               ▼
                                     CalibratedClassifierCV(LinearSVC(C=1.0), sigmoid, cv=3)
                                                               ▼
                                                  P(phishing), threshold 0.5
```

The **entire** chain is one `sklearn.pipeline.Pipeline` saved with joblib, so training and inference cannot drift apart. The predictor passes raw URL strings.

**Why the scheme is stripped:** in `phishing_site_urls.csv`, 507,088 of 507,195 unique URLs have no scheme, and the 107 that start with `http://` or `https://` are **all** labelled phishing. The original model's `https` feature was really learning "has a scheme ⇒ phishing", while real QR codes almost always start with `https://`. Canonicalising both sides removes this train/serve skew. HTTPS is evaluated by the rule engine instead.

## Data model

```sql
scans(id, created_at, source['upload'|'webcam'|'url'], content_type, raw_content,
      url, host, ml_label, ml_probability, heuristic_score,
      risk_level['LOW'|'MEDIUM'|'HIGH'], result_json)
```

`result_json` stores the full analysis, so the detail page re-renders exactly what the user saw. Images are never stored.

## Security controls

| Threat | Control |
|---|---|
| CSRF | Synchroniser token in the session, required on every POST/PUT/PATCH/DELETE (header `X-CSRF-Token`), constant-time compare |
| XSS | Jinja auto-escaping; all dynamic content inserted with `textContent`; scan JSON embedded with `|tojson` (escapes `<`, `>`, `&`); strict CSP with `script-src 'self'` and no inline scripts or styles |
| SQL injection | Only parameterised queries; `LIKE` wildcards escaped; CHECK constraints on enum columns |
| Malicious uploads | Size limit, extension allow-list, magic-byte check, Pillow verify, pixel limit, in-memory processing only |
| SSRF | Scanned URLs are **never fetched or resolved**. No outbound requests exist in the codebase. |
| Brute-force / DoS | Per-IP sliding-window rate limits per endpoint group; `X-Forwarded-For` only trusted when `SECUREQR_TRUST_PROXY=true` |
| Session theft | `HttpOnly`, `SameSite=Lax`, optional `Secure` + HSTS, secret key from the environment |
| Clickjacking / sniffing | `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` |
| Log injection | CR/LF stripped and length limited before scanned content is logged |
| Information leakage | Generic 500 responses; stack traces only in the log file |

## Scaling notes (not implemented)

- Rate limiter and model are per-process. For several workers, move rate limiting to Redis and run behind gunicorn/waitress + nginx.
- SQLite is fine for a single node; swap to PostgreSQL behind the same `db.py` interface for multi-user deployments.
- Model inference is ~1 ms per URL; decoding large photos (~0.1–3 s) dominates, so it could move to a task queue if needed.

# SecureQR – 5-minute demo script

## Before you start (checklist)

- [ ] `.\venv\Scripts\Activate.ps1` then `python run.py`; open http://127.0.0.1:5000 in Chrome.
- [ ] Clear old history (History → Clear history) so the analytics are clean, or keep a few scans for a populated dashboard.
- [ ] Open the `demo_qr` folder in Explorer. Optionally open `04_brand_lookalike.png` on your phone for the webcam demo.
- [ ] Allow camera access for 127.0.0.1 once beforehand.
- [ ] Have `docs/MODEL_EVALUATION.md` and `secureqr/ml/features.py` open in VS Code in case you're asked.

All demo QR codes use reserved documentation domains/IPs or invented domains. They are safe even if opened.

---

## 0:00 – 0:40 · Problem

> "QR codes are everywhere: parking meters, restaurant menus, UPI payments. But a QR code hides its destination until you open it. Attackers exploit this by sticking fake codes over real ones, or putting QR codes in e-mails so link scanners can't see them. This is called *quishing*. In India, there's also the 'scan this to receive money' UPI scam.
> I built SecureQR so you can see what a QR code contains and how risky it is *before* you act on it, and it never opens the link itself."

## 0:40 – 1:20 · Solution and architecture

Show the landing page and scroll to "Three checks on every scan".

> "Every scan goes through three layers. **Decode**: OpenCV reads the QR code, even stylised ones, and identifies the content type. **Classify**: a Linear SVM trained on about 507,000 unique URLs gives a phishing probability. **Explain**: more than 20 security rules check for things like IP addresses, URL shorteners and fake brand domains. A risk policy combines the two into low, medium or high, and the two signals are always shown separately."

(If asked: Flask app factory, blueprints, SQLite, vanilla JS; the whole ML pipeline is one scikit-learn object, so training and inference are identical.)

## 1:20 – 3:10 · Live demonstration

1. **Safe code.** Scan → Image → `01_safe_wikipedia.png`.
   > "Low risk: the ML probability is near zero and no rules fire. Notice the URL is displayed as text, not a link."
2. **Phishing look-alike.** Upload `04_brand_lookalike.png`.
   > "High risk. The model is confident, and the rules explain *why*: 'paypal' appears outside the real domain, which is actually `example.xyz`; it's HTTP; it uses a high-abuse TLD; and it contains credential keywords. There's also a defanged version for safe sharing."
3. **The `@` trick.** Upload `06_userinfo_trick.png`.
   > "This looks like SBI, but everything before the `@` is ignored by the browser, so it really goes to an IP address."
4. **UPI scam.** Upload `09_upi_payment.png`.
   > "Not every QR code is a URL. This is a UPI payment request. SecureQR shows the payee and amount and warns that you never scan a code to *receive* money."
5. **Webcam.** Camera tab → Start camera → hold up the phone showing a demo code.
   > "Frames are sent to the local server every 0.7 seconds; it stops automatically once a code is found."
6. **Designer QR.** Upload `sample_stylised_qr.webp`.
   > "This red dotted QR code defeats the standard OpenCV detector. My decoder falls back to colour-channel thresholding and erosion to merge the dots. It's a QR-generator short link, so it shows a shortener warning and a note that ML is less reliable here."
7. **History & Analytics.** Open History (filter by High), then Analytics.
   > "Every scan is stored in SQLite. The analytics page shows trends and the model's real evaluation."

## 3:10 – 4:00 · ML explanation (on the Analytics page)

Point at the before/after table and the confusion matrix.

> "My first model had 77.5% accuracy, which sounded fine, but it caught only 26% of phishing URLs. A model that always says 'legitimate' would get 71.6%.
> Investigating, I found the dataset's only URLs with `https://` were all labelled phishing, so the old `https` feature had learned the opposite of reality for QR codes. I fixed that skew, removed 42,000 duplicates, and switched to character n-gram TF-IDF plus 30 lexical features with a calibrated Linear SVM.
> On 101,000 held-out URLs: 98.5% accuracy, 95.7% recall, 96.6% F1. On a stricter split where test domains never appear in training, F1 is 90%, and that's the number I'd quote for new phishing sites."

## 4:00 – 4:30 · Security explanation

> "Because the app processes attacker-controlled content, I treated it like a security product: CSRF tokens on every POST, per-IP rate limiting, a strict Content Security Policy with no inline scripts, parameterised SQL, uploads validated in memory by size, type, magic bytes and pixel count, and secure cookies. Most importantly, the server never fetches a scanned URL, so there's no SSRF risk and the attacker never learns the code was scanned. There are 155 automated tests, including stored-XSS and SQL-injection cases."

## 4:30 – 5:00 · Challenges, limitations, future scope

> "The biggest challenges were the data skew, combining sparse and dense features (the SVM wouldn't converge until I re-weighted them), and decoding designer QR codes.
> Limitations: the model only sees URL text, and the dataset is older and US-centric. For example, it gives my own GitHub URL an 86% phishing score, which is why ML alone can never produce 'high risk'.
> Next: safe redirect expansion in a sandbox, domain-age and threat-intel signals, a fresher dataset, and a mobile app."

---

## Common interviewer questions during the demo (short answers)

| Question | Answer |
|---|---|
| Why Linear SVM? | Best validation F1 of six candidates; trains in about a minute on 400K URLs; 1 ms predictions; 4.9 MB model. The representation mattered more than the algorithm. |
| How do you get a probability from an SVM? | Platt scaling via `CalibratedClassifierCV(method="sigmoid")`. |
| What if the model is wrong? | Rules are shown separately; ML alone caps at MEDIUM; the user sees reasons, not just a label. |
| Why not visit the URL? | SSRF risk, it tips off the attacker, and drive-by downloads. It would need a sandboxed resolver (future work). |
| How do you stop XSS from QR content? | `textContent` only, `|tojson` embedding, auto-escaping, strict CSP, tested with a `</script>` payload. |
| Accuracy on new domains? | F1 90.05% with a domain-grouped split. |
| How is it tested? | 155 pytest tests plus a headless-Chrome webcam test with a fake camera feed. |
| What would you change for production? | gunicorn/waitress behind nginx with TLS, Redis rate limiting, PostgreSQL, user accounts, model checksum, Docker + CI. |

## Backup plan

- **Webcam fails:** use the image upload; mention the automated webcam test.
- **Model fails to load:** the app still works with rules only (results show "Model unavailable"). Run `python -m secureqr.ml.train --quick` (about 1.5 min) for a working model.
- **No internet:** everything runs offline; only the web fonts fall back to system fonts.

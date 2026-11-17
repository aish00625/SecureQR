# SecureQR HTTP API

Base URL: `http://127.0.0.1:5000`. All responses are JSON. Errors look like:

```json
{ "error": "invalid_image", "message": "File content does not match its extension." }
```

## CSRF

Every `POST` and `DELETE` must send the session's CSRF token in the `X-CSRF-Token` header. The token is in `<meta name="csrf-token">` on any HTML page, and the session cookie must be sent too. The bundled front-end does this automatically. A missing or invalid token returns **400**.

## Rate limits (per client IP, 60 s window, configurable)

| Group | Endpoints | Default |
|---|---|---|
| scan | `/api/scan/image`, `/api/scan/url` | 30 |
| frame | `/api/scan/frame` | 150 |
| read / write | history, stats, model | 120 each |

When a limit is exceeded the API returns **429** with a `Retry-After` header.

---

### `POST /api/scan/image`
Multipart form with field `file` (PNG, JPG/JPEG, WEBP or BMP, up to 5 MB, up to 40 MP).

| Status | Meaning |
|---|---|
| 200 | `{found: true, count, results: [ScanResult…]}` (up to 5 codes per image) |
| 400 | `no_file` / `invalid_image` (wrong type, spoofed extension, corrupt, too many pixels) |
| 413 | file larger than the limit |
| 422 | `{found: false, message}`: valid image but no QR code |

### `POST /api/scan/frame`
Same as above, for webcam frames. Returns **200** `{found:false}` when no code is visible so the client can keep polling. Uses faster, less exhaustive decoding.

### `POST /api/scan/url`
JSON `{"url": "https://example.com/login"}`. Max 2048 characters, no whitespace, must look like a URL (scheme optional).

### `ScanResult`
```jsonc
{
  "id": 12,
  "raw_content": "http://198.51.100.23:8080/secure/bank/login.php",
  "content_type": "url",             // url | dangerous_scheme | text_with_url | upi | wifi | email | phone | sms | contact | location | text | empty
  "content_label": "Web link",
  "content_details": {},             // e.g. UPI payee/amount, Wi-Fi SSID/security
  "content_notes": [],
  "url": "http://198.51.100.23:8080/secure/bank/login.php",
  "url_defanged": "hxxp://198[.]51[.]100[.]23:8080/secure/bank/login.php",
  "ml": {                            // null when not applicable
    "available": true, "label": "PHISHING", "phishing_probability": 0.9993,
    "confidence": 0.9993, "threshold": 0.5,
    "model": "Linear SVM (char n-grams + lexical features) v2.0.0"
  },
  "heuristics": {
    "score": 64, "critical": false,
    "findings": [ { "id": "ip_host", "severity": "high", "title": "Raw IP address instead of a domain", "detail": "…", "points": 25 } ],
    "facts": { "scheme": "http", "https": false, "host": "198.51.100.23", "registered_domain": "…", "subdomain_count": 0, "tld": null, "is_ip": true, "length": 47 }
  },
  "risk_level": "HIGH",
  "risk_reasons": ["Heuristic risk score 64/100 is at or above 50."],
  "recommendations": ["Do not open this link or enter any information.", "…"],
  "decoder": "opencv"                // only for image/frame scans
}
```

### `GET /api/history?limit=25&offset=0&risk=HIGH&q=paypal`
Returns `{items, total, limit, offset}`. `limit` is clamped to 1–100; `risk` is one of LOW/MEDIUM/HIGH; `q` searches content and host (max 200 characters).

### `GET /api/history/<id>`
The summary fields plus `result` (the full ScanResult). Returns 404 if the scan does not exist.

### `DELETE /api/history/<id>` · `DELETE /api/history`
Delete one scan, or clear all scans. Returns `{deleted: n}`.

### `GET /api/stats`
Totals by risk, source and content type, a 14-day daily series, the most frequent warnings and the most scanned hosts.

### `GET /api/model`
The evaluation summary from `model/metrics.json`: dataset, baseline, comparison, cross-validation, test metrics, confusion matrix and domain-grouped metrics.

### `GET /api/health`
`{status, model_loaded, model:{…}, decoders:["opencv", …]}`. Not rate limited.

## Example (PowerShell)

```powershell
$s = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$page = Invoke-WebRequest http://127.0.0.1:5000/scan -WebSession $s
$token = ($page.Content | Select-String 'name="csrf-token" content="([^"]+)"').Matches[0].Groups[1].Value
Invoke-RestMethod http://127.0.0.1:5000/api/scan/url -Method Post -WebSession $s `
  -Headers @{ "X-CSRF-Token" = $token } -ContentType "application/json" `
  -Body '{"url":"http://198.51.100.23/paypal/login.php"}'
```

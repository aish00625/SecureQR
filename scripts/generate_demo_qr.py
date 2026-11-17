"""Generate safe demonstration QR codes into ./demo_qr.

None of the "suspicious" links point at real infrastructure: they use the
reserved documentation domains/IP ranges (example.com/.net, *.test, RFC 5737
addresses 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) or invented domains,
so scanning or accidentally opening them is harmless.

    python scripts/generate_demo_qr.py
"""
from pathlib import Path

import cv2

OUT = Path(__file__).resolve().parents[1] / "demo_qr"

DEMOS = {
    "01_safe_wikipedia": "https://en.wikipedia.org/wiki/QR_code",
    "02_safe_github": "https://github.com/",
    "03_ip_login_http": "http://198.51.100.23:8080/secure/bank/login.php",
    "04_brand_lookalike": "http://paypal.com.account-verify-login.example.xyz/webscr?cmd=_login",
    "05_shortened_link": "https://bit.ly/3xYzAbC",
    "06_userinfo_trick": "https://www.sbi.co.in@203.0.113.50/kyc-update",
    "07_apk_download": "https://free-prize-claim.example.top/app/reward.apk",
    "08_javascript_scheme": "javascript:alert('SecureQR demo')",
    "09_upi_payment": "upi://pay?pa=demo.merchant@okaxis&pn=Demo%20Store&am=499.00&cu=INR&tn=Order%2042",
    "10_open_wifi": "WIFI:T:nopass;S:Free_Airport_WiFi;;",
    "11_plain_text": "SecureQR demo - this QR code only contains text.",
}


def write(name: str, text: str, scale: int = 10, border: int = 4) -> Path:
    qr = cv2.QRCodeEncoder.create().encode(text)
    qr = cv2.resize(qr, None, fx=scale, fy=scale, interpolation=cv2.INTER_NEAREST)
    qr = cv2.copyMakeBorder(qr, *(4 * [border * scale]), cv2.BORDER_CONSTANT, value=255)
    path = OUT / f"{name}.png"
    cv2.imwrite(str(path), qr)
    return path


def main():
    OUT.mkdir(exist_ok=True)
    for name, text in DEMOS.items():
        print(write(name, text).name, "->", text)


if __name__ == "__main__":
    main()

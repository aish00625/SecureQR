"""OpenCV webcam scanner (optional, terminal + preview window). Press ESC to quit.

Run from the project root:  python -m desktop_app.webcam_qr_scanner
The web app's Camera tab is the recommended way to scan with a webcam.
"""
import cv2

from secureqr.config import Config
from secureqr.core.analyzer import analyze_payload
from secureqr.core.predictor import Predictor
from secureqr.core.qr_decoder import decode_qr

COLORS = {"HIGH": (60, 60, 230), "MEDIUM": (0, 170, 240), "LOW": (110, 200, 50)}


def main():
    predictor = Predictor(Config.MODEL_PATH)
    cap = cv2.VideoCapture(0)
    if not cap.isOpened():
        print("Could not open the webcam.")
        return
    last, label = None, ""
    print("Webcam started - press ESC to exit")
    while True:
        ok, frame = cap.read()
        if not ok:
            print("Failed to read from webcam")
            break
        res = decode_qr(frame, fast=True)
        if res.found and res.payloads[0] != last:
            last = res.payloads[0]
            r = analyze_payload(last, predictor)
            label = f"{r['risk_level']} RISK"
            print(f"\nQR: {last}\nRisk: {r['risk_level']} | reasons: {'; '.join(r['risk_reasons'])}")
        if label:
            color = COLORS.get(label.split()[0], (255, 255, 255))
            cv2.putText(frame, label, (20, 40), cv2.FONT_HERSHEY_SIMPLEX, 1.0, color, 2)
        cv2.imshow("SecureQR webcam scanner", frame)
        if cv2.waitKey(1) == 27:
            break
    cap.release()
    cv2.destroyAllWindows()


if __name__ == "__main__":
    main()

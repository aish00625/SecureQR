import cv2
from pyzbar.pyzbar import decode
import joblib

# Load trained model
model = joblib.load("svm_model.pkl")


# Feature Extraction Function
def extract_features(url):

    length = len(url)

    dots = url.count('.')

    hyphens = url.count('-')

    digits = sum(c.isdigit() for c in url)

    at_symbol = 1 if '@' in url else 0

    https = 1 if url.startswith('https') else 0

    return [
        length,
        dots,
        hyphens,
        digits,
        at_symbol,
        https
    ]


# Open Webcam
cap = cv2.VideoCapture(0)

# Prevent same QR from being processed repeatedly
last_url = ""

print("Webcam Started...")
print("Press ESC to Exit")

while True:

    ret, frame = cap.read()

    if not ret:
        print("Failed to access webcam")
        break

    qr_codes = decode(frame)

    for qr in qr_codes:

        url = qr.data.decode()

        # Process only if new QR
        if url != last_url:

            last_url = url

            print("\nQR Detected:")
            print(url)

            features = extract_features(url)

            prediction = model.predict([features])

            if prediction[0] == 0:

                result = "SAFE"

            else:

                result = "PHISHING"

            print("Prediction:", result)

        # Draw rectangle around QR code
        points = qr.polygon

        if len(points) == 4:

            pts = [(p.x, p.y) for p in points]

            for i in range(4):

                cv2.line(
                    frame,
                    pts[i],
                    pts[(i + 1) % 4],
                    (0, 255, 0),
                    2
                )

            # Show result on frame
            cv2.putText(
                frame,
                result if 'result' in locals() else "",
                (pts[0][0], pts[0][1] - 10),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.8,
                (0, 0, 255),
                2
            )

    cv2.imshow("Secure QR Scanner", frame)

    key = cv2.waitKey(1)

    if key == 27:  # ESC key
        break

cap.release()

cv2.destroyAllWindows()
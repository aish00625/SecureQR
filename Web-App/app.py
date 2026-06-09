from flask import Flask, render_template, request
import cv2
from pyzbar.pyzbar import decode
import joblib
import os

UPLOAD_FOLDER = "uploads"

os.makedirs(
    UPLOAD_FOLDER,
    exist_ok=True
)

app =Flask(__name__)

model = joblib.load("model\svm_model.pkl")

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

@app.route("/", methods = ["GET", "POST"])

def home():

    result = ""
    url = ""

    if request.method =="POST":

        file = request.files["qrfile"]

        filepath = os.path.join(UPLOAD_FOLDER,file.filename)

        file.save(filepath)

        image = cv2.imread(filepath)
        

        if image is None:
            return render_template(
                "index.html",
                result="Invalid image file",
                url=""
            )
            


        codes = decode(image)

        if codes:

            url = codes[0].data.decode()

            features = extract_features(url)

            prediction = model.predict([features])

            if prediction[0] == 0:
                result = "SAFE"
            else:
                result = "PHISHING"

        else:

            result = "NO QR FOUND"
    return render_template(
        "index.html",
        result = result,
        url = url
    )

if __name__ == "__main__":
    app.run(debug = True)
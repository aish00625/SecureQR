import tkinter as tk
from tkinter import filedialog, messagebox

import cv2
from pyzbar.pyzbar import decode

import joblib


# Load trained model
model = joblib.load("svm_model.pkl")


# Feature extraction
def extract_features(url):

    length = len(url)

    dots = url.count('.')

    https = 1 if url.startswith("https") else 0

    return [length, dots, https]


# Upload and scan
def upload_qr():

    file_path = filedialog.askopenfilename(
        filetypes=[("Image Files", "*.png *.jpg *.jpeg *.webp")]
    )

    if not file_path:
        return

    file_label.config(text=file_path)

    image = cv2.imread(file_path)

    qr_codes = decode(image)

    if not qr_codes:

        messagebox.showerror(
            "Error",
            "No QR Code Found"
        )

        return

    url = qr_codes[0].data.decode()

    url_label.config(text=url)

    features = extract_features(url)

    prediction = model.predict([features])

    if prediction[0] == 0:

        result_label.config(
            text="SAFE"
        )

        messagebox.showinfo(
            "Result",
            "SAFE URL"
        )

    else:

        result_label.config(
            text="PHISHING"
        )

        messagebox.showwarning(
            "Warning",
            "PHISHING URL DETECTED!"
        )


# Main window
window = tk.Tk()

window.title("Secure QR Scanner")

window.geometry("700x400")


heading = tk.Label(
    window,
    text="Secure QR Scanner",
    font=("Arial", 18)
)

heading.pack(pady=10)


upload_button = tk.Button(
    window,
    text="Upload QR",
    command=upload_qr
)

upload_button.pack(pady=10)


file_label = tk.Label(
    window,
    text="No file selected"
)

file_label.pack()


url_title = tk.Label(
    window,
    text="Extracted URL:"
)

url_title.pack(pady=10)


url_label = tk.Label(
    window,
    text="-"
)

url_label.pack()


status_title = tk.Label(
    window,
    text="Status:"
)

status_title.pack(pady=10)


result_label = tk.Label(
    window,
    text="-",
    font=("Arial", 14)
)

result_label.pack()


window.mainloop()
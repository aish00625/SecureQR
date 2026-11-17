"""Minimal Tkinter desktop client for SecureQR (optional).

Uses exactly the same decoder, heuristics and ML model as the web app.
Run from the project root:  python -m desktop_app.qr_scanner_gui
"""
import tkinter as tk
from tkinter import filedialog, messagebox
from pathlib import Path

from secureqr.config import Config
from secureqr.core.analyzer import analyze_payload
from secureqr.core.predictor import Predictor
from secureqr.core.qr_decoder import ImageValidationError, decode_qr, validate_image_bytes

predictor = Predictor(Config.MODEL_PATH)
COLORS = {"HIGH": "#dc2626", "MEDIUM": "#d97706", "LOW": "#059669"}


def scan_file():
    path = filedialog.askopenfilename(filetypes=[("Images", "*.png *.jpg *.jpeg *.webp *.bmp")])
    if not path:
        return
    file_label.config(text=path)
    try:
        img = validate_image_bytes(Path(path).read_bytes(), path, Config.ALLOWED_EXTENSIONS,
                                   20 * 1024 * 1024, Config.MAX_IMAGE_PIXELS)
    except ImageValidationError as exc:
        messagebox.showerror("Invalid image", str(exc))
        return
    decoded = decode_qr(img)
    if not decoded.found:
        messagebox.showerror("No QR code", "No QR code was found in this image.")
        return
    r = analyze_payload(decoded.payloads[0], predictor)
    content_label.config(text=r["url"] or r["raw_content"])
    ml = r["ml"] or {}
    ml_label.config(text=f"ML: {ml.get('label', 'n/a')} ({ml.get('phishing_probability', 0):.0%})"
                    if ml.get("available") else "ML: not applicable")
    heur = r["heuristics"]
    heur_label.config(text=f"Rules: {heur['score']}/100, {len(heur['findings'])} warnings" if heur else "Rules: n/a")
    risk_label.config(text=f"{r['risk_level']} RISK", fg=COLORS[r["risk_level"]])


window = tk.Tk()
window.title("SecureQR")
window.geometry("720x380")
tk.Label(window, text="SecureQR", font=("Segoe UI", 18, "bold")).pack(pady=12)
tk.Button(window, text="Open QR image…", command=scan_file).pack(pady=6)
file_label = tk.Label(window, text="No file selected", fg="#64748b")
file_label.pack()
content_label = tk.Label(window, text="-", font=("Consolas", 11), wraplength=660)
content_label.pack(pady=12)
ml_label = tk.Label(window, text="")
ml_label.pack()
heur_label = tk.Label(window, text="")
heur_label.pack()
risk_label = tk.Label(window, text="", font=("Segoe UI", 16, "bold"))
risk_label.pack(pady=12)

if __name__ == "__main__":
    window.mainloop()

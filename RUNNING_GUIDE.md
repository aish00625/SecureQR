# Running SecureQR on Windows 11 (PowerShell + VS Code)

Every command below runs in **PowerShell** (Windows PowerShell 5.1 or PowerShell 7) from the project folder, e.g. `C:\Users\<you>\SecureQR`. In VS Code: **Terminal → New Terminal** opens PowerShell in the project folder.

## 1 · Prerequisites (one time)

- **Python 3.11–3.14** (3.12 or 3.13 recommended) from python.org. During setup tick *"Add python.exe to PATH"*. The installer also adds the `py` launcher.
- Optional: **VS Code** with the *Python* extension (it will suggest it when you open the folder).

Check:

```powershell
py --list          # shows installed Pythons
python --version
```

## 2 · Open the project

```powershell
cd $HOME\SecureQR
code .             # opens VS Code here (optional)
```

## 3A · One-command setup (recommended)

```powershell
powershell -ExecutionPolicy Bypass -File .\setup.ps1
```

This will:
1. pick a supported Python (3.13 → 3.12 → 3.14 → 3.11);
2. create `.\venv`;
3. install `requirements.txt`;
4. create `.env` from `.env.example` with a random `SECUREQR_SECRET_KEY`;
5. run `scripts\check_setup.py`, which should end with **"Ready for the demo."**

`-ExecutionPolicy Bypass` applies only to that one command; it does not change your system settings. Running the script again is safe.

## 3B · Manual setup (same result)

```powershell
py -3.13 -m venv venv              # or: python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
copy .env.example .env
python -c "import secrets; print(secrets.token_hex(32))"
notepad .env                       # paste the value after SECUREQR_SECRET_KEY=
python scripts\check_setup.py
```

If `Activate.ps1` says *"running scripts is disabled on this system"*:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\venv\Scripts\Activate.ps1
```

## 4 · Start the application

```powershell
powershell -ExecutionPolicy Bypass -File .\run.ps1
# or, with the venv activated:
python run.py
```

Open **http://127.0.0.1:5000** in Chrome or Edge. Stop the server with `Ctrl+C`. Use another port with `python run.py --port 8080`.

**In VS Code:** press **F5** → *SecureQR: run web app* (debugging works: breakpoints in `secureqr\views.py` etc.). If VS Code asks for an interpreter, choose `.\venv\Scripts\python.exe` (Ctrl+Shift+P → *Python: Select Interpreter*).

## 5 · Try the demo QR codes

**Scan → Image**, then upload files from the `demo_qr` folder. For the webcam, open a demo PNG on your phone and hold it up to the laptop camera (**Scan → Camera → Start camera**, then allow camera access when Edge/Chrome asks).

## 6 · Run the tests

```powershell
powershell -ExecutionPolicy Bypass -File .\test.ps1
# or, with the venv activated:
python -m pytest
```

Expected: `155 passed` in roughly 10–40 seconds. In VS Code the tests also appear in the **Testing** panel (flask icon).

## 7 · (Optional) Retrain the model

The trained model is already in `model\`. Retrain only if you change the features or the model fails to load (e.g. after installing a different scikit-learn version):

```powershell
python -m secureqr.ml.train                          # ~15-25 min; rewrites model\*
python -m secureqr.ml.train --quick --out tmp_model  # ~1 min smoke run, leaves model\ alone
```

## 8 · Optional desktop tools

```powershell
python -m desktop_app.qr_scanner_gui        # Tkinter window: open a QR image
python -m desktop_app.webcam_qr_scanner     # OpenCV webcam window (ESC to quit)
```

## Demo-day checklist

1. `python scripts\check_setup.py` → "Ready for the demo."
2. `python run.py` → open http://127.0.0.1:5000.
3. Allow the camera once before presenting.
4. Optional: clear history from the History page.

## Troubleshooting

| Problem | Fix |
|---|---|
| `python` opens the Microsoft Store | Install Python from python.org, or turn off *App execution aliases* for python in Settings → Apps → Advanced app settings. Use `py -3.13` instead of `python`. |
| `setup.ps1 cannot be loaded … not digitally signed` | Run it as shown: `powershell -ExecutionPolicy Bypass -File .\setup.ps1`. If you extracted the project from a downloaded ZIP, you can also run `Get-ChildItem -Recurse | Unblock-File` once. |
| `ModuleNotFoundError: secureqr` | Run commands from the project root (the folder containing `run.py`) with the venv activated. |
| check_setup says scikit-learn is not 1.9.1, or results show "Model unavailable" | `pip install -r requirements.txt` inside the venv, or retrain (step 7). |
| `pip install` fails / tries to compile packages | Use 64-bit Python 3.11–3.14 (not 3.15 or newer, which may not have pre-built wheels yet) and upgrade pip. |
| Camera: "permission was denied" | Click the camera icon in the address bar → Allow, then *Start camera* again. Also check Windows Settings → Privacy & security → Camera → "Let desktop apps access your camera". |
| Camera busy | Close Teams/Zoom/the Camera app, which may be holding the webcam. |
| Port 5000 already in use | `python run.py --port 5050` |
| Windows Firewall prompt | Not needed for local use; the server listens only on 127.0.0.1. You can click Cancel. |
| Reset history | Stop the server and delete the `instance` folder, or use *Clear history* in the app. |

## Where things are stored

| What | Where (git-ignored) |
|---|---|
| Scan history | `instance\secureqr.db` |
| Logs | `logs\secureqr.log` |
| Settings / secret key | `.env` |
| Backup of the original v1 project | `_backup\` |

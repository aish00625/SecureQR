"""Start the SecureQR web application.

    python run.py                 # http://127.0.0.1:5000
    python run.py --port 8080
    python run.py --host 0.0.0.0  # expose on your LAN (e.g. to test the webcam from a phone)
"""
import argparse
import os

from secureqr import create_app


def main():
    ap = argparse.ArgumentParser(description="Run the SecureQR server")
    ap.add_argument("--host", default=os.getenv("SECUREQR_HOST", "127.0.0.1"))
    ap.add_argument("--port", type=int, default=int(os.getenv("SECUREQR_PORT", "5000")))
    args = ap.parse_args()
    app = create_app()
    print(f"\n  SecureQR running at http://{args.host}:{args.port}  (Ctrl+C to stop)\n")
    app.run(host=args.host, port=args.port, debug=app.config["DEBUG"], use_reloader=False)


if __name__ == "__main__":
    main()

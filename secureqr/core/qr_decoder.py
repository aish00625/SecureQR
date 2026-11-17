"""Secure image validation and robust multi-pass QR decoding.

Uploaded images are processed entirely in memory - nothing is written to
disk, so path traversal / stored-file attacks are not possible.

Decoding strategy (stops at the first pass that yields data):
  1. pyzbar (if installed)               - fast, tolerant
  2. OpenCV QRCodeDetector on the image  - built into opencv-python
  3. OpenCV on enhanced variants         - min-channel + Otsu threshold and
     morphological erosion, which recovers coloured and "dotted" artistic QR
     codes that the plain detector misses.
"""
from __future__ import annotations

import io
import logging
from dataclasses import dataclass, field

import cv2
import numpy as np
from PIL import Image, UnidentifiedImageError

log = logging.getLogger(__name__)

try:  # optional backend
    from pyzbar.pyzbar import ZBarSymbol
    from pyzbar.pyzbar import decode as _zbar_decode
    PYZBAR_AVAILABLE = True
except Exception:  # ImportError or missing zbar shared library
    PYZBAR_AVAILABLE = False

MAGIC = {
    "png": [b"\x89PNG\r\n\x1a\n"],
    "jpg": [b"\xff\xd8\xff"],
    "jpeg": [b"\xff\xd8\xff"],
    "bmp": [b"BM"],
    "webp": [b"RIFF"],
}
PIL_FORMATS = {"PNG", "JPEG", "BMP", "WEBP", "MPO"}
WORK_MAX_SIDE = 1600
FULL_MAX_SIDE = 3000


class ImageValidationError(ValueError):
    """Raised when an upload is not an acceptable image."""


@dataclass
class DecodeResult:
    payloads: list[str] = field(default_factory=list)
    method: str | None = None
    width: int = 0
    height: int = 0

    @property
    def found(self) -> bool:
        return bool(self.payloads)


def _extension(filename: str) -> str:
    return filename.rsplit(".", 1)[-1].lower() if filename and "." in filename else ""


def validate_image_bytes(data: bytes, filename: str, allowed: set[str],
                         max_bytes: int, max_pixels: int) -> np.ndarray:
    """Validate an upload and return it as a BGR numpy array.

    Checks: non-empty, size limit, extension allow-list, magic bytes,
    Pillow format verification, pixel-count limit (decompression bombs).
    """
    if not data:
        raise ImageValidationError("The uploaded file is empty.")
    if len(data) > max_bytes:
        raise ImageValidationError(f"File is too large (max {max_bytes // (1024 * 1024)} MB).")
    ext = _extension(filename)
    if ext not in allowed:
        raise ImageValidationError(
            "Unsupported file type. Allowed: " + ", ".join(sorted(allowed)).upper() + ".")
    if not any(data.startswith(m) for m in MAGIC.get(ext, [])):
        raise ImageValidationError("File content does not match its extension.")
    if ext == "webp" and data[8:12] != b"WEBP":
        raise ImageValidationError("File content does not match its extension.")
    try:
        with Image.open(io.BytesIO(data)) as im:
            if im.format not in PIL_FORMATS:
                raise ImageValidationError("Unsupported image format.")
            w, h = im.size
            if w * h > max_pixels:
                raise ImageValidationError("Image dimensions are too large.")
            im.verify()
    except ImageValidationError:
        raise
    except (UnidentifiedImageError, OSError, SyntaxError, Image.DecompressionBombError) as exc:
        raise ImageValidationError("The file is not a valid image.") from exc
    arr = cv2.imdecode(np.frombuffer(data, dtype=np.uint8), cv2.IMREAD_COLOR)
    if arr is None:
        raise ImageValidationError("The image could not be decoded.")
    return arr


def _resize(img: np.ndarray, max_side: int) -> np.ndarray:
    h, w = img.shape[:2]
    scale = max_side / max(h, w)
    if scale >= 1:
        return img
    return cv2.resize(img, (int(w * scale), int(h * scale)), interpolation=cv2.INTER_AREA)


def _cv_decode(img: np.ndarray) -> list[str]:
    out: list[str] = []
    for det in (cv2.QRCodeDetector(), cv2.QRCodeDetectorAruco()):
        try:
            ok, texts, _, _ = det.detectAndDecodeMulti(img)
            if ok:
                out = [t for t in texts if t]
            if not out:
                text, _, _ = det.detectAndDecode(img)
                out = [text] if text else []
        except cv2.error:
            continue
        if out:
            return out
    return out


def _zbar(img: np.ndarray) -> list[str]:
    if not PYZBAR_AVAILABLE:
        return []
    try:
        res = _zbar_decode(img, symbols=[ZBarSymbol.QRCODE])
    except Exception:  # pragma: no cover - defensive
        return []
    return [r.data.decode("utf-8", errors="replace") for r in res if r.data]


def _binarize(gray: np.ndarray, k: int) -> np.ndarray:
    if k > 1:
        gray = cv2.erode(gray, np.ones((k, k), np.uint8))
    return cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)[1]


def _variants(work: np.ndarray, full: np.ndarray, fast: bool):
    """Yield (name, image) pairs in order of cost.

    ``work`` is the image capped at WORK_MAX_SIDE; ``full`` is the image at up
    to FULL_MAX_SIDE, used for the erosion passes that recover dotted/artistic
    QR codes (the dots must be merged at roughly their native resolution).
    """
    yield "opencv", work
    gray = cv2.cvtColor(work, cv2.COLOR_BGR2GRAY)
    yield "opencv-otsu", _binarize(gray, 1)
    if fast:
        return
    mn = work.min(axis=2)  # coloured modules become dark, white stays white
    yield "opencv-minchannel", _binarize(mn, 1)
    for k in (2, 3, 4):
        yield f"opencv-erode{k}", _binarize(mn, k)
    if full.shape != work.shape:
        mn_full = full.min(axis=2)
        for k in (3, 4, 5, 6, 7):
            yield f"opencv-full-erode{k}", _binarize(mn_full, k)


def decode_qr(img: np.ndarray, fast: bool = False) -> DecodeResult:
    """Decode all QR codes in a BGR image. ``fast`` limits work for webcam frames."""
    h, w = img.shape[:2]
    result = DecodeResult(width=w, height=h)
    work = _resize(img, WORK_MAX_SIDE)

    payloads = _zbar(work)
    if payloads:
        result.payloads, result.method = _dedupe(payloads), "pyzbar"
        return result
    full = _resize(img, FULL_MAX_SIDE)
    for name, variant in _variants(work, full, fast):
        payloads = _cv_decode(variant)
        if payloads:
            result.payloads, result.method = _dedupe(payloads), name
            return result
    return result


def _dedupe(items: list[str]) -> list[str]:
    seen, out = set(), []
    for i in items:
        if i not in seen:
            seen.add(i)
            out.append(i)
    return out


def backends() -> list[str]:
    return (["pyzbar"] if PYZBAR_AVAILABLE else []) + ["opencv"]

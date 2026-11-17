import cv2
import numpy as np
import pytest

from secureqr.core.qr_decoder import ImageValidationError, decode_qr, validate_image_bytes
from tests.conftest import ROOT, blank_png, make_qr

ALLOWED = {"png", "jpg", "jpeg", "webp", "bmp"}
MB = 1024 * 1024


def load(data: bytes, name="x.png", max_bytes=5 * MB, max_pixels=40_000_000):
    return validate_image_bytes(data, name, ALLOWED, max_bytes, max_pixels)


@pytest.mark.parametrize("fmt,name", [(".png", "a.png"), (".jpg", "a.jpg"), (".bmp", "a.bmp"), (".webp", "a.webp")])
def test_decodes_generated_qr_in_all_formats(fmt, name):
    img = load(make_qr("https://example.com/path?q=1", fmt=fmt), name)
    res = decode_qr(img)
    assert res.found
    assert res.payloads == ["https://example.com/path?q=1"]


def test_decodes_coloured_qr():
    img = load(make_qr("https://colour.example.org", color=(40, 40, 220)))
    assert decode_qr(img).payloads == ["https://colour.example.org"]


def test_decodes_stylised_dotted_sample_from_repo():
    data = (ROOT / "demo_qr" / "sample_stylised_qr.webp").read_bytes()
    res = decode_qr(load(data, "sample.webp", max_bytes=10 * MB))
    assert res.payloads == ["https://qr-codes.io/dX97eV"]


def test_multiple_codes_in_one_image():
    a = cv2.imdecode(np.frombuffer(make_qr("https://one.example"), np.uint8), cv2.IMREAD_COLOR)
    b = cv2.imdecode(np.frombuffer(make_qr("https://two.example"), np.uint8), cv2.IMREAD_COLOR)
    h = max(a.shape[0], b.shape[0])
    canvas = np.full((h, a.shape[1] + b.shape[1] + 40, 3), 255, np.uint8)
    canvas[:a.shape[0], :a.shape[1]] = a
    canvas[:b.shape[0], a.shape[1] + 40:] = b
    assert set(decode_qr(canvas).payloads) == {"https://one.example", "https://two.example"}


def test_no_qr_returns_empty():
    res = decode_qr(load(blank_png()))
    assert not res.found and res.payloads == []


def test_non_url_payload_round_trip():
    payload = "WIFI:T:WPA;S:CafeNet;P:secret123;;"
    assert decode_qr(load(make_qr(payload))).payloads == [payload]


@pytest.mark.parametrize("data,name,msg", [
    (b"", "a.png", "empty"),
    (b"\x89PNG\r\n\x1a\n" + b"0" * 50, "a.gif", "Unsupported file type"),
    (b"\x89PNG\r\n\x1a\n" + b"0" * 50, "noextension", "Unsupported file type"),
    (b"GIF89a....", "a.png", "does not match"),
    (b"MZ\x90\x00 fake exe", "a.jpg", "does not match"),
    (b"RIFF\x00\x00\x00\x00WAVEfmt ", "a.webp", "does not match"),
    (b"\x89PNG\r\n\x1a\n" + b"corrupted data here", "a.png", "not a valid image"),
])
def test_validation_rejects_bad_files(data, name, msg):
    with pytest.raises(ImageValidationError, match=msg):
        load(data, name)


def test_validation_rejects_oversized_bytes():
    with pytest.raises(ImageValidationError, match="too large"):
        load(make_qr("x"), max_bytes=100)


def test_validation_rejects_too_many_pixels():
    with pytest.raises(ImageValidationError, match="dimensions"):
        load(blank_png(2000, 2000), max_pixels=1_000_000)


def test_svg_script_disguised_as_png_rejected():
    with pytest.raises(ImageValidationError):
        load(b"<svg onload=alert(1)>", "evil.png")

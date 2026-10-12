"""
FORESIGHT - Universal Dynamic QR Code Decoder
Decodes ANY valid QR code from raw image files/bytes.
Uses dual-engine decoding (zxing-cpp + OpenCV) with adaptive image pre-processing.
Works with any camera capture, screenshot, or uploaded image file.
"""

import io
from typing import Optional, Tuple
from PIL import Image, ImageOps
import numpy as np
import zxingcpp
import cv2

def decode_qr_image(image_bytes_or_path) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Decodes QR code data from image bytes or file path.
    Returns (success, decoded_text, method_used).
    Works dynamically with ANY valid QR code.
    """
    try:
        if isinstance(image_bytes_or_path, (str, bytes, bytearray)):
            if isinstance(image_bytes_or_path, str):
                pil_img = Image.open(image_bytes_or_path)
            else:
                pil_img = Image.open(io.BytesIO(image_bytes_or_path))
        elif isinstance(image_bytes_or_path, Image.Image):
            pil_img = image_bytes_or_path
        else:
            return False, None, "Invalid image input type"

        # Ensure RGB format
        if pil_img.mode not in ("RGB", "L"):
            pil_img = pil_img.convert("RGB")

    except Exception as e:
        return False, None, f"Image parsing error: {str(e)}"

    # --- Strategy 1: Direct zxing-cpp decode on original image ---
    try:
        results = zxingcpp.read_barcodes(pil_img)
        for r in results:
            text = (r.text or "").strip()
            if text:
                return True, text, "zxing-cpp (direct)"
    except Exception:
        pass

    # --- Strategy 2: OpenCV QRCodeDetector on BGR array ---
    try:
        np_img = np.array(pil_img)
        if len(np_img.shape) == 3 and np_img.shape[2] == 3:
            bgr_img = cv2.cvtColor(np_img, cv2.COLOR_RGB2BGR)
        else:
            bgr_img = np_img
        detector = cv2.QRCodeDetector()
        val, points, straight_qrcode = detector.detectAndDecode(bgr_img)
        val = (val or "").strip()
        if val:
            return True, val, "opencv (direct)"
    except Exception:
        pass

    # --- Strategy 3: Multi-scale Pre-processing for high-res / phone camera photos ---
    # Phone camera photos can be 4000x3000px, which causes some decoders to miss small QR codes
    max_dim = max(pil_img.size)
    if max_dim > 1200:
        scale = 1200 / max_dim
        new_size = (int(pil_img.width * scale), int(pil_img.height * scale))
        resized = pil_img.resize(new_size, Image.Resampling.LANCZOS)
        try:
            results = zxingcpp.read_barcodes(resized)
            for r in results:
                text = (r.text or "").strip()
                if text:
                    return True, text, "zxing-cpp (scaled 1200px)"
        except Exception:
            pass

    # --- Strategy 4: Grayscale + Contrast Enhancement (Histogram Equalization) ---
    try:
        gray_pil = ImageOps.grayscale(pil_img)
        results = zxingcpp.read_barcodes(gray_pil)
        for r in results:
            text = (r.text or "").strip()
            if text:
                return True, text, "zxing-cpp (grayscale)"

        # Otsu thresholding via OpenCV
        gray_np = np.array(gray_pil)
        _, thresh = cv2.threshold(gray_np, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        results = zxingcpp.read_barcodes(Image.fromarray(thresh))
        for r in results:
            text = (r.text or "").strip()
            if text:
                return True, text, "zxing-cpp (otsu binarized)"
    except Exception:
        pass

    # --- Strategy 5: Inverted Colors (e.g. White QR on dark background) ---
    try:
        inverted = ImageOps.invert(pil_img.convert("RGB"))
        results = zxingcpp.read_barcodes(inverted)
        for r in results:
            text = (r.text or "").strip()
            if text:
                return True, text, "zxing-cpp (inverted)"
    except Exception:
        pass

    return False, None, "No QR code detected in image"

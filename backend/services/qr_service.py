"""
Email QR Code & QRishing Analyzer Service
Extracts embedded, inline, and attached QR code images from email messages,
decodes QR payloads using OpenCV, Pyzbar, and pure-python PIL matrix fallback.
"""

import re
import io
import base64
import logging
import numpy as np
from typing import Dict, List, Optional
from PIL import Image

try:
    import cv2
    CV2_AVAILABLE = True
except ImportError:
    CV2_AVAILABLE = False

try:
    from pyzbar import pyzbar
    PYZBAR_AVAILABLE = True
except Exception:
    PYZBAR_AVAILABLE = False

from backend.utils.url_utils import extract_urls

logger = logging.getLogger(__name__)


def _decode_pure_python_qr(pil_img: Image.Image) -> List[str]:
    """
    Pure Python QR code matrix decoder fallback using PIL image sampling.
    Decodes standard QR codes (Byte mode, Version 1-10) without native binaries.
    """
    try:
        img = pil_img.convert('L')
        bw = img.point(lambda p: 0 if p < 128 else 255)
        w, h = bw.size
        pixels = bw.load()

        # Find bounding box of non-white QR area
        min_x, min_y, max_x, max_y = w, h, 0, 0
        for y in range(h):
            for x in range(w):
                if pixels[x, y] == 0:
                    if x < min_x: min_x = x
                    if x > max_x: max_x = x
                    if y < min_y: min_y = y
                    if y > max_y: max_y = y

        if min_x >= max_x or min_y >= max_y:
            return []

        qr_w = max_x - min_x + 1
        qr_h = max_y - min_y + 1

        # Determine module size from top-left finder pattern border (7 modules wide)
        start_x = min_x
        start_y = min_y
        black_len = 0
        while start_x <= max_x and pixels[start_x, start_y] == 0:
            black_len += 1
            start_x += 1

        if black_len == 0:
            return []

        mod_size = black_len / 7.0
        if mod_size < 1:
            mod_size = 1.0

        grid_size = int(round(qr_w / mod_size))
        if grid_size < 21:
            return []

        # Sample grid matrix (True = black module, False = white module)
        matrix = [[False] * grid_size for _ in range(grid_size)]
        for r in range(grid_size):
            for c in range(grid_size):
                px = int(min_x + (c + 0.5) * mod_size)
                py = int(min_y + (r + 0.5) * mod_size)
                if 0 <= px < w and 0 <= py < h:
                    matrix[r][c] = (pixels[px, py] == 0)

        # Read 15-bit format info around top-left finder pattern
        fmt_coords = [
            (8, 0), (8, 1), (8, 2), (8, 3), (8, 4), (8, 5), (8, 7), (8, 8),
            (7, 8), (5, 8), (4, 8), (3, 8), (2, 8), (1, 8), (0, 8)
        ]
        raw_fmt = 0
        for i, (r, c) in enumerate(fmt_coords):
            if matrix[r][c]:
                raw_fmt |= (1 << (14 - i))

        raw_fmt ^= 0x5412
        mask_pattern = (raw_fmt >> 10) & 0x07

        def is_masked(r, c):
            if mask_pattern == 0: return (r + c) % 2 == 0
            if mask_pattern == 1: return r % 2 == 0
            if mask_pattern == 2: return c % 3 == 0
            if mask_pattern == 3: return (r + c) % 3 == 0
            if mask_pattern == 4: return ((r // 2) + (c // 3)) % 2 == 0
            if mask_pattern == 5: return ((r * c) % 2 + (r * c) % 3) == 0
            if mask_pattern == 6: return (((r * c) % 2 + (r * c) % 3) % 2) == 0
            if mask_pattern == 7: return (((r + c) % 2 + (r * c) % 3) % 2) == 0
            return False

        def is_function_pattern(r, c):
            if r < 9 and c < 9: return True
            if r < 9 and c >= grid_size - 8: return True
            if r >= grid_size - 8 and c < 9: return True
            if r == 6 or c == 6: return True
            if grid_size > 21 and (grid_size - 9 <= r <= grid_size - 5) and (grid_size - 9 <= c <= grid_size - 5):
                return True
            return False

        bits = []
        col = grid_size - 1
        upward = True
        while col > 0:
            if col == 6:
                col -= 1
            for r_idx in range(grid_size):
                r = (grid_size - 1 - r_idx) if upward else r_idx
                for c in (col, col - 1):
                    if not is_function_pattern(r, c):
                        val = matrix[r][c]
                        if is_masked(r, c):
                            val = not val
                        bits.append(1 if val else 0)
            upward = not upward
            col -= 2

        def get_bits(start, count):
            v = 0
            for i in range(count):
                if start + i < len(bits):
                    v = (v << 1) | bits[start + i]
            return v

        mode = get_bits(0, 4)
        if mode == 4:  # Byte mode
            char_count = get_bits(4, 8)
            data_bytes = bytearray()
            idx = 12
            for _ in range(char_count):
                b = get_bits(idx, 8)
                data_bytes.append(b)
                idx += 8
            decoded = data_bytes.decode('utf-8', errors='ignore').strip()
            if decoded:
                return [decoded]
    except Exception as e:
        logger.debug(f"Pure python QR decode error: {e}")
    return []


class QREmailAnalyzer:
    """Extract and decode QR codes from email contents and attachments"""

    DATA_URI_PATTERN = re.compile(r'data:image/[a-zA-Z]+;base64,([A-Za-z0-9+/=\s]+)', re.IGNORECASE)

    @classmethod
    def decode_qr_image(cls, image_bytes: bytes) -> List[str]:
        """
        Decode QR code(s) from raw image bytes.
        Returns list of decoded payload strings.
        """
        if not image_bytes:
            return []

        payloads = []

        # Engine 1: OpenCV QRCodeDetector
        if CV2_AVAILABLE:
            try:
                np_arr = np.frombuffer(image_bytes, np.uint8)
                img = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
                if img is not None:
                    detector = cv2.QRCodeDetector()
                    data, points, _ = detector.detectAndDecode(img)
                    if data and data.strip():
                        payloads.append(data.strip())
                    else:
                        try:
                            retval, decoded_info, points, _ = detector.detectAndDecodeMulti(img)
                            if retval:
                                for info in decoded_info:
                                    if info and info.strip():
                                        payloads.append(info.strip())
                        except Exception:
                            pass
            except Exception as e:
                logger.debug(f"OpenCV QR decode error: {e}")

        # Engine 2: Pyzbar
        if not payloads and PYZBAR_AVAILABLE:
            try:
                pil_img = Image.open(io.BytesIO(image_bytes))
                decoded_objects = pyzbar.decode(pil_img)
                for obj in decoded_objects:
                    data = obj.data.decode('utf-8', errors='ignore').strip()
                    if data:
                        payloads.append(data)
            except Exception as e:
                logger.debug(f"Pyzbar QR decode error: {e}")

        # Engine 3: Pure Python PIL matrix decoder fallback
        if not payloads:
            try:
                pil_img = Image.open(io.BytesIO(image_bytes))
                pure_results = _decode_pure_python_qr(pil_img)
                if pure_results:
                    payloads.extend(pure_results)
            except Exception as e:
                logger.debug(f"PIL fallback QR error: {e}")

        return list(dict.fromkeys(payloads))

    @classmethod
    def extract_qr_from_email(cls, email_data: dict) -> Dict:
        """
        Scan email structure (body, attachments, raw_body) for QR codes.
        """
        all_payloads = []
        qr_details = []

        # 1. Embedded base64 data URIs
        body_text = (email_data.get('raw_body', '') or '') + ' ' + (email_data.get('body', '') or '')
        for match in cls.DATA_URI_PATTERN.finditer(body_text):
            try:
                b64_str = match.group(1).replace('\n', '').replace('\r', '').strip()
                img_bytes = base64.b64decode(b64_str)
                payloads = cls.decode_qr_image(img_bytes)
                for p in payloads:
                    all_payloads.append(p)
                    qr_details.append({'source': 'embedded_data_uri', 'payload': p})
            except Exception as e:
                logger.debug(f"Failed to decode base64 data URI image: {e}")

        # 2. Attachments
        attachments = email_data.get('attachments', [])
        for att in attachments:
            filename = att.get('filename', '').lower()
            content = att.get('content')
            if not content:
                continue

            if isinstance(content, str):
                try:
                    img_bytes = base64.b64decode(content)
                except Exception:
                    img_bytes = content.encode('utf-8', errors='ignore')
            else:
                img_bytes = content

            if any(filename.endswith(ext) for ext in ['.png', '.jpg', '.jpeg', '.bmp', '.gif', '.webp']) or not filename:
                payloads = cls.decode_qr_image(img_bytes)
                for p in payloads:
                    all_payloads.append(p)
                    qr_details.append({'source': f"attachment:{att.get('filename', 'image')}", 'payload': p})

        qr_urls = []
        for p in all_payloads:
            extracted = extract_urls(p)
            if extracted:
                qr_urls.extend(extracted)
            elif p.startswith(('http://', 'https://', 'www.')):
                qr_urls.append(p)

        qr_urls = list(dict.fromkeys(qr_urls))
        all_payloads = list(dict.fromkeys(all_payloads))

        qrishing_threat = len(qr_urls) > 0

        return {
            'qr_detected': len(all_payloads) > 0,
            'qr_count': len(all_payloads),
            'payloads': all_payloads,
            'urls_found': qr_urls,
            'qrishing_threat': qrishing_threat,
            'details': qr_details,
        }

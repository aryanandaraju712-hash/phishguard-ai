"""
QR-Code URL Extraction and Threat Analysis Service.
Safely ingests and decodes QR-code images using OpenCV and PIL,
validates upload size and image dimensions, extracts embedded content
without opening or visiting destination URLs, and pipes extracted URLs
into the static PhishGuard URL triage engine.
"""

import io
import re
import os
import uuid
import tempfile
import unicodedata
from typing import Dict, Any, List, Tuple, Optional
from fastapi import HTTPException, status
from PIL import Image, UnidentifiedImageError
import numpy as np
import cv2

from app.services.url_analyzer import (
    analyze_url_comprehensive,
    defang_url
)
from app.services.report_generator import defang_url_safe

# Maximum allowable file size for QR image upload: 5 MB
MAX_UPLOAD_SIZE_BYTES = 5 * 1024 * 1024

# Allowed MIME content types
ALLOWED_MIME_TYPES = {
    "image/png", "image/jpeg", "image/pjpeg", "image/webp",
    "image/bmp", "image/x-ms-bmp", "image/gif"
}

# Allowed file extensions
ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp", ".bmp", ".gif"}

# Dimension constraints to prevent decompression bombs (e.g. pixel floods)
MAX_IMAGE_WIDTH = 4096
MAX_IMAGE_HEIGHT = 4096
MIN_IMAGE_DIMENSION = 10


def validate_image_upload(
    file_bytes: bytes,
    filename: Optional[str] = "upload.png",
    content_type: Optional[str] = None
) -> Tuple[Image.Image, str]:
    """
    Validates uploaded image file bytes for size, format, extension, and dimensions.
    Raises descriptive HTTPExceptions on validation failures.
    """
    if not file_bytes:
        raise HTTPException(
            status_code=getattr(status, "HTTP_422_UNPROCESSABLE_CONTENT", 422),
            detail="Uploaded file is empty."
        )

    # 1. File size check
    if len(file_bytes) > MAX_UPLOAD_SIZE_BYTES:
        raise HTTPException(
            status_code=getattr(status, "HTTP_413_CONTENT_TOO_LARGE", 413),
            detail=f"Uploaded image exceeds maximum allowable size (5MB). Current size: {len(file_bytes) / (1024 * 1024):.2f}MB"
        )

    # 2. Extension check
    clean_filename = os.path.basename(filename or "upload.png")
    _, ext = os.path.splitext(clean_filename.lower())
    if ext and ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail=f"Unsupported file extension '{ext}'. Supported formats: PNG, JPEG, WebP, BMP, GIF."
        )

    # 3. MIME type check if provided
    if content_type and content_type.lower() not in ALLOWED_MIME_TYPES:
        # If MIME header does not match, allow if extension is standard and image decodes
        if ext not in ALLOWED_EXTENSIONS:
            raise HTTPException(
                status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                detail=f"Unsupported media type '{content_type}'. Supported formats: PNG, JPEG, WebP, BMP, GIF."
            )

    # 4. Safe image decoding & dimension verification
    try:
        pil_img = Image.open(io.BytesIO(file_bytes))
        pil_img.verify()  # Verifies file integrity
        # Re-open after verify as per PIL documentation
        pil_img = Image.open(io.BytesIO(file_bytes))
    except (UnidentifiedImageError, OSError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid or corrupted image file: {str(exc)}"
        )

    width, height = pil_img.size
    if width > MAX_IMAGE_WIDTH or height > MAX_IMAGE_HEIGHT:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Image dimensions ({width}x{height}) exceed maximum allowed dimensions (4096x4096px)."
        )

    if width < MIN_IMAGE_DIMENSION or height < MIN_IMAGE_DIMENSION:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Image dimensions ({width}x{height}) are too small to contain a readable QR code."
        )

    img_format = pil_img.format or (ext.lstrip(".").upper() if ext else "PNG")
    return pil_img, img_format


def extract_qr_texts(pil_img: Image.Image) -> List[str]:
    """
    Decodes QR codes from a validated PIL image using OpenCV's QRCodeDetector.
    Tries both multi-code and single-code detection, in RGB and grayscale color spaces.
    Never navigates to or executes decoded content.
    """
    rgb_img = pil_img.convert("RGB")
    rgb_arr = np.array(rgb_img)

    # OpenCV expects BGR format
    bgr_arr = cv2.cvtColor(rgb_arr, cv2.COLOR_RGB2BGR)
    gray_arr = cv2.cvtColor(rgb_arr, cv2.COLOR_RGB2GRAY)

    detector = cv2.QRCodeDetector()
    decoded_texts: List[str] = []

    # Attempt 1: Multi-detect on BGR
    try:
        ok, texts, _, _ = detector.detectAndDecodeMulti(bgr_arr)
        if ok and texts:
            for t in texts:
                st = str(t).strip()
                if st and st not in decoded_texts:
                    decoded_texts.append(st)
    except Exception:
        pass

    # Attempt 2: Single-detect on BGR fallback
    if not decoded_texts:
        try:
            single_text, _, _ = detector.detectAndDecode(bgr_arr)
            st = str(single_text).strip()
            if st and st not in decoded_texts:
                decoded_texts.append(st)
        except Exception:
            pass

    # Attempt 3: Multi-detect on Grayscale
    if not decoded_texts:
        try:
            ok, texts, _, _ = detector.detectAndDecodeMulti(gray_arr)
            if ok and texts:
                for t in texts:
                    st = str(t).strip()
                    if st and st not in decoded_texts:
                        decoded_texts.append(st)
        except Exception:
            pass

    # Attempt 4: Single-detect on Grayscale fallback
    if not decoded_texts:
        try:
            single_text, _, _ = detector.detectAndDecode(gray_arr)
            st = str(single_text).strip()
            if st and st not in decoded_texts:
                decoded_texts.append(st)
        except Exception:
            pass

    return decoded_texts


def is_url_candidate(text: str) -> bool:
    """
    Checks whether extracted text resembles a web URL.
    Does NOT initiate any network resolution.
    """
    if not text:
        return False
    t = text.strip()
    # Explicit schemes
    if re.match(r"^(?:https?|hxxps?|ftp)://", t, re.IGNORECASE):
        return True
    # Common www or domain syntax (e.g. www.domain.com or domain.tld/path)
    if re.match(r"^(?:www\.)?[a-zA-Z0-9-]{1,63}\.[a-zA-Z0-9.-]{2,}(?:/.*)?$", t):
        return True
    # Punycode URL syntax
    if "xn--" in t:
        return True
    return False


def analyze_qr_image_bytes(
    file_bytes: bytes,
    filename: Optional[str] = "upload.png",
    content_type: Optional[str] = None
) -> Dict[str, Any]:
    """
    Full workflow for QR-code image phishing triage:
    1. Validates file size, format, and dimensions.
    2. Safely decodes embedded QR codes using OpenCV.
    3. Defangs decoded content.
    4. If the content is a URL, pipes it through the comprehensive URL analyzer.
    5. Returns transparent indicators, risk scores, and actionable recommendations.
    """
    pil_img, img_format = validate_image_upload(file_bytes, filename, content_type)
    decoded_texts = extract_qr_texts(pil_img)

    analysis_id = f"QR-{uuid.uuid4().hex[:8].upper()}"

    if not decoded_texts:
        # Image does not contain any readable QR code
        return {
            "success": True,
            "analysis_id": analysis_id,
            "id": analysis_id,
            "source_type": "qr_code_image",
            "qr_detected": False,
            "qr_count": 0,
            "decoded_content": "",
            "defanged_content": "",
            "all_decoded_texts": [],
            "is_url": False,
            "prediction": "No QR Code Detected",
            "classification": "No QR Code Detected",
            "risk_score": 0.0,
            "risk_level": "Low Risk",
            "message": "No readable QR code could be found in the uploaded image. Please ensure the code is well-lit, in focus, and unclipped.",
            "indicators": [],
            "indicator_details": [],
            "reasons": ["Image was scanned successfully with OpenCV QRCodeDetector, but no 2D barcode matrix was recognized."],
            "recommendations": [
                "Verify that the uploaded image contains a clean, unobstructed QR code.",
                "Ensure sufficient contrast and resolution (at least 200x200 pixels recommended)."
            ],
            "features": {
                "image_width": pil_img.size[0],
                "image_height": pil_img.size[1],
                "image_format": img_format,
                "file_size_bytes": len(file_bytes)
            }
        }

    primary_text = decoded_texts[0]
    defanged_text = defang_url_safe(primary_text)
    is_url = is_url_candidate(primary_text)

    if is_url:
        # Run through existing comprehensive static URL analyzer
        url_target = primary_text
        if not re.match(r"^[a-zA-Z]+://", url_target):
            url_target = "http://" + url_target

        url_result = analyze_url_comprehensive(url_target)

        # Augment with QR-specific indicators and metadata
        indicators = list(url_result["indicators"])
        indicators.insert(0, {
            "category": "QR-Code URL Ingestion Vector",
            "severity": "Informational",
            "weight": 5,
            "description": f"Target URL was extracted optically from an uploaded QR-code image ({len(decoded_texts)} code(s) detected).",
            "evidence": f"Decoded Payload: {defanged_text}",
            "why_it_matters": "QR codes (Quishing) bypass traditional email text scanners and perimeter URL firewalls because link text is not visible in standard email bodies."
        })

        # Recalculate transparent score with QR context
        raw_score = sum(ind.get("weight", 0) for ind in indicators)
        risk_score = min(100.0, max(5.0, float(raw_score)))

        reasons = [
            f"[{ind['category']}] {ind['description']}"
            for ind in indicators
            if ind.get("weight", 0) > 0
        ]

        recommendations = list(url_result["recommendations"])
        recommendations.insert(0, "BEWARE OF QUISHING (QR PHISHING): Attackers use QR codes to force mobile device redirection outside organizational web security gateways.")

        return {
            "success": True,
            "analysis_id": analysis_id,
            "id": analysis_id,
            "source_type": "qr_code_image",
            "qr_detected": True,
            "qr_count": len(decoded_texts),
            "decoded_content": primary_text,
            "defanged_content": defanged_text,
            "all_decoded_texts": decoded_texts,
            "is_url": True,
            "url": primary_text,
            "defanged_url": defanged_text,
            "prediction": url_result["prediction"],
            "classification": url_result["prediction"],
            "risk_score": round(risk_score, 1),
            "risk_level": url_result["risk_level"],
            "features": {
                **url_result["features"],
                "image_width": pil_img.size[0],
                "image_height": pil_img.size[1],
                "image_format": img_format,
                "file_size_bytes": len(file_bytes),
                "qr_codes_found": len(decoded_texts)
            },
            "indicators": indicators,
            "indicator_details": indicators,
            "reasons": reasons,
            "recommendations": recommendations,
            "ai_explanation": url_result["ai_explanation"],
            "extracted_urls": url_result["extracted_urls"],
            "url_analysis": url_result
        }
    else:
        # Non-URL plain text QR payload
        indicators = [{
            "category": "QR Non-URL Text Payload",
            "severity": "Informational",
            "weight": 5,
            "description": f"Decoded QR code contains text/data payload ({len(primary_text)} characters) rather than an active web destination.",
            "evidence": f"Payload: {defanged_text[:120]}",
            "why_it_matters": "Non-URL payloads do not initiate browser connections, but should still be inspected for suspicious commands or social engineering instructions."
        }]

        return {
            "success": True,
            "analysis_id": analysis_id,
            "id": analysis_id,
            "source_type": "qr_code_image",
            "qr_detected": True,
            "qr_count": len(decoded_texts),
            "decoded_content": primary_text,
            "defanged_content": defanged_text,
            "all_decoded_texts": decoded_texts,
            "is_url": False,
            "prediction": "Legitimate",
            "classification": "Legitimate",
            "risk_score": 5.0,
            "risk_level": "Low Risk",
            "features": {
                "image_width": pil_img.size[0],
                "image_height": pil_img.size[1],
                "image_format": img_format,
                "file_size_bytes": len(file_bytes),
                "payload_length": len(primary_text)
            },
            "indicators": indicators,
            "indicator_details": indicators,
            "reasons": ["Decoded QR code contains plain text or non-web data rather than an executable web address."],
            "recommendations": [
                "Review the decoded content before manually copying or executing any instructions.",
                "Ensure the QR code was received from a trusted and verified administrative channel."
            ]
        }

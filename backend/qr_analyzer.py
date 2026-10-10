"""
Proxy module exposing QR code analysis functionality from app.services.qr_analyzer
"""
from app.services.qr_analyzer import (
    validate_image_upload,
    extract_qr_texts,
    is_url_candidate,
    analyze_qr_image_bytes,
    MAX_UPLOAD_SIZE_BYTES,
    ALLOWED_MIME_TYPES,
    ALLOWED_EXTENSIONS
)

__all__ = [
    "validate_image_upload",
    "extract_qr_texts",
    "is_url_candidate",
    "analyze_qr_image_bytes",
    "MAX_UPLOAD_SIZE_BYTES",
    "ALLOWED_MIME_TYPES",
    "ALLOWED_EXTENSIONS"
]

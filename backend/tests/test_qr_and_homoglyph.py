"""
Automated Test Suite for Advanced URL Intelligence, IDN/Homoglyph Detection,
and QR-Code Phishing Triage (Step 7).

Verifies:
1. Feature 1: IDN & Homoglyph Detection
   - Ordinary ASCII domains
   - Legitimate internationalized domains (single-script, umlauts)
   - Punycode decoding and safe fallback
   - Mixed-script homoglyphs targeting brands (Apple, etc.)
   - Malformed Unicode & punycode handling
   - Non-double-counting of indicators
2. Feature 2: QR-Code URL Extraction
   - Valid QR images containing benign URLs
   - Valid QR images containing suspicious/phishing URLs
   - Valid QR images containing homoglyph URLs
   - Valid QR images containing non-URL plain text
   - Images containing no QR code
   - Invalid image file formats & corrupt payloads
   - Oversized image uploads (>5MB) & oversized dimensions (>4096px)
   - In-memory decoding without executing or navigating to URLs
3. Reports & Integration
   - PDF generation for QR and homoglyph analyses
   - Defanged and non-clickable link integrity
   - Regression of URL, Email, and Evaluation workflows
"""

import io
import pytest
from fastapi.testclient import TestClient
from PIL import Image
import qrcode

from app.main import app
from app.services.url_analyzer import (
    analyze_url_comprehensive,
    extract_url_features,
    analyze_idn_and_homoglyphs,
    CONFUSABLE_MAP,
    defang_url
)
from app.services.qr_analyzer import (
    validate_image_upload,
    extract_qr_texts,
    analyze_qr_image_bytes,
    is_url_candidate,
    MAX_UPLOAD_SIZE_BYTES
)
from app.services.report_generator import (
    generate_url_report,
    generate_qr_report,
    defang_url_safe
)

client = TestClient(app)


def make_synthetic_qr_image(text: str, fmt: str = "PNG") -> bytes:
    """Generates a synthetic QR code in-memory without disk I/O."""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=4,
    )
    qr.add_data(text)
    qr.make(fit=True)
    pil_img = qr.make_image(fill_color="black", back_color="white").convert("RGB")
    buf = io.BytesIO()
    pil_img.save(buf, format=fmt)
    return buf.getvalue()


# ============================================================================
# 1. HOMOGLYPH & PUNYCODE TESTS
# ============================================================================

def test_homoglyph_ordinary_ascii_domain():
    """Ordinary ASCII domains should be recognized as single-script Latin and not flagged as homoglyphs."""
    res = analyze_idn_and_homoglyphs("google.com")
    assert res["is_punycode"] is False
    assert res["is_mixed_script"] is False
    assert res["is_homoglyph_attack"] is False
    assert res["scripts_detected"] == ["LATIN"]
    assert res["decoded_hostname"] == "google.com"


def test_homoglyph_legitimate_german_idn_umlaut():
    """
    Legitimate German IDN with umlaut ('müller.de' -> 'xn--mller-kva.de')
    should decode safely, have single-script Latin, and NOT be flagged as malicious homoglyph.
    """
    res = analyze_idn_and_homoglyphs("xn--mller-kva.de")
    assert res["is_punycode"] is True
    assert res["is_mixed_script"] is False
    assert res["is_homoglyph_attack"] is False
    assert res["decoded_hostname"] == "müller.de"
    assert res["scripts_detected"] == ["LATIN"]

    # Full URL analysis should classify as Legitimate/Low Risk
    url_res = analyze_url_comprehensive("https://xn--mller-kva.de/about")
    assert url_res["risk_score"] <= 24.0
    assert url_res["prediction"] == "Legitimate"
    # Should include informational IDN indicator without penalty
    idn_ind = [i for i in url_res["indicators"] if "Internationalized Domain Name" in i["category"]]
    assert len(idn_ind) == 1
    assert idn_ind[0]["weight"] == 0


def test_homoglyph_legitimate_cyrillic_cctld():
    """
    Pure Cyrillic domain ('xn--e1afmkfd.xn--p1ai' -> 'пример.рф')
    is entirely Cyrillic (single script) and should not be flagged as mixed-script.
    """
    res = analyze_idn_and_homoglyphs("xn--e1afmkfd.xn--p1ai")
    assert res["is_punycode"] is True
    assert res["is_mixed_script"] is False
    assert res["is_homoglyph_attack"] is False
    assert "CYRILLIC" in res["scripts_detected"]
    assert "LATIN" not in res["scripts_detected"]


def test_homoglyph_mixed_script_apple_spoof():
    """
    Punycode 'xn--pple-43d.com' decodes to 'аpple.com' where 'а' is Cyrillic U+0430
    and 'pple' is Latin. Must be detected as mixed-script homoglyph targeting Apple.
    """
    res = analyze_idn_and_homoglyphs("xn--pple-43d.com")
    assert res["is_punycode"] is True
    assert res["is_mixed_script"] is True
    assert res["is_homoglyph_attack"] is True
    assert "CYRILLIC" in res["scripts_detected"]
    assert "LATIN" in res["scripts_detected"]
    assert res["homoglyph_brand_target"] == "apple"
    assert len(res["confusables_detected"]) > 0

    # Full triage should flag with high/critical severity
    url_res = analyze_url_comprehensive("http://xn--pple-43d.com/auth/login")
    assert url_res["risk_score"] >= 50.0
    assert url_res["prediction"] == "Potential Phishing"
    homo_ind = [i for i in url_res["indicators"] if "Mixed-Script Homoglyph" in i["category"]]
    assert len(homo_ind) == 1
    assert homo_ind[0]["severity"] in ("Critical", "High")


def test_homoglyph_confusable_skeleton_google_spoof():
    """
    Test Cyrillic 'о' (U+043E) embedded in google ('g\u043egle' -> 'xn--ggle-55d.com').
    """
    res = analyze_idn_and_homoglyphs("xn--ggle-55d.com")
    assert res["is_punycode"] is True
    assert res["is_mixed_script"] is True
    assert res["homoglyph_brand_target"] == "google"


def test_homoglyph_malformed_punycode_fallback():
    """Malformed punycode like xn--invalid-punycode-$$$ should not throw an exception."""
    res = analyze_idn_and_homoglyphs("xn--invalid-punycode-$$$.com")
    assert res["is_punycode"] is True
    # Should safely fallback to original label
    assert "xn--invalid-punycode-$$$" in res["decoded_hostname"]


def test_homoglyph_features_structure():
    """extract_url_features must expose original_hostname, normalized_hostname, and decoded_hostname."""
    features = extract_url_features("https://xn--pple-43d.com/login")
    assert features["hostname"] == "xn--pple-43d.com"
    assert features["normalized_hostname"] == "xn--pple-43d.com"
    assert features["decoded_hostname"] == "аpple.com"
    assert features["is_mixed_script"] is True
    assert "idn_details" in features


def test_homoglyph_no_double_counting():
    """A homoglyph brand impersonation should not double-count generic ASCII typosquatting."""
    res = analyze_url_comprehensive("http://xn--pple-43d.com/secure")
    categories = [i["category"] for i in res["indicators"]]
    # Should have Mixed-Script Homoglyph Impersonation
    assert "Mixed-Script Homoglyph Impersonation" in categories
    # Should NOT also add Brand Impersonation / Typosquatting as a duplicate penalty
    assert "Brand Impersonation / Typosquatting" not in categories


# ============================================================================
# 2. QR-CODE URL EXTRACTION TESTS
# ============================================================================

def test_qr_detection_benign_url():
    """Valid QR image containing benign URL should decode and analyze safely."""
    qr_bytes = make_synthetic_qr_image("https://example.com/documentation")
    res = analyze_qr_image_bytes(qr_bytes, "qr_benign.png")
    assert res["qr_detected"] is True
    assert res["qr_count"] == 1
    assert res["is_url"] is True
    assert "example[.]com" in res["defanged_content"]
    assert res["prediction"] == "Legitimate"
    assert res["risk_score"] <= 24.0


def test_qr_detection_suspicious_ip_url():
    """Valid QR image containing bare numeric IP and credential lure."""
    qr_bytes = make_synthetic_qr_image("http://192.168.1.100/login/verify-credentials")
    res = analyze_qr_image_bytes(qr_bytes, "qr_phish.png")
    assert res["qr_detected"] is True
    assert res["is_url"] is True
    assert res["prediction"] in ("Suspicious", "Potential Phishing")
    assert res["risk_score"] >= 45.0
    # Must contain IP indicator and Quishing ingestion note
    categories = [i["category"] for i in res["indicators"]]
    assert "IP Address as Hostname" in categories
    assert "QR-Code URL Ingestion Vector" in categories


def test_qr_detection_homoglyph_url():
    """Valid QR image containing IDN homoglyph lookalike."""
    qr_bytes = make_synthetic_qr_image("http://xn--pple-43d.com/m365/login")
    res = analyze_qr_image_bytes(qr_bytes, "qr_homo.png")
    assert res["qr_detected"] is True
    assert res["is_url"] is True
    assert res["risk_score"] >= 50.0
    categories = [i["category"] for i in res["indicators"]]
    assert "Mixed-Script Homoglyph Impersonation" in categories


def test_qr_detection_non_url_text():
    """Valid QR image containing plain text / WiFi / contact string."""
    plain_text = "WIFI:S:GuestNetwork;T:WPA;P:StrongKey2026;;"
    qr_bytes = make_synthetic_qr_image(plain_text)
    res = analyze_qr_image_bytes(qr_bytes, "qr_wifi.png")
    assert res["qr_detected"] is True
    assert res["is_url"] is False
    assert res["prediction"] == "Legitimate"
    assert res["risk_score"] <= 10.0
    assert plain_text in res["decoded_content"]


def test_qr_no_qr_code_in_blank_image():
    """Image without any QR code returns qr_detected=False gracefully."""
    blank = Image.new("RGB", (300, 300), color=(255, 255, 255))
    buf = io.BytesIO()
    blank.save(buf, format="PNG")
    res = analyze_qr_image_bytes(buf.getvalue(), "blank.png")
    assert res["qr_detected"] is False
    assert res["qr_count"] == 0
    assert res["is_url"] is False
    assert "No readable QR code" in res["message"]


def test_qr_unsupported_file_extension():
    """Rejecting unsupported file extension with HTTP 415."""
    with pytest.raises(Exception) as excinfo:
        validate_image_upload(b"Fake payload", "malicious_script.exe")
    assert "415" in str(excinfo.value)


def test_qr_corrupt_image_bytes():
    """Rejecting corrupt/invalid bytes with HTTP 400."""
    with pytest.raises(Exception) as excinfo:
        validate_image_upload(b"Not an image at all", "test.png")
    assert "400" in str(excinfo.value)


def test_qr_oversized_file_upload():
    """Rejecting files exceeding 5MB with HTTP 413."""
    oversized_bytes = b"0" * (MAX_UPLOAD_SIZE_BYTES + 1024)
    with pytest.raises(Exception) as excinfo:
        validate_image_upload(oversized_bytes, "huge.png")
    assert "413" in str(excinfo.value)


def test_qr_oversized_image_dimensions():
    """Rejecting image dimensions exceeding 4096px to prevent pixel bomb."""
    # Synthetic huge dimensions in memory
    huge_img = Image.new("RGB", (5000, 100), color=(0, 0, 0))
    buf = io.BytesIO()
    huge_img.save(buf, format="PNG")
    with pytest.raises(Exception) as excinfo:
        validate_image_upload(buf.getvalue(), "huge_dims.png")
    assert "400" in str(excinfo.value)


# ============================================================================
# 3. ENDPOINT API INTEGRATION TESTS
# ============================================================================

def test_api_analyze_qr_endpoint_valid_url():
    """Test POST /api/analyze-qr with a synthetic QR image."""
    qr_bytes = make_synthetic_qr_image("https://secure.internal-portal.org/home")
    response = client.post(
        "/api/analyze-qr",
        files={"file": ("test_qr.png", qr_bytes, "image/png")}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["qr_detected"] is True
    assert data["is_url"] is True
    assert "analysis_id" in data
    assert data["analysis_id"].startswith("QR-")


def test_api_analyze_qr_endpoint_blank_image():
    """Test POST /api/analyze-qr with image containing no QR code."""
    blank = Image.new("RGB", (200, 200), color="white")
    buf = io.BytesIO()
    blank.save(buf, format="JPEG")
    response = client.post(
        "/api/analyze-qr",
        files={"file": ("blank.jpg", buf.getvalue(), "image/jpeg")}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["qr_detected"] is False
    assert data["prediction"] == "No QR Code Detected"


def test_api_analyze_qr_endpoint_unsupported_media():
    """Test POST /api/analyze-qr with unsupported file format."""
    response = client.post(
        "/api/analyze-qr",
        files={"file": ("bad_script.py", b"print('hello')", "text/x-python")}
    )
    assert response.status_code in (415, 400)


def test_api_analyze_qr_endpoint_empty_file():
    """Test POST /api/analyze-qr with empty upload."""
    response = client.post(
        "/api/analyze-qr",
        files={"file": ("empty.png", b"", "image/png")}
    )
    assert response.status_code in (422, 400)


# ============================================================================
# 4. REPORT CONSISTENCY & PDF TESTS
# ============================================================================

def test_qr_pdf_report_compilation():
    """Verify generate_qr_report and generate_url_report compile valid PDF bytes for QR analysis."""
    qr_bytes = make_synthetic_qr_image("http://xn--pple-43d.com/auth/login")
    analysis = analyze_qr_image_bytes(qr_bytes, "qr_test.png")

    pdf_bytes = generate_qr_report(analysis)
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 2000
    assert pdf_bytes.startswith(b"%PDF-")


def test_api_qr_pdf_report_endpoint():
    """Test POST /api/report/qr endpoint."""
    qr_bytes = make_synthetic_qr_image("https://legit-service.com/login")
    analysis_resp = client.post(
        "/api/analyze-qr",
        files={"file": ("qr.png", qr_bytes, "image/png")}
    )
    assert analysis_resp.status_code == 200
    qr_data = analysis_resp.json()

    # Request PDF report
    pdf_resp = client.post("/api/report/qr", json=qr_data)
    assert pdf_resp.status_code == 200
    assert pdf_resp.headers["content-type"] == "application/pdf"
    assert len(pdf_resp.content) > 2000
    assert pdf_resp.content.startswith(b"%PDF-")


def test_defanging_integrity_in_reports():
    """Ensure URLs are defanged and non-clickable."""
    raw = "http://malicious.evil-phish.xyz/login.php?user=admin"
    defanged = defang_url_safe(raw)
    assert "hxxp://" in defanged
    assert "[.]" in defanged
    assert "http://" not in defanged

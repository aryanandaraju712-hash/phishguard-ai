import io
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.services.report_generator import (
    generate_url_report,
    generate_email_report,
    defang_url_safe,
    redact_sensitive_text,
    store_server_analysis,
    get_server_analysis
)

client = TestClient(app)

# ============================================================================
# Unit Tests: Core Report Generation & Formatting
# ============================================================================

def test_defang_url_safe():
    assert defang_url_safe("http://example.com/login") == "hxxp://example[.]com/login"
    assert defang_url_safe("https://192.168.1.1/admin") == "hxxps://192[.]168[.]1[.]1/admin"
    assert defang_url_safe("hxxp://already[.]defanged.com") == "hxxp://already[.]defanged.com"
    assert defang_url_safe("http://sub.domain.co.uk/") == "hxxp://sub[.]domain[.]co[.]uk/"
    assert defang_url_safe("") == ""


def test_redact_sensitive_text():
    text = "User password: SuperSecretPassword123 and auth Bearer eyJhbGciOiJIUzI1Ni4. Code otp: 849201"
    redacted = redact_sensitive_text(text)
    assert "SuperSecretPassword123" not in redacted
    assert "[REDACTED]" in redacted
    assert "[REDACTED-TOKEN]" in redacted
    assert "[REDACTED-OTP]" in redacted

    card_text = "Credit card is 4111 2222 3333 4444 please charge"
    card_redacted = redact_sensitive_text(card_text)
    assert "4111 2222 3333 4444" not in card_redacted
    assert "[REDACTED-CARD]" in card_redacted


def test_generate_url_report_success():
    sample_url = {
        "analysis_id": "URL-UTEST01",
        "url": "http://192.168.1.1/login",
        "defanged_url": "hxxp://192[.]168[.]1[.]1/login",
        "prediction": "Potential Phishing",
        "risk_score": 75.0,
        "risk_level": "Critical Risk",
        "features": {
            "scheme": "http",
            "is_ip": True,
            "hostname": "192.168.1.1",
            "subdomains_count": 0,
            "path_length": 6,
            "has_at_symbol": False
        },
        "indicators": [
            {
                "category": "Numeric IP Hostname",
                "severity": "High",
                "weight": 25,
                "evidence": "192.168.1.1",
                "why_it_matters": "Numeric IP addresses obscure destination identity."
            }
        ],
        "reasons": ["[Numeric IP Hostname] Host is numeric IP.", "[Unencrypted HTTP] No TLS."],
        "recommendations": ["Do not click link.", "Block destination IP at perimeter firewall."]
    }

    pdf_bytes = generate_url_report(sample_url)
    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes.startswith(b"%PDF-")
    assert len(pdf_bytes) > 2000


def test_generate_email_report_success():
    sample_email = {
        "analysis_id": "EML-UTEST02",
        "subject": "Urgent: Verify corporate credentials",
        "sender": "security-alert@fake-internal.org",
        "model_name": "GowthamAdhikarla/email-spam-detector-distilbert",
        "model_label": "LABEL_0",
        "classification_score": 0.88,
        "inference_device": "cpu_fallback",
        "text_truncated": False,
        "risk_score": 78.0,
        "risk_level": "Critical Risk",
        "prediction": "Potential Phishing",
        "email_indicators": [
            {
                "category": "Account Credential Verification Request",
                "severity": "Critical",
                "weight": 25,
                "evidence": "Verify corporate credentials",
                "why_it_matters": "Direct request for passwords is characteristic of phishing."
            }
        ],
        "extracted_urls": ["http://192.168.1.1/login"],
        "url_analysis_results": [
            {
                "url": "http://192.168.1.1/login",
                "defanged_url": "hxxp://192[.]168[.]1[.]1/login",
                "risk_score": 62.0,
                "risk_level": "High Risk",
                "reasons": ["[Numeric IP Hostname] Numeric IP host used."]
            }
        ],
        "reasons": ["Urgent language detected", "Suspicious link detected"],
        "recommendations": ["Do not click link.", "Report message to IT desk."]
    }

    pdf_bytes = generate_email_report(sample_email)
    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes.startswith(b"%PDF-")
    assert len(pdf_bytes) > 3000


def test_generate_report_invalid_input_raises():
    with pytest.raises(ValueError):
        generate_url_report("invalid string payload")

    with pytest.raises(ValueError):
        generate_email_report(None)


# ============================================================================
# API Endpoint Tests: /api/report/url & /api/report/email
# ============================================================================

def test_api_report_url_end_to_end():
    # Step 1: Run URL analysis
    r_anl = client.post("/api/analyze-url", json={"url": "http://10.0.0.1/verify"})
    assert r_anl.status_code == 200
    res_data = r_anl.json()
    aid = res_data["analysis_id"]

    # Step 2: Request PDF report using authentic analysis ID
    r_pdf = client.post("/api/report/url", json={"analysis_id": aid})
    assert r_pdf.status_code == 200
    assert r_pdf.headers["content-type"] == "application/pdf"
    assert "attachment; filename=" in r_pdf.headers["content-disposition"]
    assert f"PhishGuard_URL_Report_{aid}.pdf" in r_pdf.headers["content-disposition"]
    assert r_pdf.content.startswith(b"%PDF-")
    assert len(r_pdf.content) > 1000


def test_api_report_email_end_to_end():
    # Step 1: Run Email analysis
    r_anl = client.post("/api/analyze-email", json={
        "subject": "Important update: Payroll direct deposit",
        "body": "Please confirm your banking details at http://192.168.1.1/bank"
    })
    assert r_anl.status_code == 200
    res_data = r_anl.json()
    aid = res_data["analysis_id"]

    # Step 2: Request PDF report using authentic analysis ID
    r_pdf = client.post("/api/report/email", json={"analysis_id": aid})
    assert r_pdf.status_code == 200
    assert r_pdf.headers["content-type"] == "application/pdf"
    assert "attachment; filename=" in r_pdf.headers["content-disposition"]
    assert f"PhishGuard_Email_Report_{aid}.pdf" in r_pdf.headers["content-disposition"]
    assert r_pdf.content.startswith(b"%PDF-")
    assert len(r_pdf.content) > 1000


def test_api_report_missing_id_returns_404():
    r = client.post("/api/report/url", json={"analysis_id": "URL-NONEXISTENT9999"})
    assert r.status_code == 404
    assert "not found" in r.json()["detail"].lower()

    r2 = client.post("/api/report/email", json={"analysis_id": "EML-NONEXISTENT9999"})
    assert r2.status_code == 404
    assert "not found" in r2.json()["detail"].lower()


def test_api_report_empty_body_returns_422():
    r = client.post("/api/report/url", json={})
    assert r.status_code == 422

    r2 = client.post("/api/report/email", json={})
    assert r2.status_code == 422


def test_api_report_mocked_analysis_unit_fallback():
    # Unit tests can supply mocked analysis payloads directly
    mock_url_payload = {
        "analysis_id": "URL-MOCK-001",
        "url": "https://secure-test.org",
        "risk_score": 15.0,
        "risk_level": "Low Risk",
        "prediction": "Legitimate",
        "features": {"scheme": "https", "hostname": "secure-test.org"}
    }
    r = client.post("/api/report/url", json=mock_url_payload)
    assert r.status_code == 200
    assert r.content.startswith(b"%PDF-")


def test_server_side_result_priority_over_tampered_client_data():
    """
    Guarantees that when an authentic server analysis exists, client-tampered
    risk scores or classifications are ignored in favor of the authentic server record.
    """
    # 1. Run legitimate URL analysis that yields Critical Risk
    r_anl = client.post("/api/analyze-url", json={"url": "http://192.168.1.1/login"})
    assert r_anl.status_code == 200
    real_data = r_anl.json()
    aid = real_data["analysis_id"]
    real_score = real_data["risk_score"]

    # 2. Attacker client tries to claim risk_score is 0.0 (Legitimate)
    tampered_request = {
        "analysis_id": aid,
        "risk_score": 0.0,
        "prediction": "Legitimate",
        "risk_level": "Low Risk"
    }

    r_pdf = client.post("/api/report/url", json=tampered_request)
    assert r_pdf.status_code == 200

    # Retrieve cached server record and ensure authentic score is intact
    cached_record = get_server_analysis(aid)
    assert cached_record is not None
    assert cached_record["risk_score"] == real_score

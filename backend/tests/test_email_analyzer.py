"""
Automated tests for AI Email Spam Detection & Triage Module.
Tests unit functions, pattern detection, embedded URL triage, risk engine,
model error handling / CPU fallback, and the FastAPI POST /api/analyze-email endpoint.
Uses mocked model outputs for reliable, self-contained unit execution.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.database import get_db, Base
from app.services.email_pattern_analyzer import analyze_email_patterns
from app.services.email_analyzer import (
    model_manager,
    extract_embedded_urls,
    analyze_email_comprehensive,
    EmailSpamModelManager
)
from app.services.risk_engine import calculate_email_risk, RiskLevel, PredictionCategory


# In-memory test SQLite engine
engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db
Base.metadata.create_all(bind=engine)


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(autouse=True)
def cleanup_mock():
    """Ensure mock model predictions are cleared between tests."""
    yield
    model_manager.clear_mock_prediction()


# =========================================================================
# Unit Tests: Email Patterns & Feature Extraction
# =========================================================================

def test_legitimate_email_pattern_analysis():
    """Test standard business email with no malicious indicators."""
    subject = "Quarterly Business Review"
    body = "Hi team, please find the meeting agenda for our sync on Tuesday at 2 PM. Best regards."
    indicators = analyze_email_patterns(subject, body)
    assert len(indicators) == 0


def test_promotional_spam_pattern_analysis():
    """Test aggressive marketing and lottery/prize indicators."""
    subject = "CONGRATULATIONS! You have won $500,000 in our exclusive lottery!"
    body = "Claim your cash reward now! Limited time offer with guaranteed returns. Click here to unsubscribe."
    indicators = analyze_email_patterns(subject, body)

    categories = [i["category"] for i in indicators]
    assert any("Lottery" in c for c in categories)
    assert any("Promotional" in c or "Unsubscribe" in c for c in categories)


def test_phishing_credential_urgency_pattern_analysis():
    """Test urgent account deactivation and password harvesting."""
    subject = "URGENT: Your corporate account is suspended"
    body = "Unauthorized access detected. Within 24 hours, verify your password and enter your OTP to keep access."
    indicators = analyze_email_patterns(subject, body)

    categories = [i["category"] for i in indicators]
    assert any("Urgency" in c for c in categories)
    assert any("Credential" in c or "Password" in c for c in categories)


def test_financial_bec_pattern_analysis():
    """Test CEO impersonation and wire transfer requests."""
    subject = "Confidential Request from CEO"
    body = "I am in a meeting and cannot take calls. Please execute an urgent wire transfer for vendor payment."
    sender = "CEO Mark Sterling <ceo.mark@gmail.com>"
    reply_to = "attacker.drop@outlook.com"

    indicators = analyze_email_patterns(subject, body, sender=sender, reply_to=reply_to)
    categories = [i["category"] for i in indicators]
    assert any("Wire Transfer" in c for c in categories)
    assert any("Executive Impersonation" in c for c in categories)
    assert any("Mismatch" in c for c in categories)


def test_extract_embedded_urls_single_and_multiple():
    """Test safe extraction of embedded URLs without duplicates."""
    text = (
        "Check this link: https://portal.company.com/login and also "
        "http://192.168.1.10/admin. Don't forget www.backup-site.org/sync."
    )
    urls = extract_embedded_urls(text)
    assert len(urls) == 3
    assert "https://portal.company.com/login" in urls
    assert "http://192.168.1.10/admin" in urls


def test_extract_embedded_urls_malformed_handling():
    """Test that malformed or punctuated URLs are stripped cleanly."""
    text = "Visit https://safe.com/path, or (http://another.com/test)."
    urls = extract_embedded_urls(text)
    assert "https://safe.com/path" in urls
    assert "http://another.com/test" in urls


# =========================================================================
# Unit Tests: Comprehensive Email Analyzer & Risk Engine
# =========================================================================

def test_legitimate_email_triage():
    """Test that a legitimate email classified as Ham gets Low Risk."""
    model_manager.set_mock_prediction(label="LABEL_0", score=0.9850)

    res = analyze_email_comprehensive(
        subject="Project Status Update",
        body="Hello everyone, the sprint deliverables are on track for Friday. Thanks!"
    )
    assert res["success"] is True
    assert res["model_label"] == "LABEL_0"
    assert res["prediction"] == PredictionCategory.LEGITIMATE
    assert res["risk_score"] <= 24.0
    assert res["risk_level"] == RiskLevel.LOW
    assert len(res["extracted_urls"]) == 0


def test_promotional_spam_triage():
    """Test that an unsolicited promotional email is categorized as Spam / Moderate Risk."""
    model_manager.set_mock_prediction(label="LABEL_1", score=0.9700)

    res = analyze_email_comprehensive(
        subject="Special Promotion: Huge Discounts Today",
        body="Exclusive deal for valued members! Limited time offer with 80% discount. Click here to unsubscribe."
    )
    assert res["model_label"] == "LABEL_1"
    assert res["prediction"] in [PredictionCategory.SPAM, PredictionCategory.SUSPICIOUS]
    assert 25.0 <= res["risk_score"] <= 49.0
    assert res["risk_level"] == RiskLevel.MEDIUM


def test_phishing_with_suspicious_url():
    """Test phishing email containing credential lure and suspicious IP URL."""
    model_manager.set_mock_prediction(label="LABEL_1", score=0.9920)

    res = analyze_email_comprehensive(
        subject="Security Alert: Immediate Action Required",
        body="Your account has unusual activity. Verify your password at http://185.220.101.5/bank/verify immediately."
    )
    assert res["risk_score"] >= 50.0
    assert res["risk_level"] in [RiskLevel.HIGH, RiskLevel.CRITICAL]
    assert res["prediction"] == PredictionCategory.POTENTIAL_PHISHING
    assert len(res["extracted_urls"]) == 1
    assert res["url_analysis_results"][0]["risk_score"] >= 50.0


def test_empty_email_validation():
    """Test that empty subject and body raises ValueError."""
    with pytest.raises(ValueError, match="cannot both be empty"):
        analyze_email_comprehensive(subject="", body="")

    with pytest.raises(ValueError, match="cannot both be empty"):
        analyze_email_comprehensive(subject="   ", body="   ")


def test_excessively_long_email_truncation():
    """Test that extremely large messages trigger documented text truncation."""
    huge_body = "word " * 10000
    res = analyze_email_comprehensive(subject="Large Email", body=huge_body)
    assert res["text_truncated"] is True


def test_model_manager_fallback_and_cpu():
    """Test that model manager gracefully reports device and fallback state."""
    mgr = EmailSpamModelManager()
    status_pred = mgr.classify_email("Subject: Free Cash\n\nYou won a free lottery prize!")
    assert "model_name" in status_pred
    assert "model_label" in status_pred
    assert "inference_device" in status_pred


def test_risk_engine_output_consistency():
    """Test that calculate_email_risk returns consistent bounds."""
    # Score must be bounded between 5.0 and 100.0
    score, level, pred, recs = calculate_email_risk(
        model_label="LABEL_0",
        model_score=0.99,
        email_indicators=[],
        url_analysis_results=[]
    )
    assert 5.0 <= score <= 24.0
    assert level == RiskLevel.LOW
    assert pred == PredictionCategory.LEGITIMATE


# =========================================================================
# API Integration Tests: POST /api/analyze-email & GET /api/model-status
# =========================================================================

def test_api_model_status_endpoint(client: TestClient):
    """Ensure GET /api/model-status returns expected fields without leaking secrets."""
    resp = client.get("/api/model-status")
    assert resp.status_code == 200
    data = resp.json()
    assert "model_id" in data
    assert "model_loaded" in data
    assert "inference_device" in data
    assert "cuda_available" in data
    assert "status" in data


def test_api_analyze_email_valid(client: TestClient):
    """Test POST /api/analyze-email returns required schema fields from Step 3."""
    model_manager.set_mock_prediction(label="LABEL_1", score=0.9800)
    payload = {
        "subject": "Urgent: Verify your account",
        "body": "Please verify your account credentials using http://192.168.1.1/login within 24 hours."
    }
    resp = client.post("/api/analyze-email", json=payload)
    assert resp.status_code == 200
    data = resp.json()

    # Required fields from STEP 7
    assert data["success"] is True
    assert "analysis_id" in data
    assert "model_name" in data
    assert "inference_device" in data
    assert "prediction" in data
    assert isinstance(data["classification_score"], float)
    assert isinstance(data["risk_score"], (int, float))
    assert "risk_level" in data
    assert isinstance(data["email_indicators"], list)
    assert isinstance(data["extracted_urls"], list)
    assert isinstance(data["url_analysis_results"], list)
    assert isinstance(data["reasons"], list)
    assert isinstance(data["recommendations"], list)
    assert len(data["extracted_urls"]) == 1


def test_api_analyze_email_empty_returns_422(client: TestClient):
    """Test POST /api/analyze-email with empty strings returns 422."""
    payload = {"subject": "", "body": "   "}
    resp = client.post("/api/analyze-email", json=payload)
    assert resp.status_code == 422

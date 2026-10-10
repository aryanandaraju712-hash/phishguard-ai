"""
Automated tests for URL Phishing Detection Module.
Tests unit functions and the FastAPI POST /api/analyze-url endpoint across all required scenarios:
- Normal HTTPS URL
- Normal HTTP URL
- IP-address URL
- URL containing an @ symbol
- URL with many subdomains
- Unusually long URL
- Malformed URL
- Empty input
- URL with encoded characters
- Verifies that HTTPS alone does NOT guarantee safety, and HTTP alone does NOT mark phishing.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.database import get_db, Base
from app.services.url_analyzer import (
    extract_url_features,
    analyze_url_comprehensive,
    is_ip_address,
    check_brand_lookalike,
    defang_url
)
from app.services.risk_engine import RiskLevel, PredictionCategory


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


# =========================================================================
# Unit Tests for URL Features and Risk Engine
# =========================================================================

def test_normal_https_url():
    """Test a legitimate HTTPS URL from a trusted domain."""
    url = "https://www.google.com"
    result = analyze_url_comprehensive(url)

    assert result["success"] is True
    assert result["features"]["scheme"] == "https"
    assert result["features"]["hostname"] == "www.google.com"
    assert result["features"]["is_ip"] is False
    assert result["risk_score"] <= 24.0
    assert result["risk_level"] == RiskLevel.LOW
    assert result["prediction"] == PredictionCategory.LEGITIMATE
    # Verify HTTPS note is present for explainability
    assert any("HTTPS" in ind["category"] for ind in result["indicators"])


def test_normal_http_url():
    """Test a plain HTTP URL from a standard domain."""
    url = "http://example.com"
    result = analyze_url_comprehensive(url)

    assert result["success"] is True
    assert result["features"]["scheme"] == "http"
    assert result["features"]["is_ip"] is False
    # Crucial rule: HTTP alone does NOT mean phishing!
    assert result["prediction"] != PredictionCategory.POTENTIAL_PHISHING
    assert result["risk_score"] <= 24.0
    assert result["risk_level"] == RiskLevel.LOW
    # Verify unencrypted HTTP is recorded as informational
    assert any("Unencrypted HTTP" in ind["category"] for ind in result["indicators"])


def test_https_alone_does_not_mark_phishing_url_safe():
    """
    Test that adding HTTPS to a phishing URL (e.g. brand typosquatting + credentials)
    does NOT mark it safe.
    """
    url = "https://micros0ft-security-update.xyz/login/verify"
    result = analyze_url_comprehensive(url)

    assert result["features"]["scheme"] == "https"
    # Even with HTTPS, high-risk indicators must classify it as phishing/suspicious
    assert result["risk_score"] >= 50.0
    assert result["risk_level"] in [RiskLevel.HIGH, RiskLevel.CRITICAL]
    assert result["prediction"] == PredictionCategory.POTENTIAL_PHISHING


def test_http_alone_does_not_mark_url_phishing():
    """
    Test that a benign plain HTTP URL is NOT classified as phishing.
    """
    url = "http://info.cern.ch"
    result = analyze_url_comprehensive(url)

    assert result["features"]["scheme"] == "http"
    assert result["prediction"] == PredictionCategory.LEGITIMATE
    assert result["risk_level"] == RiskLevel.LOW


def test_ip_address_url():
    """Test a URL with a raw IPv4 address as host."""
    url = "http://185.220.101.5/admin/login"
    result = analyze_url_comprehensive(url)

    assert result["features"]["is_ip"] is True
    assert result["features"]["is_ipv4"] is True
    assert "hxxp://185[.]220[.]101[.]5/admin/login" in result["defanged_url"]
    assert result["risk_score"] >= 50.0
    assert any("numeric IP address" in ind["description"] for ind in result["indicators"])
    assert result["risk_level"] in [RiskLevel.HIGH, RiskLevel.CRITICAL]


def test_url_with_at_symbol():
    """Test a URL using @ authority deception."""
    url = "https://google.com@evil-phishing-host.com/session"
    result = analyze_url_comprehensive(url)

    assert result["features"]["has_at_symbol"] is True
    assert result["risk_score"] >= 30.0
    assert any("Suspicious @ Credential Syntax" in ind["category"] for ind in result["indicators"])


def test_url_with_many_subdomains():
    """Test a URL with an excessive chain of subdomains."""
    url = "https://login.verify.portal.account.security.service-portal.net/auth"
    result = analyze_url_comprehensive(url)

    assert result["features"]["subdomain_count"] >= 3
    assert any("Excessive Subdomain Depth" in ind["category"] for ind in result["indicators"])


def test_unusually_long_url():
    """Test a URL exceeding typical length thresholds."""
    long_query = "x" * 150
    url = f"https://legitimate-looking-subdomain.com/path?token={long_query}"
    result = analyze_url_comprehensive(url)

    assert result["features"]["url_length"] > 120
    assert any("Long URL" in ind["category"] for ind in result["indicators"])


def test_url_with_encoded_characters():
    """Test a URL containing obfuscated percent-encoding (%2e, %2f, %40)."""
    url = "https://safe-domain.org/%2e%2e/%2f%40account/verify"
    result = analyze_url_comprehensive(url)

    assert result["features"]["has_suspicious_encoding"] is True
    assert any("Percent Encoding" in ind["category"] for ind in result["indicators"])


def test_url_shortener_detection():
    """Test that known URL shorteners are flagged with medium risk obfuscation."""
    url = "https://bit.ly/3xSecAlert"
    result = analyze_url_comprehensive(url)

    assert result["features"]["is_shortener"] is True
    assert result["risk_level"] == RiskLevel.MEDIUM
    assert result["prediction"] == PredictionCategory.SUSPICIOUS


def test_empty_input_validation():
    """Test that empty or whitespace-only inputs raise ValueError."""
    with pytest.raises(ValueError, match="URL cannot be empty"):
        analyze_url_comprehensive("")

    with pytest.raises(ValueError, match="URL cannot be empty"):
        analyze_url_comprehensive("   ")


def test_malformed_url_handling():
    """Test that malformed URLs are handled gracefully without unhandled crashes."""
    # Defanging still handles strings
    defanged = defang_url("http://[invalid-ipv6/test")
    assert "hxxp://" in defanged

    # extract_url_features handles missing scheme or unusual characters
    feats = extract_url_features("custom-subdomain.com/path")
    assert feats["scheme_missing"] is True
    assert feats["hostname"] == "custom-subdomain.com"


# =========================================================================
# API Endpoint Integration Tests: POST /api/analyze-url
# =========================================================================

def test_api_health_endpoint(client: TestClient):
    """Ensure GET /api/health operates reliably."""
    resp = client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert "service" in data


def test_api_analyze_url_valid_https(client: TestClient):
    """Test POST /api/analyze-url with valid HTTPS input."""
    payload = {"url": "https://www.google.com"}
    resp = client.post("/api/analyze-url", json=payload)

    assert resp.status_code == 200
    data = resp.json()

    # Verify all required top-level fields from STEP 4
    assert data["success"] is True
    assert "analysis_id" in data
    assert data["url"] == "https://www.google.com"
    assert data["prediction"] == "Legitimate"
    assert isinstance(data["risk_score"], (int, float))
    assert data["risk_level"] == "Low Risk"
    assert isinstance(data["features"], dict)
    assert isinstance(data["reasons"], list)
    assert isinstance(data["recommendations"], list)
    assert len(data["recommendations"]) > 0


def test_api_analyze_url_phishing_ip(client: TestClient):
    """Test POST /api/analyze-url with an IP address and credential lure."""
    payload = {"url": "http://192.168.1.100/bank/login"}
    resp = client.post("/api/analyze-url", json=payload)

    assert resp.status_code == 200
    data = resp.json()

    assert data["success"] is True
    assert data["prediction"] in ["Potential Phishing", "Suspicious"]
    assert data["risk_score"] >= 50.0
    assert data["features"]["is_ip"] is True
    assert any("numeric IP address" in r for r in data["reasons"])
    # Actionable guidance
    assert any("DO NOT OPEN" in rec for rec in data["recommendations"])


def test_api_analyze_url_empty_validation(client: TestClient):
    """Test POST /api/analyze-url with empty string returns 422."""
    payload = {"url": "   "}
    resp = client.post("/api/analyze-url", json=payload)
    assert resp.status_code == 422


def test_api_legacy_url_endpoint_compatibility(client: TestClient):
    """Ensure backward-compatible POST /api/analyze/url continues to serve existing frontend."""
    payload = {"url": "https://paypal-verify-account.xyz/update", "create_incident": True}
    resp = client.post("/api/analyze/url", json=payload)

    assert resp.status_code == 200
    data = resp.json()
    assert "id" in data
    assert "risk_score" in data
    assert "classification" in data
    assert data["analysis_type"] == "url"


# =========================================================================
# STEP 11 Regression Tests for URL Phishing Detection
# =========================================================================

def test_regression_suspicious_subdomain_paypal_url(client: TestClient):
    """
    Regression test for: http://paypal-login-verify.example.com/account/update
    Verifies that brand impersonation in subdomains combined with authentication keywords
    is correctly triaged as High Risk / Potential Phishing rather than Low Risk.
    """
    url = "http://paypal-login-verify.example.com/account/update"
    result = analyze_url_comprehensive(url)

    # Features verification
    assert result["features"]["hostname"] == "paypal-login-verify.example.com"
    assert result["features"]["registered_domain"] == "example.com"
    assert result["features"]["subdomains"] == ["paypal-login-verify"]
    assert result["features"]["is_lookalike"] is True
    assert result["features"]["lookalike_brand"] == "paypal"
    assert "paypal" in result["features"]["lookalike_reason"].lower()

    # Risk score & label verification
    assert result["risk_score"] >= 50.0, f"Expected risk_score >= 50.0, got {result['risk_score']}"
    assert result["risk_level"] == RiskLevel.HIGH
    assert result["prediction"] == PredictionCategory.POTENTIAL_PHISHING

    # Indicator verification
    categories = [ind["category"] for ind in result["indicators"]]
    assert any("Brand Impersonation" in c for c in categories)
    assert any("Credential Lure" in c for c in categories)
    assert any("Unencrypted HTTP" in c for c in categories)

    # Actionable guidance
    assert any("DO NOT OPEN" in rec for rec in result["recommendations"])

    # API Endpoint check
    resp = client.post("/api/analyze-url", json={"url": url})
    assert resp.status_code == 200
    api_data = resp.json()
    assert api_data["prediction"] == "Potential Phishing"
    assert api_data["risk_level"] == "High Risk"
    assert api_data["risk_score"] >= 50.0


def test_regression_normal_https_wikipedia_url(client: TestClient):
    """
    Regression test for: https://www.wikipedia.org/
    Verifies that trusted, benign HTTPS domains are classified as Low Risk / Legitimate.
    """
    url = "https://www.wikipedia.org/"
    result = analyze_url_comprehensive(url)

    # Features verification
    assert result["features"]["scheme"] == "https"
    assert result["features"]["hostname"] == "www.wikipedia.org"
    assert result["features"]["registered_domain"] == "wikipedia.org"
    assert result["features"]["is_lookalike"] is False
    assert result["features"]["is_ip"] is False

    # Risk score & label verification (must be Low Risk < 25.0)
    assert result["risk_score"] <= 24.0, f"Expected risk_score <= 24.0, got {result['risk_score']}"
    assert result["risk_level"] == RiskLevel.LOW
    assert result["prediction"] == PredictionCategory.LEGITIMATE

    # Recommendations must be standard awareness, not high-severity block advice
    assert not any("DO NOT OPEN" in rec for rec in result["recommendations"])

    # API Endpoint check
    resp = client.post("/api/analyze-url", json={"url": url})
    assert resp.status_code == 200
    api_data = resp.json()
    assert api_data["prediction"] == "Legitimate"
    assert api_data["risk_level"] == "Low Risk"
    assert api_data["risk_score"] <= 24.0


def test_regression_bare_ip_test_url(client: TestClient):
    """
    Regression test for bare-IP test URL: http://192.168.1.1/admin-login
    Verifies that raw IP destination with credential path is classified as Potential Phishing.
    """
    url = "http://192.168.1.1/admin-login"
    result = analyze_url_comprehensive(url)

    # Features verification
    assert result["features"]["is_ip"] is True
    assert result["features"]["is_ipv4"] is True
    assert "hxxp://192[.]168[.]1[.]1/admin-login" in result["defanged_url"]

    # Risk score & label verification
    assert result["risk_score"] >= 50.0, f"Expected risk_score >= 50.0, got {result['risk_score']}"
    assert result["risk_level"] in (RiskLevel.HIGH, RiskLevel.CRITICAL)
    assert result["prediction"] == PredictionCategory.POTENTIAL_PHISHING

    # Indicator verification
    categories = [ind["category"] for ind in result["indicators"]]
    assert any("IP Address as Hostname" in c for c in categories)
    assert any("Credential Lure" in c for c in categories)

    # API Endpoint check
    resp = client.post("/api/analyze-url", json={"url": url})
    assert resp.status_code == 200
    api_data = resp.json()
    assert api_data["prediction"] == "Potential Phishing"
    assert api_data["risk_score"] >= 50.0


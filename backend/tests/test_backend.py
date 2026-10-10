import pytest
import io
import os
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.database import get_db, Base, seed_sample_data
from app.core.config import settings
from app.models.models import User, Incident, EmailAnalysis
from app.core.security import get_password_hash
from app.services.phishing_analyzer import analyze_email_data
from app.services.url_analyzer import analyze_url, is_ip_address, check_brand_lookalike
from app.services.email_parser import parse_manual_email_input, parse_eml_bytes

# Test SQLite in-memory DB setup with StaticPool so all connections share the memory DB
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

# Create tables and seed initial test data
Base.metadata.create_all(bind=engine)
test_db = TestingSessionLocal()
admin = User(
    email="admin@phishguard.local",
    hashed_password=get_password_hash("Admin@PhishGuard2026!"),
    full_name="Sarah Connor",
    role="admin",
    is_active=True
)
analyst = User(
    email="analyst@phishguard.local",
    hashed_password=get_password_hash("Analyst@PhishGuard2026!"),
    full_name="Alex Mercer",
    role="analyst",
    is_active=True
)
test_db.add(admin)
test_db.add(analyst)
test_db.commit()
test_db.refresh(admin)
test_db.refresh(analyst)
seed_sample_data(test_db, admin.id, analyst.id)
test_db.close()

@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c

# 1. URL Analyzer Tests
def test_url_analyzer_ip_address():
    res = analyze_url("http://192.168.1.50/login")
    assert res["is_ip"] is True
    assert "hxxp://192[.]168[.]1[.]50/login" in res["defanged_url"]
    assert any("numeric IP address" in r for r in res["reasons"])

def test_url_analyzer_brand_typosquatting():
    is_lookalike, brand, reason = check_brand_lookalike("micros0ft-login.com")
    assert is_lookalike is True
    assert brand == "microsoft"

def test_url_analyzer_anchor_mismatch():
    res = analyze_url("http://evil-tracker.xyz/steal", anchor_text="https://paypal.com/signin")
    assert any("Misleading link text" in r for r in res["reasons"])

# 2. Phishing Engine Tests
def test_benign_sample_email():
    parsed = parse_manual_email_input(
        subject="Quarterly Planning Sync",
        sender="Jessica <jessica@partner.com>",
        reply_to="jessica@partner.com",
        body="Hi team, here is the agenda for our Tuesday meeting at 2 PM. Best, Jessica."
    )
    result = analyze_email_data(parsed)
    assert result["risk_score"] <= 29.0
    assert result["risk_level"] == "Low"
    assert any("PhishGuard AI does NOT certify emails as 100% safe" in r for r in result["recommendations"])

def test_obvious_phishing_email():
    parsed = parse_manual_email_input(
        subject="URGENT: Your account is suspended - Verify password now",
        sender="Microsoft Security <alerts@micros0ft-fake.xyz>",
        reply_to="attacker.drop@gmail.com",
        body="Your account will be suspended within 2 hours. Enter your password at http://185.220.101.5/verify",
        explicit_urls=["http://185.220.101.5/verify"]
    )
    result = analyze_email_data(parsed)
    assert result["risk_score"] >= 80.0
    assert result["risk_level"] == "Critical"
    categories = [ind["category"] for ind in result["indicator_details"]]
    assert "Reply-To Address Mismatch" in categories
    assert "IP-Address-Based URL" in categories
    assert "Credential & Sensitive Data Request" in categories

def test_sender_and_reply_to_mismatch():
    parsed = parse_manual_email_input(
        subject="Hello",
        sender="HR Team <hr@company.com>",
        reply_to="stealth@external-inbox.com",
        body="Please review your benefits package."
    )
    result = analyze_email_data(parsed)
    cats = [i["category"] for i in result["indicator_details"]]
    assert "Reply-To Address Mismatch" in cats

def test_unknown_authentication_evidence():
    parsed = parse_manual_email_input(
        subject="Status update",
        sender="john@example.com",
        body="Work in progress."
    )
    result = analyze_email_data(parsed)
    assert any("SPF" in item for item in result["missing_evidence"])

# 3. EML Parsing Tests
def test_eml_file_parsing_safe():
    raw_eml = b"""From: Billing <billing@quickbooks.com>
To: target@smallbiz.org
Subject: Invoice Attached
Date: Fri, 9 Oct 2026 10:00:00 +0000
Content-Type: multipart/mixed; boundary="====BOUNDARY===="

--====BOUNDARY====
Content-Type: text/plain; charset="utf-8"

Please see attached invoice.

--====BOUNDARY====
Content-Type: application/octet-stream; name="invoice.iso"
Content-Disposition: attachment; filename="invoice.iso"

FAKE_DATA
--====BOUNDARY====--
"""
    parsed = parse_eml_bytes(raw_eml)
    assert parsed["subject"] == "Invoice Attached"
    assert len(parsed["attachments"]) == 1
    assert parsed["attachments"][0]["filename"] == "invoice.iso"
    assert parsed["attachments"][0]["is_dangerous"] is True

def test_malformed_eml_rejected():
    with pytest.raises(Exception):
        parse_eml_bytes(None)

# 4. API Endpoints Integration Tests
def test_api_health(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    assert res.json()["status"] == "healthy"

def test_api_analyze_manual(client):
    payload = {
        "subject": "Wire Transfer Needed Immediately",
        "sender": "CEO <ceo@fraud-exec.org>",
        "reply_to": "attacker@gmail.com",
        "body": "Transfer $50,000 to routing number 12345 right now. In a meeting, cannot talk.",
        "create_incident": True
    }
    res = client.post("/api/analyze", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["risk_score"] >= 50.0
    assert data["incident_id"] is not None
    assert len(data["ai_explanation"]) > 0

def test_api_analyze_upload(client):
    raw_eml = b"From: IT <it@phish.xyz>\nSubject: Password Reset\n\nClick http://10.0.0.1/reset"
    files = {"file": ("test.eml", io.BytesIO(raw_eml), "message/rfc822")}
    res = client.post("/api/analyze/upload", files=files)
    assert res.status_code == 200
    assert res.json()["has_eml"] is True

def test_api_upload_oversized(client, monkeypatch):
    monkeypatch.setattr(settings, "MAX_UPLOAD_SIZE_BYTES", 50)
    files = {"file": ("test.eml", io.BytesIO(b"A" * 100), "message/rfc822")}
    res = client.post("/api/analyze/upload", files=files)
    assert res.status_code in [413, 400]

def test_api_dashboard_stats(client):
    res = client.get("/api/dashboard/stats")
    assert res.status_code == 200
    data = res.json()
    assert "total_emails_analyzed" in data
    assert "risk_distribution" in data
    assert "daily_activity" in data

def test_api_incidents_lifecycle(client):
    # 1. Fetch incidents
    inc_res = client.get("/api/incidents")
    assert inc_res.status_code == 200
    inc_list = inc_res.json()
    assert len(inc_list) > 0
    test_inc_id = inc_list[0]["id"]

    # 2. Add Analyst Note
    note_res = client.post(f"/api/incidents/{test_inc_id}/notes", json={"note_text": "Investigating false alarm"})
    assert note_res.status_code == 200
    assert note_res.json()["note_text"] == "Investigating false alarm"

    # 3. Patch Status
    patch_res = client.patch(f"/api/incidents/{test_inc_id}", json={"status": "Investigating", "comment": "Under review"})
    assert patch_res.status_code == 200
    assert patch_res.json()["status"] == "Investigating"

    # 4. View Detail
    detail_res = client.get(f"/api/incidents/{test_inc_id}")
    assert detail_res.status_code == 200
    assert len(detail_res.json()["notes"]) >= 1

def test_api_report_export_csv(client):
    res = client.get("/api/reports/export/csv")
    assert res.status_code == 200
    assert res.headers["content-type"].startswith("text/csv")
    assert "Incident ID" in res.text

def test_api_samples(client):
    res = client.get("/api/samples")
    assert res.status_code == 200
    samples = res.json()
    assert len(samples) >= 5

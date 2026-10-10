import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from app.core.config import settings
from app.core.security import get_password_hash
from app.models.models import Base, User, Incident, EmailAnalysis, AnalystNote, StatusHistory

# Connect args for SQLite
connect_args = {"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(
    settings.DATABASE_URL,
    connect_args=connect_args
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    """Create tables and seed initial accounts and demo incidents."""
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        # Check if admin user exists
        admin_user = db.query(User).filter(User.email == "admin@phishguard.local").first()
        if not admin_user:
            admin_user = User(
                email="admin@phishguard.local",
                hashed_password=get_password_hash("Admin@PhishGuard2026!"),
                full_name="Sarah Connor (Lead Admin)",
                role="admin",
                is_active=True
            )
            db.add(admin_user)
        
        analyst_user = db.query(User).filter(User.email == "analyst@phishguard.local").first()
        if not analyst_user:
            analyst_user = User(
                email="analyst@phishguard.local",
                hashed_password=get_password_hash("Analyst@PhishGuard2026!"),
                full_name="Alex Mercer (SOC Analyst)",
                role="analyst",
                is_active=True
            )
            db.add(analyst_user)
        
        db.commit()
        db.refresh(admin_user)
        db.refresh(analyst_user)

        # Check if sample incidents exist, if not seed realistic initial data
        incident_count = db.query(Incident).count()
        if incident_count == 0:
            seed_sample_data(db, admin_user.id, analyst_user.id)
            
    finally:
        db.close()

def seed_sample_data(db: Session, admin_id: int, analyst_id: int):
    """Seed initial realistic incidents marked clearly as demo samples."""
    samples = [
        {
            "id": "INC-2026-0001",
            "title": "URGENT: Executive Wire Transfer Request [CONFIDENTIAL]",
            "risk_score": 92.0,
            "risk_level": "Critical",
            "status": "Investigating",
            "assigned_to_user_id": analyst_id,
            "is_sample": True,
            "created_at": datetime.datetime.utcnow() - datetime.timedelta(hours=3),
            "analysis": {
                "id": "ANL-SAMPLE-0001",
                "subject": "URGENT: Executive Wire Transfer Request [CONFIDENTIAL]",
                "sender": "CEO Mark Sterling <m.sterling@exec-acquisitions-direct.com>",
                "reply_to": "m.sterling.private@gmail.com",
                "recipient": "finance@smallbiz.org",
                "body_snippet": "Hi team, I am in a board meeting right now and cannot take calls. Please process an urgent wire transfer of $48,500 to account 98234-1192 immediately for the supplier buyout. Reply when completed.",
                "urls_count": 0,
                "attachments_count": 0,
                "risk_score": 92.0,
                "risk_level": "Critical",
                "confidence_score": "High (94%)",
                "indicator_details": [
                    {
                        "category": "Sender & Display Name Mismatch",
                        "severity": "High",
                        "weight": 30,
                        "description": "Sender display name impersonates company executive 'CEO Mark Sterling' but sends from unregistered external domain 'exec-acquisitions-direct.com'."
                    },
                    {
                        "category": "Reply-To Mismatch",
                        "severity": "Critical",
                        "weight": 35,
                        "description": "Reply-To address 'm.sterling.private@gmail.com' reroutes responses to a free public email address, bypassing corporate visibility."
                    },
                    {
                        "category": "Urgent Financial Coercion",
                        "severity": "High",
                        "weight": 27,
                        "description": "Demands immediate wire transfer of $48,500, claims inability to take calls ('in board meeting'), classic Business Email Compromise (BEC)."
                    }
                ],
                "ai_explanation": [
                    {
                        "finding": "Executive impersonation and free-mail reply rerouting",
                        "evidence": "Sender display claims to be CEO Mark Sterling, but return path points to a gmail.com mailbox.",
                        "why_it_matters": "Attackers pose as executives during busy hours to pressure finance personnel into bypassing dual-authorization controls.",
                        "recommended_action": "Do NOT process wire transfer. Call CEO on verified phone number or via internal chat to verify."
                    }
                ],
                "recommendations": [
                    "Immediately freeze any wire instructions pending verbal confirmation via an out-of-band channel.",
                    "Flag external domain 'exec-acquisitions-direct.com' on mail gateway.",
                    "Escalate to CFO and notify corporate banking partner if transactions were initiated."
                ],
                "missing_evidence": [
                    "DKIM and SPF records for exec-acquisitions-direct.com were not present in message headers (marked as Unknown)."
                ]
            },
            "notes": [
                {
                    "author_name": "Alex Mercer (SOC Analyst)",
                    "note_text": "Investigating BEC attempt targeting Accounting dept. Contacted CEO executive assistant; confirmed CEO is on vacation, did not send this email."
                }
            ]
        },
        {
            "id": "INC-2026-0002",
            "title": "Microsoft 365: Your password expires in 2 hours",
            "risk_score": 84.0,
            "risk_level": "Critical",
            "status": "Escalated",
            "assigned_to_user_id": analyst_id,
            "is_sample": True,
            "created_at": datetime.datetime.utcnow() - datetime.timedelta(hours=7),
            "analysis": {
                "id": "ANL-SAMPLE-0002",
                "subject": "Microsoft 365: Your password expires in 2 hours",
                "sender": "Microsoft IT Admin <support@msft-auth-token99.net>",
                "reply_to": "support@msft-auth-token99.net",
                "recipient": "employee@smallbiz.org",
                "body_snippet": "Your organization password is set to expire today. Keep current password by validating your credentials here: http://194.38.20.12/login/m365",
                "urls_count": 1,
                "attachments_count": 0,
                "risk_score": 84.0,
                "risk_level": "Critical",
                "confidence_score": "High (90%)",
                "indicator_details": [
                    {
                        "category": "Credential Harvesting",
                        "severity": "Critical",
                        "weight": 35,
                        "description": "Urges user to retain credentials through an unauthenticated login page."
                    },
                    {
                        "category": "IP-Address Link",
                        "severity": "Critical",
                        "weight": 30,
                        "description": "Link directs to raw public IP address 'http://194.38.20.12/login/m365' instead of Microsoft official domain."
                    },
                    {
                        "category": "Domain Typosquatting / Lookalike",
                        "severity": "High",
                        "weight": 19,
                        "description": "Domain 'msft-auth-token99.net' attempts to impersonate Microsoft trademark."
                    }
                ],
                "ai_explanation": [
                    {
                        "finding": "Credential harvesting phishing using IP URL",
                        "evidence": "Destination URL is hosted directly on a numeric IP address 194.38.20.12 mimicking Microsoft login.",
                        "why_it_matters": "Legitimate enterprise providers like Microsoft never host production login portals on raw numeric IP addresses.",
                        "recommended_action": "Block the IP at perimeter firewall and reset credentials for targeted user."
                    }
                ],
                "recommendations": [
                    "Instruct targeted employee to NOT click or submit passwords.",
                    "Verify if any employee submitted credentials in Azure AD / Entra sign-in logs.",
                    "Block IP 194.38.20.12 at firewall."
                ],
                "missing_evidence": []
            },
            "notes": [
                {
                    "author_name": "Sarah Connor (Lead Admin)",
                    "note_text": "Escalated to network team. IP 194.38.20.12 has been submitted to firewall blocklist."
                }
            ]
        },
        {
            "id": "INC-2026-0003",
            "title": "Invoice INV-88291 Overdue Payment Reminder",
            "risk_score": 64.0,
            "risk_level": "High",
            "status": "New",
            "assigned_to_user_id": None,
            "is_sample": True,
            "created_at": datetime.datetime.utcnow() - datetime.timedelta(hours=14),
            "analysis": {
                "id": "ANL-SAMPLE-0003",
                "subject": "Invoice INV-88291 Overdue Payment Reminder",
                "sender": "QuickBooks Billing <billing@quickbooks-invoicing-center.org>",
                "reply_to": "billing@quickbooks-invoicing-center.org",
                "recipient": "accounting@smallbiz.org",
                "body_snippet": "Please find attached the past due invoice INV-88291. Open invoice.iso immediately to avoid late fees.",
                "urls_count": 0,
                "attachments_count": 1,
                "risk_score": 64.0,
                "risk_level": "High",
                "confidence_score": "Medium (75%)",
                "indicator_details": [
                    {
                        "category": "Dangerous Attachment Extension",
                        "severity": "High",
                        "weight": 35,
                        "description": "Attachment 'invoice.iso' uses disk image extension .iso commonly used to bypass mark-of-the-web and deliver malware payloads."
                    },
                    {
                        "category": "Fake Invoice / Financial Urgency",
                        "severity": "Medium",
                        "weight": 29,
                        "description": "Demands immediate payment for unknown invoice with threat of penalties."
                    }
                ],
                "ai_explanation": [
                    {
                        "finding": "Suspicious disk image attachment disguised as invoice",
                        "evidence": "Attachment named 'invoice.iso' is an ISO container, not a standard PDF or document file.",
                        "why_it_matters": "Malware authors package malicious executables inside ISO files so Windows auto-mounts them without triggering browser download warnings.",
                        "recommended_action": "Do not double-click or mount the attachment. Submit file hash to sandbox."
                    }
                ],
                "recommendations": [
                    "Do not mount or extract invoice.iso on endpoint.",
                    "Check email gateway rules to quarantine inbound disk images (.iso, .img, .vhd)."
                ],
                "missing_evidence": [
                    "Attachment binary contents were not executed or analyzed in dynamic sandbox (static metadata only)."
                ]
            },
            "notes": []
        },
        {
            "id": "INC-2026-0004",
            "title": "Quarterly Operations Review & Planning Sync",
            "risk_score": 14.0,
            "risk_level": "Low",
            "status": "Resolved",
            "assigned_to_user_id": analyst_id,
            "is_sample": True,
            "created_at": datetime.datetime.utcnow() - datetime.timedelta(days=1),
            "analysis": {
                "id": "ANL-SAMPLE-0004",
                "subject": "Quarterly Operations Review & Planning Sync",
                "sender": "Jessica Miller <jmiller@partner-consulting.com>",
                "reply_to": "jmiller@partner-consulting.com",
                "recipient": "team@smallbiz.org",
                "body_snippet": "Hi everyone, here is the agenda for our upcoming quarterly sync next Tuesday at 2 PM. Please let me know if you would like to add any discussion points.",
                "urls_count": 0,
                "attachments_count": 0,
                "risk_score": 14.0,
                "risk_level": "Low",
                "confidence_score": "High (88%)",
                "indicator_details": [],
                "ai_explanation": [
                    {
                        "finding": "No overt phishing indicators detected",
                        "evidence": "Sender and Reply-to match legitimate domain; polite non-coercive tone; no links or attachments.",
                        "why_it_matters": "Routine business communications rarely feature credential harvesting or urgency cues, but users should remain vigilant.",
                        "recommended_action": "Standard review; safe to accept calendar invite."
                    }
                ],
                "recommendations": [
                    "Review available evidence; note that PhishGuard AI does not assume the message is guaranteed safe without out-of-band context.",
                    "Verify meeting link inside your trusted calendar client."
                ],
                "missing_evidence": []
            },
            "notes": [
                {
                    "author_name": "Alex Mercer (SOC Analyst)",
                    "note_text": "Legitimate partner meeting request. Marked as resolved / benign."
                }
            ]
        },
        {
            "id": "INC-2026-0005",
            "title": "Dropbox File Share: Confidential Tax Document",
            "risk_score": 48.0,
            "risk_level": "Medium",
            "status": "False Positive",
            "assigned_to_user_id": analyst_id,
            "is_sample": True,
            "created_at": datetime.datetime.utcnow() - datetime.timedelta(days=2),
            "analysis": {
                "id": "ANL-SAMPLE-0005",
                "subject": "Dropbox File Share: Confidential Tax Document",
                "sender": "Dropbox Notifications <no-reply@dropboxmail.com>",
                "reply_to": "no-reply@dropboxmail.com",
                "recipient": "hr@smallbiz.org",
                "body_snippet": "A file was shared with you on Dropbox: 2025_Tax_Forms.pdf. View it here: https://www.dropbox.com/scl/fi/taxdocs",
                "urls_count": 1,
                "attachments_count": 0,
                "risk_score": 48.0,
                "risk_level": "Medium",
                "confidence_score": "Medium (70%)",
                "indicator_details": [
                    {
                        "category": "External Cloud Storage Link",
                        "severity": "Medium",
                        "weight": 25,
                        "description": "Contains cloud document sharing link requiring authentication."
                    },
                    {
                        "category": "Sensitive Tax / Financial Theme",
                        "severity": "Medium",
                        "weight": 23,
                        "description": "Subject references confidential tax documents, common social engineering bait."
                    }
                ],
                "ai_explanation": [
                    {
                        "finding": "External file-sharing notification with financial theme",
                        "evidence": "Email is from legitimate Dropbox domain but refers to confidential corporate tax files.",
                        "why_it_matters": "Attackers frequently abuse legitimate cloud storage services to host phishing forms or bypass gateway reputation filters.",
                        "recommended_action": "Confirm with internal HR or accounting whether this tax file was expected."
                    }
                ],
                "recommendations": [
                    "Verify the sender with HR before entering corporate credentials on cloud storage prompts.",
                    "Never enter single-sign-on credentials into third-party cloud forms."
                ],
                "missing_evidence": []
            },
            "notes": [
                {
                    "author_name": "Alex Mercer (SOC Analyst)",
                    "note_text": "HR verified that this file was shared by our official external CPA firm. Closed as False Positive."
                }
            ]
        }
    ]

    for item in samples:
        anl_data = item["analysis"]
        analysis = EmailAnalysis(
            id=anl_data["id"],
            subject=anl_data["subject"],
            sender=anl_data["sender"],
            reply_to=anl_data["reply_to"],
            recipient=anl_data["recipient"],
            body_snippet=anl_data["body_snippet"],
            has_eml=False,
            urls_count=anl_data["urls_count"],
            attachments_count=anl_data["attachments_count"],
            risk_score=anl_data["risk_score"],
            risk_level=anl_data["risk_level"],
            confidence_score=anl_data["confidence_score"],
            indicator_details=anl_data["indicator_details"],
            ai_explanation=anl_data["ai_explanation"],
            recommendations=anl_data["recommendations"],
            missing_evidence=anl_data["missing_evidence"],
            is_synthetic=True,
            analyzed_by_user_id=analyst_id,
            created_at=item["created_at"]
        )
        db.add(analysis)
        db.flush()

        incident = Incident(
            id=item["id"],
            title=item["title"],
            risk_score=item["risk_score"],
            risk_level=item["risk_level"],
            status=item["status"],
            assigned_to_user_id=item["assigned_to_user_id"],
            analysis_id=analysis.id,
            is_sample=True,
            created_at=item["created_at"],
            updated_at=item["created_at"]
        )
        db.add(incident)
        db.flush()

        for note in item["notes"]:
            db_note = AnalystNote(
                incident_id=incident.id,
                user_id=analyst_id,
                author_name=note["author_name"],
                note_text=note["note_text"],
                created_at=item["created_at"] + datetime.timedelta(minutes=15)
            )
            db.add(db_note)

        history = StatusHistory(
            incident_id=incident.id,
            user_id=analyst_id,
            user_name="System Initializer",
            old_status="New",
            new_status=item["status"],
            comment="Seeded demo triage status",
            timestamp=item["created_at"]
        )
        db.add(history)

    db.commit()

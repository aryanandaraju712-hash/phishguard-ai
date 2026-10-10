from typing import List, Dict, Any
from fastapi import APIRouter

router = APIRouter(prefix="/samples", tags=["Hackathon Demo Center"])

SYNTHETIC_DEMO_SAMPLES: List[Dict[str, Any]] = [
    {
        "id": "sample-1-meeting",
        "title": "Normal Meeting Invitation",
        "badge": "Benign / Low Risk",
        "expected_risk": "Low (0-29)",
        "description": "Routine quarterly business planning meeting invitation between legitimate colleagues with no links or coercive pressure.",
        "data": {
            "subject": "Quarterly Operations Review & Planning Sync",
            "sender": "Jessica Miller <jmiller@partner-consulting.com>",
            "reply_to": "jmiller@partner-consulting.com",
            "recipient": "team@smallbiz.org",
            "body": "Hi everyone,\n\nI hope you are having a productive week. Attached below is the agenda for our upcoming quarterly sync scheduled for next Tuesday at 2:00 PM EST.\n\nPlease let me know if you would like to include any specific operational review items or supply chain metrics before Friday.\n\nBest regards,\nJessica Miller\nPartner Operations",
            "urls": []
        }
    },
    {
        "id": "sample-2-account-verification",
        "title": "Suspicious Account Verification Alert",
        "badge": "Phishing / High Risk",
        "expected_risk": "High (60-79)",
        "description": "False security alarm claiming unauthorized login activity with strict 24-hour deadline and external domain link.",
        "data": {
            "subject": "Security Alert: Unauthorized login attempt detected on your account",
            "sender": "IT Support Desk <security-notification@internal-it-support-notice.com>",
            "reply_to": "security-notification@internal-it-support-notice.com",
            "recipient": "employee@smallbiz.org",
            "body": "CRITICAL SECURITY WARNING:\n\nOur automated security telemetry detected an unauthorized sign-in attempt to your corporate account from an unknown IP address in Moscow, Russia.\n\nYour account access will be deactivated and suspended within 24 hours unless you immediately verify your credentials and authenticate your account.\n\nClick below to verify your account:\nhttp://login.security-verification-portal.xyz/verify-auth\n\nIf you do not verify within 24 hours, all corporate access will be revoked permanently.",
            "urls": ["http://login.security-verification-portal.xyz/verify-auth"]
        }
    },
    {
        "id": "sample-3-fake-invoice",
        "title": "Fake Overdue Invoice & Urgent Payment Request",
        "badge": "Malware & BEC / Critical Risk",
        "expected_risk": "Critical (80-100)",
        "description": "Unsolicited invoice demanding immediate payment to avoid penalties, referencing a dangerous .iso disk image attachment.",
        "data": {
            "subject": "FINAL NOTICE: Overdue Invoice INV-94819 Past Due - Legal Action Pending",
            "sender": "QuickBooks Billing Department <billing-notice@quickbooks-accounting-hub.org>",
            "reply_to": "billing-notice@quickbooks-accounting-hub.org",
            "recipient": "accounting@smallbiz.org",
            "body": "Dear Accounts Payable,\n\nWe have not received payment for invoice INV-94819 totaling $14,250.00 which is now 45 days overdue.\n\nImmediate wire payment is required today. Failure to remit payment within 24 hours will result in immediate suspension of services and legal escalation.\n\nPlease find the detailed line-item statement attached: invoice_statement_94819.iso\n\nWire instructions are outlined inside the document. Please remit payment via bank transfer immediately.",
            "urls": []
        }
    },
    {
        "id": "sample-4-executive-impersonation",
        "title": "Sender Impersonation (CEO Fraud / BEC)",
        "badge": "BEC / High-Critical Risk",
        "expected_risk": "Critical (80-100)",
        "description": "Attacker poses as company CEO asking for confidential wire transfer while claiming to be in a meeting, with Reply-To pointing to a personal Gmail address.",
        "data": {
            "subject": "Confidential Request from CEO Mark Sterling [CONFIDENTIAL]",
            "sender": "Mark Sterling <m.sterling@executive-corporate-management.com>",
            "reply_to": "mark.sterling.private.mobile@gmail.com",
            "recipient": "controller@smallbiz.org",
            "body": "Good morning,\n\nI am currently in an all-day executive board meeting and cannot take phone calls right now.\n\nWe are closing an urgent strategic supplier acquisition today and need to process a confidential wire transfer of $38,500 immediately. I need you to handle this discreetly without discussing it with anyone in the office.\n\nPlease reply directly to this email so I can forward you the wire payment instructions and vendor routing number.\n\nThanks,\nMark Sterling\nChief Executive Officer",
            "urls": []
        }
    },
    {
        "id": "sample-5-ip-credential-harvest",
        "title": "Credential Theft with IP Link & Typosquatting",
        "badge": "Credential Theft / Critical Risk",
        "expected_risk": "Critical (80-100)",
        "description": "Microsoft 365 password expiration lure directing victims to a raw IP address login page, utilizing leetspeak typosquatting.",
        "data": {
            "subject": "Microsoft 365: Your password expires today - Keep your current password",
            "sender": "Microsoft IT Admin <admin@micros0ft-online-security.com>",
            "reply_to": "admin@micros0ft-online-security.com",
            "recipient": "staff@smallbiz.org",
            "body": "Office 365 Password Expiration Notice\n\nYour organizational password is scheduled to expire in 2 hours. To keep your current password and avoid losing access to your email and files, you must verify your identity immediately.\n\nClick the link below to confirm your password:\nhttp://185.193.12.84/m365/login?user=staff@smallbiz.org\n\nEnter your current password and one-time code to retain your active session.\n\nMicrosoft Global Security Team",
            "urls": ["http://185.193.12.84/m365/login?user=staff@smallbiz.org"]
        }
    },
    {
        "id": "sample-6-spam-lottery",
        "title": "Promotional Prize & Crypto Investment Spam",
        "badge": "Spam / Moderate Risk",
        "expected_risk": "Moderate (25-49)",
        "description": "Unsolicited promotional lottery win and crypto multiplier claim with excessive marketing buzzwords.",
        "data": {
            "subject": "CONGRATULATIONS! You have won our $500,000 Crypto Cash Reward Prize!",
            "sender": "Global Rewards Promotion <promo-winner@global-jackpot-draws.net>",
            "reply_to": "promo-winner@global-jackpot-draws.net",
            "recipient": "user@smallbiz.org",
            "body": "Congratulations Valued User!\n\nYou have been randomly selected as our grand lottery winner for an exclusive prize cash reward of $500,000 in Bitcoin.\n\nThis is a limited time offer with guaranteed returns and passive income guaranteed! Act fast before it is gone.\n\nClaim your prize and free gift card now by confirming your payout selection today.\n\nClick here to unsubscribe or to be removed from our list.\nGlobal Promo Sweepstakes Team",
            "urls": []
        }
    },
    {
        "id": "sample-7-suspicious-url",
        "title": "Deceptive Brand Typosquatting URL",
        "badge": "Phishing URL / High Risk",
        "expected_risk": "High (50-74)",
        "description": "Deceptive PayPal lookalike domain utilizing leetspeak typosquatting and suspicious login verification keywords.",
        "data": {
            "subject": "Suspicious URL Inspection",
            "sender": "URL Inspector",
            "reply_to": None,
            "recipient": "security@smallbiz.org",
            "body": "Inspect destination: http://paypa1-account-security-verify.xyz/signin",
            "urls": ["http://paypa1-account-security-verify.xyz/signin"]
        }
    }
]

@router.get("", response_model=List[Dict[str, Any]])
def get_synthetic_samples():
    """Returns synthetic demonstration samples for the Hackathon Demo Center."""
    return SYNTHETIC_DEMO_SAMPLES

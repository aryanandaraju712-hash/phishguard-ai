"""
PhishGuard AI — Labeled Evaluation Dataset
Curated benchmark samples for evaluating:
1. URL Phishing Detection (lexical & structural heuristics)
2. AI Email Spam Detection (DistilBERT model & heuristic pattern extraction)
3. Combined Triage Risk Engine
"""

from typing import List, Dict, Any

# ============================================================================
# 1. URL Evaluation Benchmark Dataset
# ============================================================================
# Positive class definition:
# ground_truth_suspicious = True indicates a URL exhibiting phishing, obfuscation,
# or suspicious structural signatures that warrant security analyst triage.

URL_EVALUATION_DATASET: List[Dict[str, Any]] = [
    # Category: Benign HTTPS
    {
        "url": "https://www.google.com/search?q=cybersecurity+training",
        "category": "Benign HTTPS",
        "ground_truth_suspicious": False,
        "description": "Standard legitimate search engine query over HTTPS"
    },
    {
        "url": "https://github.com/explore",
        "category": "Benign HTTPS",
        "ground_truth_suspicious": False,
        "description": "Legitimate code repository explore page"
    },
    {
        "url": "https://docs.python.org/3/library/urllib.parse.html",
        "category": "Benign HTTPS",
        "ground_truth_suspicious": False,
        "description": "Official Python documentation page"
    },
    {
        "url": "https://aws.amazon.com/solutions/",
        "category": "Benign HTTPS",
        "ground_truth_suspicious": False,
        "description": "Standard cloud provider corporate solution page"
    },

    # Category: Benign HTTP
    {
        "url": "http://example.com/index.html",
        "category": "Benign HTTP",
        "ground_truth_suspicious": False,
        "description": "IANA RFC 2606 standard reserved example domain over HTTP"
    },
    {
        "url": "http://info.cern.ch/hypertext/WWW/TheProject.html",
        "category": "Benign HTTP",
        "ground_truth_suspicious": False,
        "description": "Historical CERN web page served over plain HTTP"
    },

    # Category: IP-Address Hostnames (Suspicious / Phishing)
    {
        "url": "http://192.168.1.1/admin-login",
        "category": "IP-Address Hostname",
        "ground_truth_suspicious": True,
        "description": "Numeric private IP address host with administrative credential lure"
    },
    {
        "url": "http://45.33.32.156:8080/portal/auth",
        "category": "IP-Address Hostname",
        "ground_truth_suspicious": True,
        "description": "Public numeric IP address with custom port and authentication path"
    },
    {
        "url": "http://218.92.0.214/webmail/login.php",
        "category": "IP-Address Hostname",
        "ground_truth_suspicious": True,
        "description": "Numeric IP host hosting a targeted webmail login portal lure"
    },

    # Category: Suspicious URL Structures & Obfuscation
    {
        "url": "https://legit-service.com@malicious-harvesting-portal.xyz/login",
        "category": "Suspicious URL Structure (@ Symbol)",
        "ground_truth_suspicious": True,
        "description": "URL embedding deceptive authority credentials using the '@' symbol"
    },
    {
        "url": "http://bank-of-america.secure-verification.login-auth.account-update.xyz/verify",
        "category": "Excessive Subdomains",
        "ground_truth_suspicious": True,
        "description": "Deceptive brand impersonation with 4+ subdomain layers"
    },
    {
        "url": "https://login.microsoft.com.account-security-incident-response.top/auth",
        "category": "Lookalike Subdomain Impersonation",
        "ground_truth_suspicious": True,
        "description": "Lookalike subdomain prepending trusted brand to high-risk TLD"
    },

    # Category: URL Shortening Services
    {
        "url": "https://bit.ly/3xYqz9P",
        "category": "URL Shortener",
        "ground_truth_suspicious": True,
        "description": "Shortened link concealing underlying destination domain"
    },
    {
        "url": "https://tinyurl.com/bank-security-update",
        "category": "URL Shortener",
        "ground_truth_suspicious": True,
        "description": "Shortened link with deceptive credential-lure vanity alias"
    },

    # Category: Suspicious Credential-Related Paths
    {
        "url": "http://secure-update-notice.net/account/password-reset/verify-identity",
        "category": "Credential Lure Path",
        "ground_truth_suspicious": True,
        "description": "Multiple credential harvesting keywords in path on unverified domain"
    },
    {
        "url": "http://paypal-resolution-center.info/cgi-bin/webscr?cmd=_login-run",
        "category": "Credential Lure Path",
        "ground_truth_suspicious": True,
        "description": "Exact query structure imitating financial service login"
    },

    # Category: Legitimate URLs with Unusual Query Characters / Anchors
    {
        "url": "https://en.wikipedia.org/wiki/Phishing_(security)#Techniques_and_countermeasures",
        "category": "Legitimate Unusual Characters",
        "ground_truth_suspicious": False,
        "description": "Legitimate encyclopedia URL with parentheses and section anchors"
    },
    {
        "url": "https://stackoverflow.com/questions/tagged/c%2B%2B?tab=Votes",
        "category": "Legitimate Unusual Characters",
        "ground_truth_suspicious": False,
        "description": "Developer forum URL with percent-encoded programming language tags"
    },

    # Category: Malformed / Edge Case URLs
    {
        "url": "not_a_valid_url_just_text",
        "category": "Malformed URL",
        "ground_truth_suspicious": False,
        "description": "Malformed string lacking scheme and hostname structure"
    },
    {
        "url": "http:///missing-hostname/path",
        "category": "Malformed URL",
        "ground_truth_suspicious": False,
        "description": "Malformed URL structure with empty host portion"
    }
]


# ============================================================================
# 2. Email Evaluation Benchmark Dataset
# ============================================================================
# Labels:
# ground_truth_spam: Unsolicited bulk marketing, promotional lures, lotteries
# ground_truth_phishing: Deceptive social engineering, credential theft, BEC
# ground_truth_suspicious: Either spam or phishing requiring triage flag

EMAIL_EVALUATION_DATASET: List[Dict[str, Any]] = [
    # Category: Legitimate Personal Email
    {
        "id": "EML-BENIGN-01",
        "category": "Legitimate Personal",
        "ground_truth_spam": False,
        "ground_truth_phishing": False,
        "ground_truth_suspicious": False,
        "subject": "Family dinner this Sunday at 6 PM",
        "sender": "sarah.jenkins@gmail.com",
        "body": "Hi Aryan, hope you are doing well! Mom and Dad wanted to know if you can make it for Sunday dinner at 6 PM. Let us know if you need a ride from campus.",
        "description": "Authentic personal correspondence with no links or coercive pressure"
    },
    {
        "id": "EML-BENIGN-02",
        "category": "Legitimate Personal",
        "ground_truth_spam": False,
        "ground_truth_phishing": False,
        "ground_truth_suspicious": False,
        "subject": "Notes from today's study group session",
        "sender": "david_kumar@outlook.com",
        "body": "Hey, here are the summary notes from our algorithms review session this afternoon. Let's touch base again on Thursday before the midterms.",
        "description": "Normal peer-to-peer study group notes without external lures"
    },

    # Category: Legitimate Organizational Email
    {
        "id": "EML-BENIGN-03",
        "category": "Legitimate Organizational",
        "ground_truth_spam": False,
        "ground_truth_phishing": False,
        "ground_truth_suspicious": False,
        "subject": "Quarterly Operations Review & Planning Sync",
        "sender": "jmiller@partner-consulting.com",
        "body": "Hi team, attached is the agenda for our upcoming quarterly operations sync scheduled for next Tuesday at 2:00 PM EST. Please submit discussion topics by Friday.",
        "description": "Routine corporate scheduling email"
    },
    {
        "id": "EML-BENIGN-04",
        "category": "Legitimate Organizational with Link",
        "ground_truth_spam": False,
        "ground_truth_phishing": False,
        "ground_truth_suspicious": False,
        "subject": "Sprint retrospective documentation updated",
        "sender": "lead-dev@internal-corp.net",
        "body": "Hello everyone, the sprint retrospective action items have been documented. You can view the engineering notes at https://github.com/explore. Please review when you have time.",
        "description": "Legitimate workplace notification containing a safe, trusted HTTPS link"
    },

    # Category: Bulk Promotional Spam
    {
        "id": "EML-SPAM-01",
        "category": "Bulk Promotional Spam",
        "ground_truth_spam": True,
        "ground_truth_phishing": False,
        "ground_truth_suspicious": True,
        "subject": "CONGRATULATIONS! You have won our $500,000 Cash Reward Prize!",
        "sender": "promo-winner@global-jackpot-draws.net",
        "body": "Congratulations Valued Winner! You have been selected as our grand lottery winner for an exclusive cash reward of $500,000! Limited time offer with guaranteed passive income! Click here to unsubscribe from our mailing list.",
        "description": "Classic high-volume lottery and cash reward promotional spam"
    },
    {
        "id": "EML-SPAM-02",
        "category": "Bulk Promotional Spam",
        "ground_truth_spam": True,
        "ground_truth_phishing": False,
        "ground_truth_suspicious": True,
        "subject": "Exclusive Discount: 80% Off Luxury Watches and Designer Goods",
        "sender": "deals@super-mega-discount-store.biz",
        "body": "Special limited time discount! Save up to 80% on brand name luxury goods today only. Act fast before stock runs out. Free worldwide shipping on all orders over $50.",
        "description": "Commercial mass advertising spam"
    },

    # Category: Phishing-Style Credential Harvesting
    {
        "id": "EML-PHISH-01",
        "category": "Credential Harvesting Phishing",
        "ground_truth_spam": False,
        "ground_truth_phishing": True,
        "ground_truth_suspicious": True,
        "subject": "CRITICAL: Unauthorized sign-in detected on your corporate account",
        "sender": "security-notification@internal-it-support-notice.com",
        "body": "CRITICAL SECURITY WARNING: Automated telemetry detected unauthorized sign-in to your account. Your access will be suspended within 24 hours unless you verify your credentials at http://192.168.1.1/admin-login immediately.",
        "description": "High-urgency credential harvesting attack pointing to a numeric IP host"
    },
    {
        "id": "EML-PHISH-02",
        "category": "Credential Harvesting Phishing",
        "ground_truth_spam": False,
        "ground_truth_phishing": True,
        "ground_truth_suspicious": True,
        "subject": "Urgent: Action Required - Verify Your Microsoft 365 Password",
        "sender": "admin@it-helpdesk-security-update.org",
        "body": "Your password is scheduled to expire today. Please confirm your current password and OTP to retain your corporate email inbox access.",
        "description": "Password and OTP credential harvesting attack"
    },

    # Category: Executive Impersonation / CEO Wire Fraud (BEC)
    {
        "id": "EML-BEC-01",
        "category": "Executive Impersonation (BEC)",
        "ground_truth_spam": False,
        "ground_truth_phishing": True,
        "ground_truth_suspicious": True,
        "subject": "Confidential Request from CEO Mark Sterling [CONFIDENTIAL]",
        "sender": "Mark Sterling <ceo-executive-office@gmail.com>",
        "body": "Are you at your desk right now? I am currently in a closed-door acquisition meeting and need an urgent wire transfer processed before 3 PM today. Do not call my office phone. Reply directly to this email with confirmation.",
        "description": "Executive spoofing wire fraud utilizing freemail sender address and urgency"
    },
    {
        "id": "EML-BEC-02",
        "category": "Fake Invoice Payment Lure",
        "ground_truth_spam": False,
        "ground_truth_phishing": True,
        "ground_truth_suspicious": True,
        "subject": "FINAL NOTICE: Overdue Invoice INV-94819 Past Due - Legal Escalation",
        "sender": "billing@quickbooks-accounting-hub.org",
        "body": "Dear Accounts Payable, we have not received payment for invoice INV-94819 totaling $14,250.00. Immediate wire transfer is required today. Failure to remit payment within 24 hours will result in immediate legal escalation.",
        "description": "Urgent payment demand with coercive legal action threats"
    },

    # Category: Edge Case - Legitimate Email with Urgent Wording and Link
    {
        "id": "EML-EDGE-01",
        "category": "Legitimate Urgent with Link (Edge Case)",
        "ground_truth_spam": False,
        "ground_truth_phishing": False,
        "ground_truth_suspicious": False,
        "subject": "URGENT: Server outage incident retrospective meeting at 4 PM",
        "sender": "cto@corporate-domain.com",
        "body": "Team, due to the critical production database outage this morning, we need an urgent post-mortem sync at 4 PM today. Please review the incident log at https://docs.python.org/3/library/urllib.parse.html before joining.",
        "description": "Legitimate high-urgency message containing benign link; evaluates false positive resistance"
    },
    {
        "id": "EML-EDGE-02",
        "category": "Legitimate Urgent (Edge Case)",
        "ground_truth_spam": False,
        "ground_truth_phishing": False,
        "ground_truth_suspicious": False,
        "subject": "Urgent: Flight schedule change notice from Delta Air Lines",
        "sender": "ticket-updates@delta.com",
        "body": "Dear Passenger, your flight DL-482 has been rescheduled due to severe weather. Please arrive at the airport 2 hours before departure. Check your mobile boarding pass.",
        "description": "Legitimate commercial notification containing urgent keywords without credential demands"
    }
]

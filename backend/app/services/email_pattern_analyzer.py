"""
Explainable Email Pattern Analyzer.
Performs transparent lexical and structural heuristic evaluation of email subject and body.
Extracts explainable indicators for urgency, credential harvesting, wire fraud/BEC,
lottery/prize lures, promotional spam, and sender mismatches.
"""

import re
from typing import Dict, Any, List, Optional, Tuple


# Heuristic pattern definitions with severity, weights, and explanations
URGENCY_PATTERNS = [
    (
        r"\b(?:urgent(?:ly)?|immediate action|act now|suspended|suspension|deactivat(?:ed|ion)|terminat(?:ed|ion))\b",
        "Urgency / Threat of Account Suspension",
        "High",
        18,
        "Coercive urgency is heavily leveraged in social engineering to pressure victims into making impulsive security decisions without verifying authenticity."
    ),
    (
        r"\b(?:within\s+(?:24|48|12|2|1)\s+(?:hours|hrs|minutes|mins)|deadline\s+approaching|final notice|last warning)\b",
        "Strict Time Limit Coercion",
        "High",
        16,
        "Artificial deadlines create psychological pressure to bypass standard organizational verification procedures."
    ),
    (
        r"\b(?:unauthorized access|security breach|unusual activity|compromised account|flagged for fraud)\b",
        "Security Alarm / Threat Deception",
        "High",
        16,
        "Simulated security alarms scare users into logging into fraudulent identity-harvesting portals."
    )
]

CREDENTIAL_HARVEST_PATTERNS = [
    (
        r"\b(?:verify (?:your )?(?:password|credentials|account|identity)|confirm (?:your )?login)\b",
        "Account Credential Verification Request",
        "Critical",
        25,
        "Direct requests to verify passwords or login credentials from an inbound email are classic phishing signatures."
    ),
    (
        r"\b(?:enter your (?:password|pin|otp|passcode|one-time code)|input your credentials)\b",
        "Direct Request for Password / One-Time Passcode",
        "Critical",
        28,
        "Legitimate organizations never solicit passwords, PINs, or Multi-Factor Authentication (MFA) codes through email messages."
    ),
    (
        r"\b(?:keep your current password|password will expire|avoid account closure)\b",
        "Password Retention / Expiration Trick",
        "High",
        22,
        "Deceptive claims of imminent password expiration manipulate users into visiting credential-harvesting landing pages."
    ),
    (
        r"\b(?:social security|ssn|date of birth|credit card number|cvv|bank account number)\b",
        "Request for High-Value PII or Financial Card Data",
        "Critical",
        30,
        "Unsolicited emails soliciting government IDs, banking details, or card CVVs represent severe identity theft vectors."
    )
]

FINANCIAL_BEC_PATTERNS = [
    (
        r"\b(?:wire transfer|wire payment|swift code|bank transfer|routing number|remit(?:tance)? advice)\b",
        "Unsolicited Wire Transfer / Banking Instructions",
        "Critical",
        26,
        "Business Email Compromise (BEC) campaigns frequently hijack corporate communications to divert wire transfers to adversary accounts."
    ),
    (
        r"\b(?:overdue invoice|past due invoice|payment reminder|invoice attached|outstanding balance)\b",
        "Urgent Overdue Invoice Theme",
        "High",
        18,
        "Fake invoice themes provoke financial departments into opening infected attachments or issuing unauthorized vendor payments."
    ),
    (
        r"\b(?:gift cards?|apple (?:gift )?card|itunes card|steam (?:wallet )?card|google play card)\b",
        "Gift Card Reimbursement Fraud",
        "Critical",
        28,
        "Requests for gift card purchases are untraceable and represent virtually definitive signs of executive impersonation scams."
    ),
    (
        r"\b(?:in a meeting|busy right now|cannot take calls|confidential request|process this quietly)\b",
        "Executive Isolation / Out-of-Band Coercion",
        "High",
        22,
        "Attackers claim executives are unavailable for phone verification to isolate the recipient and bypass financial dual-control checks."
    )
]

LOTTERY_PRIZE_PATTERNS = [
    (
        r"\b(?:you(?:'ve|\s+have)? won|lottery winner|claim your prize|cash reward|sweepstakes winner|jackpot)\b",
        "Lottery / Prize Scam Theme",
        "High",
        22,
        "Unsolicited claims of cash prizes, lotteries, or sweepstakes are widespread lures in advance-fee spam operations."
    ),
    (
        r"\b(?:crypto(?:currency)? profit|bitcoin multiplier|guaranteed returns?|passive income guaranteed|risk[- ]free investment)\b",
        "High-Yield Investment / Cryptocurrency Scam",
        "High",
        24,
        "Promises of guaranteed crypto yields or zero-risk windfalls indicate fraudulent investment schemes."
    ),
    (
        r"\b(?:million dollars|inheritance funds?|consignment box|diplomatic courier|next of kin claim)\b",
        "Advance-Fee (419) Scam Theme",
        "Critical",
        28,
        "Classic advance-fee fraud soliciting personal cooperation in exchange for a percentage of fictitious multi-million-dollar inheritances."
    )
]

PROMOTIONAL_SPAM_PATTERNS = [
    (
        r"\b(?:exclusive (?:deal|discount)|limited time (?:offer|discount)|huge discount|special promotion|act fast)\b",
        "Aggressive Promotional Lure",
        "Medium",
        14,
        "Bulk advertising keywords designed to manufacture false scarcity and generate click-throughs."
    ),
    (
        r"\b(?:click here to unsubscribe|opt[- ]out here|manage your email preferences|to be removed from our list)\b",
        "Bulk Marketing Unsubscribe Disclosures",
        "Low",
        8,
        "Standard footers found in legitimate marketing as well as unsolicited bulk marketing campaigns."
    ),
    (
        r"\b(?:weight loss miracle|diet pills?|viagra|cialis|online pharmacy|cheap meds)\b",
        "Pharmaceutical / Illicit Product Spam",
        "High",
        22,
        "Classic product spam circulating unauthorized medical or weight-loss supplements."
    )
]

EXECUTIVE_TITLES = [
    "ceo", "chief executive officer", "cfo", "chief financial officer",
    "president", "director", "founder", "chairman", "vice president", "vp"
]

COMMON_FREEMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com", "protonmail.com", "icloud.com"
}


def analyze_email_patterns(
    subject: str,
    body: str,
    sender: Optional[str] = None,
    reply_to: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Evaluates explainable heuristic patterns in email subject and body.
    Returns structured list of detected indicators with category, severity, weight,
    description, evidence, and cybersecurity rationale.
    """
    combined_text = f"{subject}\n{body}"
    indicators: List[Dict[str, Any]] = []
    seen_categories = set()

    def check_pattern_group(patterns):
        for regex, category, severity, weight, why_it_matters in patterns:
            if category in seen_categories:
                continue
            matches = list(re.finditer(regex, combined_text, re.IGNORECASE))
            if matches:
                # Capture matched snippet without exposing excessive context
                snippet = matches[0].group(0)
                indicators.append({
                    "category": category,
                    "severity": severity,
                    "weight": weight,
                    "description": f"Detected matching pattern for '{category}'.",
                    "evidence": f"Found snippet: \"{snippet}\"",
                    "why_it_matters": why_it_matters
                })
                seen_categories.add(category)

    # Check each pattern group
    check_pattern_group(CREDENTIAL_HARVEST_PATTERNS)
    check_pattern_group(FINANCIAL_BEC_PATTERNS)
    check_pattern_group(URGENCY_PATTERNS)
    check_pattern_group(LOTTERY_PRIZE_PATTERNS)
    check_pattern_group(PROMOTIONAL_SPAM_PATTERNS)

    # Check sender vs executive display name
    if sender:
        sender_clean = sender.strip().lower()
        has_exec_title = any(title in sender_clean for title in EXECUTIVE_TITLES)
        is_freemail = any(freemail in sender_clean for freemail in COMMON_FREEMAIL_DOMAINS)

        if has_exec_title and is_freemail:
            category = "Executive Impersonation via Freemail Domain"
            if category not in seen_categories:
                indicators.append({
                    "category": category,
                    "severity": "Critical",
                    "weight": 28,
                    "description": "Sender display name claims executive authority but sends from a public freemail provider.",
                    "evidence": f"Sender: {sender[:50]}",
                    "why_it_matters": "Threat actors routinely register free webmail accounts using executive names to solicit urgent employee actions."
                })
                seen_categories.add(category)

    # Check sender vs reply-to discrepancy
    if sender and reply_to:
        sender_domain = sender.split("@")[-1].strip().lower() if "@" in sender else ""
        reply_domain = reply_to.split("@")[-1].strip().lower() if "@" in reply_to else ""
        if sender_domain and reply_domain and sender_domain != reply_domain:
            category = "Sender vs Reply-To Domain Mismatch"
            if category not in seen_categories:
                indicators.append({
                    "category": category,
                    "severity": "High",
                    "weight": 22,
                    "description": f"Sender domain ('{sender_domain}') does not match reply-to destination ('{reply_domain}').",
                    "evidence": f"Sender: @{sender_domain} vs Reply-To: @{reply_domain}",
                    "why_it_matters": "Directing replies to a different domain is a standard technique used to bypass display-name inspection and route communications to an attacker-controlled inbox."
                })
                seen_categories.add(category)

    return indicators

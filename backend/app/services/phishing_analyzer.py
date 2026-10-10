import re
from typing import Dict, Any, List, Tuple
from app.core.config import settings
from app.services.url_analyzer import analyze_url, check_brand_lookalike

# Lexical heuristic dictionaries for content inspection
URGENCY_PATTERNS = [
    (r"\b(?:urgent|immediately|immediate action|act now|suspended|suspension|terminate|deactivate)\b", "Urgency / Threat of Account Termination", 12),
    (r"\b(?:within\s+(?:24|48|12|2|1)\s+(?:hours|hrs|minutes|mins))\b", "Strict Time Limit Coercion", 14),
    (r"\b(?:unauthorized access|security breach|unusual activity|compromised|flagged for fraud)\b", "Security Alarm / False Threat Alert", 14),
    (r"\b(?:final notice|last warning|account will be locked|access restricted)\b", "Severe Penalty Threat", 15)
]

CREDENTIAL_HARVEST_PATTERNS = [
    (r"\b(?:verify (?:your )?(?:password|credentials|account|identity))\b", "Request to Verify Account Credentials", 20),
    (r"\b(?:enter your (?:password|pin|otp|passcode|one-time code))\b", "Direct Request for Password or OTP", 25),
    (r"\b(?:login to confirm|sign in to keep your password|keep your current password)\b", "Credential Retention Trick", 22),
    (r"\b(?:social security|ssn|date of birth|credit card|card number|cvv)\b", "Request for Highly Sensitive PII or Financial Card Data", 28)
]

FINANCIAL_BEC_PATTERNS = [
    (r"\b(?:wire transfer|wire payment|swift code|bank transfer|routing number)\b", "Direct Wire Transfer Request", 22),
    (r"\b(?:overdue invoice|past due invoice|payment reminder|remittance advice|invoice attached)\b", "Unsolicited Overdue Invoice Theme", 16),
    (r"\b(?:gift cards?|apple card|itunes card|steam card|google play card)\b", "Gift Card Fraud Theme", 25),
    (r"\b(?:in a meeting|busy right now|cannot take calls|confidential request|process this quietly)\b", "Executive Isolation / Out-of-Office Coercion (BEC)", 20)
]

SPAM_PATTERNS = [
    (r"\b(?:you(?:'ve|\s+have)?\s+won|lottery\s+winner|claim\s+your\s+prize|claim\s+your\s+\$?\d+|cash\s+reward|sweepstakes\s+winner|jackpot)\b", "Lottery / Prize Scam Theme", 24),
    (r"\b(?:exclusive\s+(?:deal|offer|discount)|limited\s+time\s+offer|act\s+fast\s+before\s+it(?:'s|\s+is)\s+gone|special\s+promotion|huge\s+discount)\b", "Aggressive Promotional Lure", 15),
    (r"\b(?:crypto\s+profit|bitcoin\s+multiplier|guaranteed\s+returns?|earn\s+\$?\d+[\d,]*\s+(?:daily|weekly|a\s+day)|passive\s+income\s+guaranteed|risk[- ]free\s+investment)\b", "High-Yield Investment / Crypto Scam", 25),
    (r"\b(?:work\s+from\s+home\s+earn|no\s+experience\s+needed\s+earn|easy\s+money\s+from\s+home)\b", "Work-From-Home Scam", 18),
    (r"\b(?:weight\s+loss\s+miracle|diet\s+pills?|viagra|cialis|male\s+enhancement|online\s+pharmacy|cheap\s+meds)\b", "Pharmaceutical / Unsolicited Product Spam", 22),
    (r"\b(?:free\s+gift\s+card|walmart\s+gift\s+card|amazon\s+gift\s+card\s+reward|target\s+voucher|claim\s+gift\s+card)\b", "Gift Card Lure", 20),
    (r"\b(?:click\s+here\s+to\s+unsubscribe|opt[- ]out\s+here|manage\s+your\s+email\s+preferences|to\s+be\s+removed\s+from\s+our\s+list)\b", "Unsolicited Bulk Email Footers", 12),
    (r"\b(?:million\s+dollars|inheritance\s+funds?|consignment\s+box|diplomatic\s+courier|next\s+of\s+kin\s+claim|foreign\s+lottery)\b", "Advance-Fee (419) Scam Theme", 28),
]

EXECUTIVE_TITLES = [
    "ceo", "chief executive officer", "cfo", "chief financial officer",
    "president", "director", "founder", "chairman", "vice president", "vp"
]

COMMON_FREEMAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com", "protonmail.com", "icloud.com"
}

def evaluate_sender_integrity(sender: Dict[str, str], reply_to: Dict[str, str] = None) -> List[Dict[str, Any]]:
    """Evaluates indicators 1, 2, and 9 (Sender vs Display Name, Reply-To mismatch, Domain Typosquatting)."""
    indicators = []
    display_name = (sender.get("display_name") or "").lower()
    sender_domain = (sender.get("domain") or "").lower()
    sender_email = (sender.get("email") or "").lower()

    # 1. Sender address and display-name inconsistency
    if display_name and sender_domain:
        # Check if display name claims to be a brand/executive but domain does not match
        is_lookalike, brand, reason = check_brand_lookalike(display_name)
        if (brand and brand not in sender_domain) or any(title in display_name for title in EXECUTIVE_TITLES):
            if sender_domain in COMMON_FREEMAIL_PROVIDERS or brand:
                indicators.append({
                    "category": "Sender & Display Name Mismatch",
                    "severity": "High",
                    "weight": 28,
                    "description": f"Display name '{sender.get('display_name')}' implies official entity or executive authority, but sender address ({sender_email}) belongs to external/freemail domain ({sender_domain}).",
                    "evidence": f"From: {sender.get('display_name')} <{sender_email}>",
                    "why_it_matters": "Attackers frequently forge the human-facing display name to deceive recipients into trusting an external, unauthenticated sender address."
                })

    # 2. Reply-to address mismatch
    if reply_to and reply_to.get("email"):
        reply_domain = (reply_to.get("domain") or "").lower()
        reply_email = (reply_to.get("email") or "").lower()
        if sender_domain and reply_domain and sender_domain != reply_domain:
            severity = "Critical" if reply_domain in COMMON_FREEMAIL_PROVIDERS else "High"
            indicators.append({
                "category": "Reply-To Address Mismatch",
                "severity": severity,
                "weight": 32,
                "description": f"Reply-To address ({reply_email}) redirects replies to a different domain than the sender ({sender_domain}).",
                "evidence": f"From domain: {sender_domain} | Reply-To domain: {reply_domain}",
                "why_it_matters": "An attacker may transmit the message through an arbitrary mail relay while ensuring victims' sensitive responses return directly to their controlled mailbox."
            })

    # 3. Domain lookalike / typosquatting on sender domain
    if sender_domain:
        is_lookalike, brand, reason = check_brand_lookalike(sender_domain)
        if is_lookalike:
            indicators.append({
                "category": "Domain Typosquatting / Lookalike",
                "severity": "High",
                "weight": 26,
                "description": f"Sender domain '{sender_domain}' shows deceptive similarity to well-known brand '{brand}': {reason}.",
                "evidence": f"Sender domain: {sender_domain}",
                "why_it_matters": "Spoofed lookalike domains are specifically registered to trick victims during quick visual scans."
            })

    return indicators

def evaluate_url_indicators(urls: List[Dict[str, str]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Evaluates indicators 3 and 4 (Suspicious URL patterns, IP links, deceptive anchor text)."""
    indicators = []
    inspected_urls = []

    for item in urls:
        u = item.get("url", "")
        anchor = item.get("anchor_text", "")
        inspected = analyze_url(u, anchor)
        inspected_urls.append(inspected)

        if inspected.get("is_ip"):
            indicators.append({
                "category": "IP-Address-Based URL",
                "severity": "Critical",
                "weight": 30,
                "description": f"Link destination '{inspected.get('defanged_url')}' points to a raw numeric IP address instead of an authenticated domain name.",
                "evidence": f"Destination: {inspected.get('defanged_url')}",
                "why_it_matters": "Legitimate enterprise services do not host customer portals on bare IP addresses; this is a hallmark of short-lived malicious phishing kits."
            })

        for r in inspected.get("reasons", []):
            if "Misleading link text" in r:
                indicators.append({
                    "category": "Misleading Link Text",
                    "severity": "Critical",
                    "weight": 30,
                    "description": r,
                    "evidence": f"Anchor: {anchor} -> Link: {inspected.get('defanged_url')}",
                    "why_it_matters": "Deceptive links disguise malicious redirection beneath legitimate-looking text."
                })
            elif "Domain impersonation" in r and not any(i["category"] == "Domain Typosquatting / Lookalike" for i in indicators):
                indicators.append({
                    "category": "Deceptive URL Domain",
                    "severity": "High",
                    "weight": 24,
                    "description": f"Destination URL targets brand spoofing: {r}",
                    "evidence": f"URL: {inspected.get('defanged_url')}",
                    "why_it_matters": "Credential theft pages imitate official corporate interfaces to steal login tokens."
                })
            elif "Suspicious TLD" in r:
                indicators.append({
                    "category": "Suspicious Top-Level Domain",
                    "severity": "Medium",
                    "weight": 14,
                    "description": r,
                    "evidence": f"Domain: {inspected.get('domain')}",
                    "why_it_matters": "Certain TLDs offer cheap or free registration with minimal identity verification, making them favored by cybercriminals."
                })

    return indicators, inspected_urls

def evaluate_content_indicators(subject: str, body: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Evaluates indicators 5, 6, 7, and 8 (Urgency, Credential Harvesting, Financial/BEC, and Spam)."""
    indicators = []
    highlighted_phrases = []
    full_text = f"{subject}\n{body}".lower()

    # 5. Urgent language / account suspension
    for pattern, desc, weight in URGENCY_PATTERNS:
        match = re.search(pattern, full_text, re.IGNORECASE)
        if match:
            matched_phrase = match.group(0)
            indicators.append({
                "category": "Urgent Language & Coercion",
                "severity": "High" if weight > 13 else "Medium",
                "weight": weight,
                "description": f"Employs coercive psychological pressure: '{matched_phrase}'.",
                "evidence": f"Matched context: '...{matched_phrase}...' in message text",
                "why_it_matters": "Attackers manufacture artificial urgency to panic victims into acting impulsively before consulting security protocols."
            })
            highlighted_phrases.append({
                "phrase": matched_phrase,
                "category": "Artificial Urgency",
                "explanation": "Threatens penalties or demands immediate impulsive action"
            })
            break  # Avoid double-counting within the same subcategory

    # 6. Credential harvesting requests
    for pattern, desc, weight in CREDENTIAL_HARVEST_PATTERNS:
        match = re.search(pattern, full_text, re.IGNORECASE)
        if match:
            matched_phrase = match.group(0)
            indicators.append({
                "category": "Credential & Sensitive Data Request",
                "severity": "Critical" if weight >= 22 else "High",
                "weight": weight,
                "description": f"Solicits sensitive credentials or authentication secrets: '{matched_phrase}'.",
                "evidence": f"Phrase: '{matched_phrase}'",
                "why_it_matters": "Reputable service providers and IT departments never ask users to submit passwords or secret verification tokens via unstructured links."
            })
            highlighted_phrases.append({
                "phrase": matched_phrase,
                "category": "Credential Harvesting",
                "explanation": "Directly requests passwords, OTPs, or confidential credentials"
            })
            break

    # 7. Financial requests / Fake invoice / BEC
    for pattern, desc, weight in FINANCIAL_BEC_PATTERNS:
        match = re.search(pattern, full_text, re.IGNORECASE)
        if match:
            matched_phrase = match.group(0)
            indicators.append({
                "category": "Financial Transfer / Invoice Bait",
                "severity": "High",
                "weight": weight,
                "description": f"Suspicious transaction or payment demand detected: '{matched_phrase}'.",
                "evidence": f"Context: '{matched_phrase}'",
                "why_it_matters": "Business Email Compromise (BEC) and fake invoice schemes cause substantial financial loss by manipulating routine accounts payable flows."
            })
            highlighted_phrases.append({
                "phrase": matched_phrase,
                "category": "Financial Lure",
                "explanation": "Requests wire transfers, gift cards, or unsolicited payments"
            })
            break

    # 8. Unsolicited Spam & Commercial Promotions
    for pattern, desc, weight in SPAM_PATTERNS:
        match = re.search(pattern, full_text, re.IGNORECASE)
        if match:
            matched_phrase = match.group(0)
            indicators.append({
                "category": "Unsolicited Bulk Spam / Prize Scam",
                "severity": "Medium" if weight < 20 else "High",
                "weight": weight,
                "description": f"Contains promotional lure or prize claim: '{matched_phrase}'.",
                "evidence": f"Context: '{matched_phrase}'",
                "why_it_matters": "Unsolicited spam messages often link to deceptive marketing networks, advance-fee scams, or counterfeit goods."
            })
            highlighted_phrases.append({
                "phrase": matched_phrase,
                "category": "Promotional Spam / Scam",
                "explanation": "Contains prize claims, lottery notices, or aggressive spam promotion"
            })
            break

    return indicators, highlighted_phrases

def evaluate_attachment_indicators(attachments: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Evaluates indicator 8 (Suspicious and dangerous attachments)."""
    indicators = []
    inspected_attachments = []

    for att in attachments:
        fname = att.get("filename", "")
        ext = att.get("extension", "").lower()
        is_dang = att.get("is_dangerous", False)
        reason = att.get("risk_reason", "")
        
        inspected_attachments.append({
            "filename": fname,
            "extension": ext,
            "is_dangerous": is_dang,
            "risk_reason": reason,
            "size_bytes": att.get("size_bytes", 0)
        })

        if is_dang:
            indicators.append({
                "category": "Dangerous Attachment Extension",
                "severity": "Critical",
                "weight": 34,
                "description": f"Attachment '{fname}' has high-risk extension ({ext}): {reason}.",
                "evidence": f"Filename: {fname}",
                "why_it_matters": "Executable files, scripts, and disk image containers (.iso, .vbs, .scr) can execute arbitrary malicious code or deliver ransomware upon opening."
            })

    return indicators, inspected_attachments

def evaluate_auth_headers(auth: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Evaluates indicator 10 (SPF, DKIM, DMARC headers)."""
    indicators = []
    missing_evidence = []

    spf = auth.get("spf", "Unknown / Not verified")
    dkim = auth.get("dkim", "Unknown / Not verified")
    dmarc = auth.get("dmarc", "Unknown / Not verified")

    if spf == "Fail":
        indicators.append({
            "category": "Email Authentication Failure (SPF)",
            "severity": "High",
            "weight": 25,
            "description": "SPF validation failed: The transmitting mail server is not authorized to send mail on behalf of the domain.",
            "evidence": "Received-SPF: Fail",
            "why_it_matters": "SPF failures often signal sender address spoofing."
        })
    elif spf == "Unknown / Not verified":
        missing_evidence.append("SPF verification headers not found or inconclusive (status: Unknown).")

    if dkim == "Fail":
        indicators.append({
            "category": "Email Authentication Failure (DKIM)",
            "severity": "High",
            "weight": 25,
            "description": "DKIM cryptographic signature verification failed: The message body or key was altered in transit.",
            "evidence": "DKIM: Fail",
            "why_it_matters": "A broken DKIM signature suggests tampering or unauthorized relaying."
        })
    elif dkim == "Unknown / Not verified":
        missing_evidence.append("DKIM cryptographic signature headers not present (status: Unknown).")

    if dmarc == "Fail":
        indicators.append({
            "category": "DMARC Alignment Failure",
            "severity": "High",
            "weight": 25,
            "description": "DMARC policy alignment failed: Neither SPF nor DKIM passed with domain alignment.",
            "evidence": "DMARC: Fail",
            "why_it_matters": "DMARC failures indicate unauthorized domain impersonation according to the domain owner's published policy."
        })
    elif dmarc == "Unknown / Not verified":
        missing_evidence.append("DMARC alignment evaluation not present in message headers.")

    return indicators, missing_evidence

def calculate_heuristic_score(indicators: List[Dict[str, Any]]) -> Tuple[float, str, str]:
    """
    Computes a 0-100 heuristic risk score.
    Combines indicator weights with diminishing returns to avoid distortion from redundant triggers.
    Categorizes into Low (0-29), Medium (30-59), High (60-79), Critical (80-100).
    """
    if not indicators:
        # Base baseline score for unverified external messages
        return 12.0, "Low", "High (85%)"

    total_weight = 0.0
    for idx, ind in enumerate(indicators):
        w = ind.get("weight", 15)
        # Apply slight dampening for each subsequent indicator to prevent arbitrary score blowing
        factor = 1.0 / (1.0 + 0.15 * idx)
        total_weight += w * factor

    # Map onto 0 - 100 scale
    score = min(98.0, max(10.0, total_weight))
    score = round(score, 1)

    if score <= settings.THRESHOLD_LOW_MAX:
        risk_level = "Low"
    elif score <= settings.THRESHOLD_MED_MAX:
        risk_level = "Medium"
    elif score <= settings.THRESHOLD_HIGH_MAX:
        risk_level = "High"
    else:
        risk_level = "Critical"

    # Confidence calculation based on number of validated signals
    if len(indicators) >= 3:
        confidence = "High (92%)"
    elif len(indicators) == 2:
        confidence = "Medium-High (82%)"
    elif len(indicators) == 1:
        confidence = "Medium (72%)"
    else:
        confidence = "Moderate (65%)"

    return score, risk_level, confidence

def determine_classification(risk_score: float, indicators: List[Dict[str, Any]]) -> str:
    """
    Returns one of four distinct verdicts:
    - Potential Phishing (Risk >= 50 with credentials, lookalikes, IP links, BEC, or dangerous attachments)
    - Spam (Promotional, lottery, unsolicited commercial scams without targeted phishing kit)
    - Suspicious (Moderate risk 25-49, or conflicting signals)
    - Legitimate (Low risk 0-24, no high severity markers)
    """
    has_credential_theft = any("Credential" in i.get("category", "") or "Password" in i.get("description", "") for i in indicators)
    has_impersonation = any("Mismatch" in i.get("category", "") or "Typosquatting" in i.get("category", "") or "Lookalike" in i.get("category", "") for i in indicators)
    has_dangerous_link_or_att = any("IP-Address" in i.get("category", "") or "Attachment" in i.get("category", "") or "Misleading Link" in i.get("category", "") for i in indicators)
    has_financial_bec = any("Financial" in i.get("category", "") or "Wire Transfer" in i.get("category", "") for i in indicators)
    has_spam = any("Spam" in i.get("category", "") or "Lottery" in i.get("category", "") or "Promotional" in i.get("category", "") for i in indicators)

    if risk_score >= 50 or has_credential_theft or (has_impersonation and (has_dangerous_link_or_att or has_financial_bec)):
        return "Potential Phishing"
    elif has_spam:
        return "Spam"
    elif risk_score >= 25 or len(indicators) > 0:
        return "Suspicious"
    else:
        return "Legitimate"

def generate_recommendations(risk_level: str, classification: str, indicators: List[Dict[str, Any]]) -> List[str]:
    """Actionable recommendations mapped to risk level, classification, and specific indicators."""
    recs = []

    if classification == "Potential Phishing" or risk_level == "Critical":
        recs.append("PRIORITIZE IMMEDIATE INVESTIGATION: Do NOT click any links, open attachments, or reply to this message.")
        recs.append("Isolate recipient endpoint if attachments were executed or links were clicked.")
        recs.append("Check enterprise mail security logs to determine if other employees received this campaign.")
        recs.append("Notify IT Security / Incident Response contact immediately.")
    elif classification == "Spam":
        recs.append("SPAM PROTOCOL: Mark message as Spam / Junk and block sender address in your email client.")
        recs.append("DO NOT RESPOND to unsolicited promotional offers, prize claims, or sweepstakes.")
        recs.append("Avoid clicking 'unsubscribe' links in unfamiliar emails as they often confirm active mailboxes.")
    elif risk_level == "High":
        recs.append("AVOID INTERACTION: Refrain from clicking embedded links or downloading attachments.")
        recs.append("Escalate message to security analyst or administrator for quarantined sandbox inspection.")
        recs.append("If credentials were submitted, initiate an immediate password reset and revoke active sessions.")
    elif risk_level == "Medium" or classification == "Suspicious":
        recs.append("VERIFY INDEPENDENTLY: Contact the alleged sender through an established out-of-band channel (e.g. phone call or internal chat).")
        recs.append("Do not use phone numbers or contact details provided inside this email.")
        recs.append("Double-check URL destinations before entering any login credentials.")
    else:  # Low / Legitimate
        recs.append("REVIEW AVAILABLE EVIDENCE: Note that PhishGuard AI does NOT certify emails as 100% safe.")
        recs.append("Zero-day spear phishing, compromised vendor accounts, or contextual social engineering may lack obvious static markers.")
        recs.append("Always maintain standard security hygiene and report any suspicious behavior.")

    # Add indicator-specific recommendations
    for ind in indicators:
        cat = ind.get("category", "")
        if "Wire Transfer" in cat or "Invoice" in cat:
            recs.append("Enforce dual-authorization verification for any financial transaction.")
        if "IP-Address" in cat:
            recs.append("Add the target IP address to perimeter firewall / proxy blocklists.")
        if "Attachment" in cat:
            recs.append("Block dangerous file extension at the corporate email gateway filter.")

    # Remove duplicates preserving order
    seen = set()
    deduped = []
    for r in recs:
        if r not in seen:
            seen.add(r)
            deduped.append(r)

    return deduped

def analyze_email_data(parsed_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main triage coordinator: runs all indicator checks, classifies into Legitimate/Spam/Suspicious/Phishing,
    and builds explainable triage report.
    Never claims safe. Works 100% offline.
    """
    all_indicators: List[Dict[str, Any]] = []

    # 1, 2, 9: Sender integrity & typosquatting
    sender_ind = evaluate_sender_integrity(parsed_data["sender"], parsed_data.get("reply_to"))
    all_indicators.extend(sender_ind)

    # 3, 4: URL inspection
    url_ind, inspected_urls = evaluate_url_indicators(parsed_data.get("links", []))
    all_indicators.extend(url_ind)

    # 5, 6, 7, 8: Content, Urgency, Credential, Financial & Spam threats
    content_ind, highlighted_phrases = evaluate_content_indicators(parsed_data.get("subject", ""), parsed_data.get("body", ""))
    all_indicators.extend(content_ind)

    # Attachment inspection
    att_ind, inspected_attachments = evaluate_attachment_indicators(parsed_data.get("attachments", []))
    all_indicators.extend(att_ind)

    # SPF / DKIM / DMARC authentication
    auth_ind, missing_evidence = evaluate_auth_headers(parsed_data.get("authentication", {}))
    all_indicators.extend(auth_ind)

    # Calculate heuristic score
    risk_score, risk_level, confidence = calculate_heuristic_score(all_indicators)

    # Classification: Legitimate, Spam, Suspicious, Potential Phishing
    classification = determine_classification(risk_score, all_indicators)
    is_spam = classification == "Spam"

    # Actionable recommendations
    recommendations = generate_recommendations(risk_level, classification, all_indicators)

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "classification": classification,
        "is_spam": is_spam,
        "confidence_score": confidence,
        "indicator_details": all_indicators,
        "recommendations": recommendations,
        "missing_evidence": missing_evidence,
        "highlighted_phrases": highlighted_phrases,
        "extracted_urls": inspected_urls,
        "attachment_names": inspected_attachments,
        "urls_count": len(inspected_urls),
        "attachments_count": len(inspected_attachments)
    }

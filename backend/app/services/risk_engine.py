"""
Risk Engine for Phishing & Security Triage.
Provides a transparent, weighted risk scoring matrix (0 to 100)
with explainable indicators, risk levels, and actionable security recommendations.
Supports both dedicated URL inspection and multi-layered AI Email Triage.
"""

from typing import Dict, Any, List, Tuple, Optional


class RiskLevel:
    LOW = "Low Risk"
    MEDIUM = "Medium Risk"
    HIGH = "High Risk"
    CRITICAL = "Critical Risk"


class PredictionCategory:
    LEGITIMATE = "Legitimate"
    SUSPICIOUS = "Suspicious"
    POTENTIAL_PHISHING = "Potential Phishing"
    SPAM = "Spam"


def calculate_url_risk(
    features: Dict[str, Any],
    detected_indicators: List[Dict[str, Any]]
) -> Tuple[float, str, str, List[str]]:
    """
    Computes a transparent weighted risk score from 0 to 100 based on extracted URL features and indicators.
    Avoids double-counting related indicators.
    
    Returns:
        (risk_score, risk_level, prediction, recommendations)
    """
    if not detected_indicators:
        risk_score = 5.0
        risk_level = RiskLevel.LOW
        prediction = PredictionCategory.LEGITIMATE
        recommendations = [
            "MAINTAIN STANDARD CAUTION: No malicious structural anomalies detected.",
            "Static heuristics inspect URL structure only. Always confirm unfamiliar domains before entering credentials."
        ]
        return risk_score, risk_level, prediction, recommendations

    # Sum indicator weights with diminishing returns to cap smoothly at 100
    raw_score = sum(ind.get("weight", 0) for ind in detected_indicators)
    score = min(100.0, max(10.0, float(raw_score)))

    # Determine risk category
    if score < 25.0:
        risk_level = RiskLevel.LOW
        prediction = PredictionCategory.LEGITIMATE
    elif score < 50.0:
        risk_level = RiskLevel.MEDIUM
        prediction = PredictionCategory.SUSPICIOUS
    elif score < 75.0:
        risk_level = RiskLevel.HIGH
        prediction = PredictionCategory.POTENTIAL_PHISHING
    else:
        risk_level = RiskLevel.CRITICAL
        prediction = PredictionCategory.POTENTIAL_PHISHING

    recommendations = []
    if risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
        recommendations.append("DO NOT OPEN OR CLICK THIS LINK: Strong structural phishing indicators detected.")
        recommendations.append("DO NOT SUBMIT PASSWORDS, OTPs, OR SENSITIVE DATA on any page reached through this URL.")
        recommendations.append("Report this URL immediately to your security team or IT administrator.")
        recommendations.append("Add the target domain or IP to the organizational perimeter blocklist (firewall/DNS).")
    elif risk_level == RiskLevel.MEDIUM:
        recommendations.append("PROCEED WITH CAUTION: This link presents anomalous structural attributes or shortened redirection.")
        recommendations.append("Verify the intended link destination directly through official documentation or internal IT.")
        recommendations.append("Do not authenticate or enter financial credentials if prompted after following this link.")
    else:
        recommendations.append("MAINTAIN STANDARD CAUTION: No known malicious structural anomalies were detected.")
        recommendations.append("Automated static heuristics cannot guarantee a link is safe. Always verify unfamiliar domains.")

    return round(score, 1), risk_level, prediction, recommendations


def calculate_email_risk(
    model_label: str,
    model_score: float,
    email_indicators: List[Dict[str, Any]],
    url_analysis_results: List[Dict[str, Any]]
) -> Tuple[float, str, str, List[str]]:
    """
    Combines AI email classification, explainable pattern indicators, and embedded URL triage.
    
    Keeps model classification label and confidence separate from the overall triage risk score.
    Does not assume spam equals phishing; distinguishes unsolicited bulk advertising
    from severe credential harvesting, BEC wire fraud, and phishing URLs.
    
    Returns:
        (risk_score, risk_level, prediction, recommendations)
    """
    total_weight = 0.0
    label_upper = (model_label or "").upper()
    is_spam_prediction = ("SPAM" in label_upper or "LABEL_1" in label_upper or "1" == label_upper)

    # 1. AI Model Contribution (Spam Classification)
    # A positive spam prediction contributes moderate baseline risk (25-35 pts)
    if is_spam_prediction:
        total_weight += 25.0 * float(model_score or 1.0)

    # 2. Pattern Indicators Contribution
    has_critical_patterns = False
    has_phishing_patterns = False
    has_spam_patterns = False

    for ind in email_indicators:
        w = ind.get("weight", 0)
        cat = ind.get("category", "")
        total_weight += w

        if "Credential" in cat or "Wire" in cat or "Executive Impersonation" in cat or "Gift Card" in cat:
            has_critical_patterns = True
            has_phishing_patterns = True
        elif "Urgency" in cat or "Time Limit" in cat:
            has_phishing_patterns = True
        elif "Promotional" in cat or "Lottery" in cat or "Prize" in cat or "Investment" in cat or "Spam" in cat or "Unsubscribe" in cat:
            has_spam_patterns = True

    # 3. Embedded URLs Contribution
    max_url_score = 0.0
    has_phishing_url = False

    for url_res in url_analysis_results:
        u_score = float(url_res.get("risk_score", 0.0))
        u_level = url_res.get("risk_level", "")
        max_url_score = max(max_url_score, u_score)

        if u_score >= 50.0 or u_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            has_phishing_url = True

    if has_phishing_url:
        total_weight += 35.0
    elif max_url_score >= 25.0:
        total_weight += 15.0

    # Cap overall risk score between 5.0 and 100.0
    score = min(100.0, max(5.0, float(total_weight)))

    # Determine risk category & overall triage prediction
    if score < 25.0:
        risk_level = RiskLevel.LOW
        prediction = PredictionCategory.LEGITIMATE
    elif score < 50.0:
        risk_level = RiskLevel.MEDIUM
        if has_spam_patterns or (is_spam_prediction and not has_phishing_patterns):
            prediction = PredictionCategory.SPAM
        elif not has_critical_patterns and not has_phishing_url and not has_spam_patterns:
            # DistilBERT model false positive on routine operational urgency without malicious lures
            prediction = PredictionCategory.LEGITIMATE
        else:
            prediction = PredictionCategory.SUSPICIOUS
    elif score < 75.0:
        risk_level = RiskLevel.HIGH
        prediction = PredictionCategory.POTENTIAL_PHISHING if (has_phishing_patterns or has_phishing_url) else PredictionCategory.SUSPICIOUS
    else:
        risk_level = RiskLevel.CRITICAL
        prediction = PredictionCategory.POTENTIAL_PHISHING

    # Generate actionable security recommendations
    recommendations = []
    if risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
        recommendations.append("HIGH ALERT: DO NOT INTERACT with this email or click any contained links.")
        recommendations.append("NEVER PROVIDE PASSWORDS, OTPs, OR BANKING DETAILS in response to email prompts.")
        recommendations.append("If this email requests wire transfers or payroll changes, verify out-of-band via trusted phone numbers.")
        recommendations.append("Report this message immediately to your organization's security or IT desk.")
    elif risk_level == RiskLevel.MEDIUM:
        recommendations.append("EXERCISE CAUTION: This email exhibits spam or anomalous marketing characteristics.")
        recommendations.append("Verify the sender identity and avoid clicking embedded links or promotional buttons.")
        recommendations.append("Do not reply to unsubscribe links if the sender is unfamiliar; mark as junk/spam.")
    else:
        recommendations.append("STANDARD AWARENESS: No prominent phishing or spam indicators detected.")
        recommendations.append("Always verify unexpected attachments or sensitive requests through official channels.")

    return round(score, 1), risk_level, prediction, recommendations

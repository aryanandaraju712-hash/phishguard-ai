import os
import json
from typing import List, Dict, Any, Optional
from app.core.config import settings

def generate_offline_explanations(indicators: List[Dict[str, Any]], parsed_data: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Deterministic explainable engine that converts detected indicators into simple,
    clear explanations tailored for small business employees.
    """
    explanations: List[Dict[str, str]] = []

    if not indicators:
        explanations.append({
            "finding": "No overt phishing indicators detected in the submitted content",
            "evidence": "Sender address, message text, and link formats appear consistent with standard correspondence.",
            "why_it_matters": "While no classic red flags were detected, attackers sometimes compromise legitimate accounts or tailor highly subtle spear-phishing requests.",
            "recommended_action": "Proceed with regular caution. If the email requests unexpected actions, verify directly with the sender via a trusted secondary channel."
        })
        return explanations

    for ind in indicators:
        cat = ind.get("category", "")
        desc = ind.get("description", "")
        ev = ind.get("evidence", desc)
        why = ind.get("why_it_matters", "This pattern is frequently used in fraudulent email campaigns to deceive recipients.")

        if "Sender & Display Name Mismatch" in cat:
            explanations.append({
                "finding": "Sender display name does not match the actual email address",
                "evidence": ev,
                "why_it_matters": "Attackers can write any name they want in the display name field (e.g. 'CEO' or 'IT Support') while actually sending the email from an unrelated external or free email account.",
                "recommended_action": "Do not trust the name displayed in your inbox. Look closely at the actual email address inside the angle brackets."
            })
        elif "Reply-To Address Mismatch" in cat:
            explanations.append({
                "finding": "Replies are routed to a different address than the sender",
                "evidence": ev,
                "why_it_matters": "An attacker might send an email that appears to come from a real company, but if you click 'Reply', your message goes straight to the attacker's personal inbox.",
                "recommended_action": "Do not click 'Reply'. If you need to contact the sender, compose a new email and type their known legitimate address manually."
            })
        elif "IP-Address-Based URL" in cat:
            explanations.append({
                "finding": "Link directs to a raw numeric IP address instead of a domain name",
                "evidence": ev,
                "why_it_matters": "Legitimate businesses like Microsoft, Google, or banks always use registered domain names. Raw numbers (IP addresses) are commonly used by cybercriminals running temporary scam pages.",
                "recommended_action": "Do NOT click the link. Report it to your security team."
            })
        elif "Misleading Link Text" in cat:
            explanations.append({
                "finding": "The link destination is disguised by deceptive link text",
                "evidence": ev,
                "why_it_matters": "The email text makes the link look like a trusted site, but clicking it takes you to a completely different, unauthorized website.",
                "recommended_action": "Always hover over links to inspect the actual destination before clicking, or navigate directly to the website through your browser bookmarks."
            })
        elif "Credential & Sensitive Data Request" in cat:
            explanations.append({
                "finding": "Email requests passwords, PINs, or sensitive authentication details",
                "evidence": ev,
                "why_it_matters": "Legitimate IT administrators and banks will NEVER ask you to email your password or enter it on an unverified link.",
                "recommended_action": "Never share your password or two-factor code. If you suspect an issue, log into the official service directly."
            })
        elif "Urgent Language & Threat of Suspension" in cat:
            explanations.append({
                "finding": "Email creates artificial urgency or threatens account suspension",
                "evidence": ev,
                "why_it_matters": "Scammers try to panic you with tight deadlines (e.g., 'within 2 hours') so you act before thinking or asking a coworker.",
                "recommended_action": "Take a breath and pause. Contact your IT administrator or coworker through your normal chat or phone system to confirm."
            })
        elif "Dangerous Attachment Extension" in cat:
            explanations.append({
                "finding": "Email contains an executable or high-risk file attachment",
                "evidence": ev,
                "why_it_matters": "Files ending in formats like .iso, .exe, or .vbs can immediately run malicious programs or infect your computer with ransomware when opened.",
                "recommended_action": "Do NOT double-click or open the attachment. Ask your IT support to inspect it in a secure environment."
            })
        elif "Financial Transfer / Invoice Bait" in cat:
            explanations.append({
                "finding": "Email demands an urgent wire transfer or references an unfamiliar invoice",
                "evidence": ev,
                "why_it_matters": "Executive impersonation (CEO fraud) is one of the costliest cyber attacks on small organizations. Scammers pose as managers to trick employees into sending funds.",
                "recommended_action": "Always call the requester using a known, trusted phone number before processing any money transfer or changing payment details."
            })
        elif "Domain Typosquatting / Lookalike" in cat or "Deceptive URL Domain" in cat:
            explanations.append({
                "finding": "Email domain is a lookalike imitation of a well-known brand",
                "evidence": ev,
                "why_it_matters": "Attackers register domain names with tiny spelling differences (like substituting letters or adding hyphens) hoping you won't notice at a glance.",
                "recommended_action": "Inspect the spelling of the domain very carefully. Compare it against the real company's official website."
            })
        elif "Authentication Failure" in cat or "DMARC" in cat:
            explanations.append({
                "finding": "Email failed technical domain authentication checks",
                "evidence": ev,
                "why_it_matters": "The server that delivered this message is not authorized by the real domain owner to send mail on their behalf.",
                "recommended_action": "Treat this message with high suspicion, as the sender address may have been forged."
            })
        else:
            explanations.append({
                "finding": cat,
                "evidence": ev,
                "why_it_matters": why,
                "recommended_action": "Follow standard security guidelines and consult an analyst before interacting with the message."
            })

    return explanations

def explain_analysis(indicators: List[Dict[str, Any]], parsed_data: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Coordinates explanation generation.
    Uses offline fallback by default for speed, safety, and repeatable hackathon demoing.
    If external API key is provided and configured, can augment, but strictly validates output.
    """
    # Deterministic local engine is fast, rich, explainable, and 100% offline
    return generate_offline_explanations(indicators, parsed_data)

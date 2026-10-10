import email
from email import policy
import re
from typing import Dict, Any, List, Optional
from html.parser import HTMLParser

# Dangerous file extensions commonly leveraged in malicious email delivery
DANGEROUS_EXTENSIONS = {
    ".exe": "Windows executable file",
    ".scr": "Screen saver executable (frequently disguised malware)",
    ".vbs": "VBScript script executable",
    ".js": "JavaScript script file",
    ".hta": "HTML Application executable",
    ".bat": "Windows batch command script",
    ".cmd": "Command prompt script",
    ".ps1": "PowerShell automation script",
    ".iso": "Disk image file (bypasses Mark of the Web)",
    ".img": "Disk image container",
    ".vhd": "Virtual hard disk image",
    ".docm": "Macro-enabled Microsoft Word document",
    ".xlsm": "Macro-enabled Microsoft Excel spreadsheet",
    ".pptm": "Macro-enabled Microsoft PowerPoint presentation",
    ".jar": "Java archive executable",
    ".cpl": "Control Panel extension binary"
}

class SafeHTMLParser(HTMLParser):
    """Safely extracts text and hyperlinks from untrusted HTML without executing scripts."""
    def __init__(self):
        super().__init__()
        self.text_parts: List[str] = []
        self.extracted_links: List[Dict[str, str]] = []
        self.current_href: Optional[str] = None
        self.current_link_text: List[str] = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            for attr_name, attr_val in attrs:
                if attr_name.lower() == "href" and attr_val:
                    self.current_href = attr_val
                    self.current_link_text = []

    def handle_endtag(self, tag):
        if tag.lower() == "a" and self.current_href:
            link_text = "".join(self.current_link_text).strip()
            self.extracted_links.append({
                "url": self.current_href,
                "anchor_text": link_text
            })
            self.current_href = None
            self.current_link_text = []

    def handle_data(self, data):
        self.text_parts.append(data)
        if self.current_href is not None:
            self.current_link_text.append(data)

    def get_text(self) -> str:
        return " ".join(self.text_parts)

def parse_display_and_email(address_str: str) -> Dict[str, str]:
    """Separates display name and email address from header (e.g. 'CEO Mark <ceo@evil.com>')."""
    if not address_str:
        return {"display_name": "", "email": "", "domain": ""}
    
    match = re.search(r"^(.*?)\s*<([^>]+)>$", address_str.strip())
    if match:
        display_name = match.group(1).strip().strip('"').strip("'")
        email_addr = match.group(2).strip().lower()
    else:
        # Check if contains an email
        match_email = re.search(r"[\w\.-]+@[\w\.-]+\.\w+", address_str)
        if match_email:
            email_addr = match_email.group(0).lower()
            display_name = address_str.replace(email_addr, "").strip().strip("<>").strip('"').strip("'")
        else:
            email_addr = address_str.strip().lower()
            display_name = ""

    domain = email_addr.split("@")[-1] if "@" in email_addr else ""
    return {
        "display_name": display_name,
        "email": email_addr,
        "domain": domain
    }

def extract_urls_from_text(text: str) -> List[Dict[str, str]]:
    """Safely extracts HTTP/HTTPS URLs from raw text using regex."""
    url_pattern = r"https?://(?:[a-zA-Z0-9-._~:/?#\[\]@!$&'()*+,;=]|%[0-9a-fA-F]{2})+"
    matches = re.findall(url_pattern, text)
    unique_urls = []
    seen = set()
    for u in matches:
        # Strip trailing punctuation often caught in sentence boundaries
        clean_url = u.rstrip(".,;)>]\"'")
        if clean_url not in seen:
            seen.add(clean_url)
            unique_urls.append({"url": clean_url, "anchor_text": ""})
    return unique_urls

def parse_authentication_headers(msg: email.message.EmailMessage) -> Dict[str, Any]:
    """
    Parses SPF, DKIM, and DMARC evidence from message headers.
    CRITICAL: Never invents results. If evidence is missing, reports 'Unknown / Not verified'.
    """
    auth_results_header = msg.get("Authentication-Results", "")
    spf_header = msg.get("Received-SPF", "")
    dkim_header = msg.get("DKIM-Signature", "")

    auth_data = {
        "spf": "Unknown / Not verified",
        "dkim": "Unknown / Not verified",
        "dmarc": "Unknown / Not verified",
        "raw_evidence": []
    }

    combined_auth = f"{auth_results_header} {spf_header}".lower()

    if combined_auth.strip():
        auth_data["raw_evidence"].append(combined_auth[:400])

        # SPF Evaluation
        if "spf=pass" in combined_auth or "received-spf: pass" in combined_auth:
            auth_data["spf"] = "Pass"
        elif "spf=fail" in combined_auth or "spf=softfail" in combined_auth or "received-spf: fail" in combined_auth:
            auth_data["spf"] = "Fail"
        elif "spf=neutral" in combined_auth:
            auth_data["spf"] = "Neutral"

        # DKIM Evaluation
        if "dkim=pass" in combined_auth:
            auth_data["dkim"] = "Pass"
        elif "dkim=fail" in combined_auth:
            auth_data["dkim"] = "Fail"
        elif dkim_header:
            auth_data["dkim"] = "Present (Verification Status Unknown)"

        # DMARC Evaluation
        if "dmarc=pass" in combined_auth:
            auth_data["dmarc"] = "Pass"
        elif "dmarc=fail" in combined_auth:
            auth_data["dmarc"] = "Fail"
        elif "dmarc=none" in combined_auth:
            auth_data["dmarc"] = "None (Policy not enforced)"

    return auth_data

def parse_eml_bytes(raw_bytes: bytes) -> Dict[str, Any]:
    """Safely parses raw RFC 822 / .eml bytes into structured data."""
    try:
        msg = email.message_from_bytes(raw_bytes, policy=policy.default)
    except Exception as e:
        raise ValueError(f"Malformed email file format: {str(e)}")

    subject = str(msg.get("Subject", "") or "(No Subject)")
    sender_raw = str(msg.get("From", "") or "")
    reply_to_raw = str(msg.get("Reply-To", "") or "")
    recipient_raw = str(msg.get("To", "") or "")
    date_str = str(msg.get("Date", "") or "")

    sender_parsed = parse_display_and_email(sender_raw)
    reply_to_parsed = parse_display_and_email(reply_to_raw) if reply_to_raw else None

    # Safely extract body text and links
    body_text_parts: List[str] = []
    extracted_links: List[Dict[str, str]] = []
    attachments: List[Dict[str, Any]] = []

    for part in msg.walk():
        content_maintype = part.get_content_maintype()
        disposition = str(part.get_content_disposition() or "").lower()
        filename = part.get_filename()

        # Check for attachment
        if disposition == "attachment" or filename:
            safe_fname = str(filename or "unnamed_attachment")
            ext = ("." + safe_fname.rsplit(".", 1)[-1].lower()) if "." in safe_fname else ""
            is_dangerous = ext in DANGEROUS_EXTENSIONS
            risk_reason = DANGEROUS_EXTENSIONS.get(ext) if is_dangerous else None
            
            try:
                payload = part.get_payload(decode=True)
                size_bytes = len(payload) if payload else 0
            except Exception:
                size_bytes = 0

            attachments.append({
                "filename": safe_fname,
                "extension": ext,
                "is_dangerous": is_dangerous,
                "risk_reason": risk_reason,
                "size_bytes": size_bytes
            })
            continue

        # Extract text/plain or text/html
        if content_maintype == "text":
            subtype = part.get_content_subtype()
            try:
                payload_str = part.get_content()
                if not isinstance(payload_str, str):
                    payload_bytes = part.get_payload(decode=True)
                    payload_str = payload_bytes.decode("utf-8", errors="replace") if payload_bytes else ""
            except Exception:
                payload_str = ""

            if subtype == "html":
                parser = SafeHTMLParser()
                try:
                    parser.feed(payload_str)
                    body_text_parts.append(parser.get_text())
                    extracted_links.extend(parser.extracted_links)
                except Exception:
                    body_text_parts.append(payload_str)
            else:
                body_text_parts.append(payload_str)
                extracted_links.extend(extract_urls_from_text(payload_str))

    combined_body = "\n\n".join(body_text_parts).strip()
    
    # Also extract any URLs in raw text body that parser didn't catch
    text_urls = extract_urls_from_text(combined_body)
    for tu in text_urls:
        if not any(el["url"] == tu["url"] for el in extracted_links):
            extracted_links.append(tu)

    auth_info = parse_authentication_headers(msg)

    return {
        "subject": subject,
        "sender_raw": sender_raw,
        "sender": sender_parsed,
        "reply_to_raw": reply_to_raw,
        "reply_to": reply_to_parsed,
        "recipient": recipient_raw,
        "date": date_str,
        "body": combined_body,
        "body_snippet": combined_body[:400] if combined_body else "(Empty body)",
        "links": extracted_links,
        "attachments": attachments,
        "authentication": auth_info
    }

def parse_manual_email_input(
    subject: str,
    sender: str,
    reply_to: Optional[str] = None,
    recipient: Optional[str] = None,
    body: str = "",
    explicit_urls: Optional[List[str]] = None
) -> Dict[str, Any]:
    """Parses manually submitted email fields."""
    sender_parsed = parse_display_and_email(sender)
    reply_to_parsed = parse_display_and_email(reply_to) if reply_to else None

    extracted_links = extract_urls_from_text(body)
    if explicit_urls:
        for u in explicit_urls:
            clean_u = u.strip()
            if clean_u and not any(el["url"] == clean_u for el in extracted_links):
                extracted_links.append({"url": clean_u, "anchor_text": ""})

    # Look for simulated or mentioned attachments in text (e.g., "attached: invoice.iso")
    attachments = []
    attachment_match = re.findall(r"attached[:\s]+([\w\.-]+\.([a-zA-Z0-9]{2,4}))", body, re.IGNORECASE)
    for match in attachment_match:
        fname = match[0]
        ext = "." + match[1].lower()
        is_dangerous = ext in DANGEROUS_EXTENSIONS
        attachments.append({
            "filename": fname,
            "extension": ext,
            "is_dangerous": is_dangerous,
            "risk_reason": DANGEROUS_EXTENSIONS.get(ext) if is_dangerous else None,
            "size_bytes": 0
        })

    return {
        "subject": subject or "(No Subject)",
        "sender_raw": sender,
        "sender": sender_parsed,
        "reply_to_raw": reply_to or "",
        "reply_to": reply_to_parsed,
        "recipient": recipient or "",
        "date": "",
        "body": body,
        "body_snippet": body[:400] if body else "(Empty body)",
        "links": extracted_links,
        "attachments": attachments,
        "authentication": {
            "spf": "Unknown / Not verified",
            "dkim": "Unknown / Not verified",
            "dmarc": "Unknown / Not verified",
            "raw_evidence": []
        }
    }

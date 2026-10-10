"""
PhishGuard AI — PDF Security Report Generator
Produces professional, multi-section cybersecurity triage reports using ReportLab.
Supports both URL Phishing Detection and AI Email Spam Detection analyses.
"""

import io
import re
import datetime
from typing import Dict, Any, List, Optional

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether, HRFlowable
)
from reportlab.pdfgen import canvas


# ============================================================================
# Color Palette & Styling Constants
# ============================================================================
COLOR_PRIMARY = colors.HexColor("#0B192C")      # Deep Navy
COLOR_SECONDARY = colors.HexColor("#0284C7")    # Cyan / Blue Accent
COLOR_DARK = colors.HexColor("#0F172A")         # Slate Dark Body Text
COLOR_MUTED = colors.HexColor("#475569")        # Muted Slate Gray
COLOR_LIGHT_BG = colors.HexColor("#F8FAFC")     # Card Background
COLOR_BORDER = colors.HexColor("#E2E8F0")       # Subtle Border
COLOR_WHITE = colors.HexColor("#FFFFFF")

# Risk Level Colors
COLOR_RISK_LOW = colors.HexColor("#10B981")       # Emerald
COLOR_RISK_MODERATE = colors.HexColor("#F59E0B")  # Amber
COLOR_RISK_HIGH = colors.HexColor("#F97316")      # Orange
COLOR_RISK_CRITICAL = colors.HexColor("#EF4444")  # Crimson

def get_risk_color(score: float) -> colors.HexColor:
    if score < 25:
        return COLOR_RISK_LOW
    elif score < 50:
        return COLOR_RISK_MODERATE
    elif score < 75:
        return COLOR_RISK_HIGH
    return COLOR_RISK_CRITICAL


# ============================================================================
# Safe URL Defanging & Redaction Helpers
# ============================================================================
def defang_url_safe(url: str) -> str:
    """
    Safely defangs URLs to ensure they cannot be accidentally clicked or executed.
    Replaces http/https with hxxp/hxxps and brackets dots in hostnames.
    """
    if not url:
        return ""
    u = str(url).strip()
    if u.startswith("hxxp://") or u.startswith("hxxps://") or "[.]" in u:
        return u
    
    # Replace scheme
    u = re.sub(r"^http://", "hxxp://", u, flags=re.IGNORECASE)
    u = re.sub(r"^https://", "hxxps://", u, flags=re.IGNORECASE)
    
    parts = u.split("://", 1)
    if len(parts) == 2:
        scheme, rest = parts
        host_parts = rest.split("/", 1)
        host = host_parts[0]
        # Defang dots in host
        defanged_host = host.replace(".", "[.]")
        if len(host_parts) == 2:
            return f"{scheme}://{defanged_host}/{host_parts[1]}"
        return f"{scheme}://{defanged_host}"
    
    return u.replace(".", "[.]")


def redact_sensitive_text(text: str) -> str:
    """Masks potential credentials, OTPs, or financial strings for report export."""
    if not text:
        return ""
    t = str(text)
    # Mask card numbers (13-16 digits)
    t = re.sub(r"\b(?:\d[ -]*?){13,16}\b", "[REDACTED-CARD]", t)
    # Mask auth passwords or bearer tokens
    t = re.sub(r"(bearer\s+)[A-Za-z0-9_\-\.]+", r"\1[REDACTED-TOKEN]", t, flags=re.IGNORECASE)
    t = re.sub(r"(password[:=]\s*)\S+", r"\1[REDACTED]", t, flags=re.IGNORECASE)
    t = re.sub(r"(otp[:=]\s*)\d{4,8}", r"\1[REDACTED-OTP]", t, flags=re.IGNORECASE)
    return t


def escape_xml(text: str) -> str:
    """Escapes XML entities for safe ReportLab Paragraph rendering."""
    if text is None:
        return ""
    t = str(text)
    t = t.replace("&", "&amp;")
    t = t.replace("<", "&lt;")
    t = t.replace(">", "&gt;")
    t = t.replace('"', "&quot;")
    return t


# ============================================================================
# Numbered Canvas for Running Headers and Footers
# ============================================================================
class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas that writes dynamic page count ('Page X of Y')
    and running headers/footers across all pages.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)

    def draw_page_decorations(self, page_count: int):
        self.saveState()
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(colors.HexColor("#0284C7"))
        
        # Running Top Header
        self.drawString(36, 764, "PHISHGUARD AI")
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748B"))
        self.drawString(108, 764, "|   Automated Security Assessment & Threat Triage")
        self.drawRightString(576, 764, "REPORT CLASSIFICATION: TLP:AMBER+STRICT")

        # Top Rule
        self.setStrokeColor(colors.HexColor("#CBD5E1"))
        self.setLineWidth(0.6)
        self.line(36, 756, 576, 756)

        # Bottom Rule
        self.line(36, 42, 576, 42)

        # Running Footer
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748B"))
        self.drawString(36, 30, "CONFIDENTIAL  ·  PhishGuard AI Incident Response System  ·  Do not distribute externally")
        self.drawRightString(576, 30, f"Page {self._pageNumber} of {page_count}")
        self.restoreState()


# ============================================================================
# Stylesheet Builder
# ============================================================================
def build_report_styles() -> Dict[str, ParagraphStyle]:
    sample = getSampleStyleSheet()
    styles = {}

    styles["Title"] = ParagraphStyle(
        "DocTitle",
        parent=sample["Title"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=COLOR_PRIMARY,
        alignment=0,
        spaceAfter=4
    )

    styles["Subtitle"] = ParagraphStyle(
        "DocSubtitle",
        parent=sample["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=COLOR_MUTED,
        spaceAfter=14
    )

    styles["SectionHeader"] = ParagraphStyle(
        "SectionHeader",
        parent=sample["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=COLOR_PRIMARY,
        spaceBefore=14,
        spaceAfter=6,
        keepWithNext=True
    )

    styles["Normal"] = ParagraphStyle(
        "ReportNormal",
        parent=sample["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=COLOR_DARK
    )

    styles["NormalBold"] = ParagraphStyle(
        "ReportNormalBold",
        parent=styles["Normal"],
        fontName="Helvetica-Bold"
    )

    styles["Muted"] = ParagraphStyle(
        "ReportMuted",
        parent=styles["Normal"],
        fontSize=8,
        leading=11,
        textColor=COLOR_MUTED
    )

    styles["Code"] = ParagraphStyle(
        "ReportCode",
        parent=sample["Code"],
        fontName="Courier",
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#0F172A")
    )

    styles["CodeBold"] = ParagraphStyle(
        "ReportCodeBold",
        parent=styles["Code"],
        fontName="Courier-Bold"
    )

    styles["Badge"] = ParagraphStyle(
        "ReportBadge",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=9,
        leading=12,
        alignment=1
    )

    styles["TableHeader"] = ParagraphStyle(
        "ReportTableHeader",
        parent=styles["NormalBold"],
        fontSize=8,
        leading=11,
        textColor=COLOR_WHITE
    )

    styles["TableCell"] = ParagraphStyle(
        "ReportTableCell",
        parent=styles["Normal"],
        fontSize=8,
        leading=11
    )

    styles["TableCellBold"] = ParagraphStyle(
        "ReportTableCellBold",
        parent=styles["TableCell"],
        fontName="Helvetica-Bold"
    )

    styles["AlertBox"] = ParagraphStyle(
        "ReportAlertBox",
        parent=styles["Normal"],
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor("#78350F")
    )

    return styles


# ============================================================================
# Reusable UI Blocks
# ============================================================================
def create_meta_banner(
    analysis_id: str,
    timestamp_str: str,
    analysis_type: str,
    styles: Dict[str, ParagraphStyle]
) -> Table:
    """Builds the top metadata summary box."""
    data = [
        [
            Paragraph("<b>Analysis Reference ID:</b>", styles["TableCellBold"]),
            Paragraph(f"<font face='Courier-Bold' color='#0284C7'>{escape_xml(analysis_id)}</font>", styles["TableCell"]),
            Paragraph("<b>Analysis Type:</b>", styles["TableCellBold"]),
            Paragraph(escape_xml(analysis_type), styles["TableCell"]),
        ],
        [
            Paragraph("<b>Timestamp (UTC):</b>", styles["TableCellBold"]),
            Paragraph(escape_xml(timestamp_str), styles["TableCell"]),
            Paragraph("<b>Engine Mode:</b>", styles["TableCellBold"]),
            Paragraph("Static Lexical & Heuristic Triage", styles["TableCell"]),
        ]
    ]
    t = Table(data, colWidths=[120, 150, 100, 170])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), COLOR_LIGHT_BG),
        ("BOX", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    return t


def create_executive_summary_card(
    target_label: str,
    target_value: str,
    prediction: str,
    risk_score: float,
    risk_level: str,
    styles: Dict[str, ParagraphStyle]
) -> Table:
    """Builds the prominent Executive Verdict card with color-coded risk meter."""
    score_col = get_risk_color(risk_score)
    score_hex = f"#{score_col.hexval()[2:]}"

    data = [
        [
            Paragraph(f"<b>{escape_xml(target_label)}:</b>", styles["TableCellBold"]),
            Paragraph(f"<font face='Courier' color='#0369A1'>{escape_xml(target_value)}</font>", styles["TableCell"]),
            Paragraph("<b>Triage Risk Score</b>", styles["TableCellBold"]),
        ],
        [
            Paragraph("<b>Security Verdict:</b>", styles["TableCellBold"]),
            Paragraph(
                f"<font color='{score_hex}'><b>{escape_xml(prediction)}</b></font>  "
                f"<font color='#64748B'>({escape_xml(risk_level)})</font>",
                styles["TableCell"]
            ),
            Paragraph(
                f"<font size='16' color='{score_hex}'><b>{risk_score:.1f}</b></font> "
                f"<font size='10' color='#64748B'>/ 100</font>",
                styles["TableCell"]
            ),
        ]
    ]

    t = Table(data, colWidths=[110, 290, 140])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (1, -1), COLOR_LIGHT_BG),
        ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#F1F5F9")),
        ("BOX", (0, 0), (-1, -1), 1.0, score_col),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (2, 0), (2, -1), "CENTER"),
    ]))
    return t


def create_limitation_callout(
    limitation_text: str,
    styles: Dict[str, ParagraphStyle]
) -> Table:
    """Renders the required limitations & false-positive warning callout box."""
    data = [
        [
            Paragraph(
                "<b>⚠️ LIMITATION & FALSE-POSITIVE NOTICE:</b><br/>"
                + escape_xml(limitation_text),
                styles["AlertBox"]
            )
        ]
    ]
    t = Table(data, colWidths=[540])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FEF3C7")),
        ("BOX", (0, 0), (-1, -1), 1.0, colors.HexColor("#F59E0B")),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
    ]))
    return t


# ============================================================================
# 1. URL SECURITY REPORT GENERATOR
# ============================================================================
def generate_url_report(analysis_result: Dict[str, Any]) -> bytes:
    """
    Generates a professional URL Security Assessment PDF report.
    Returns the complete PDF as raw bytes.
    """
    if not isinstance(analysis_result, dict):
        raise ValueError("Invalid analysis_result: dictionary required")

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=45,
        bottomMargin=45
    )

    styles = build_report_styles()
    story: List[Any] = []

    # Safe extraction of attributes
    analysis_id = str(analysis_result.get("analysis_id") or analysis_result.get("id") or "URL-UNKNOWN")
    raw_url = str(analysis_result.get("url") or analysis_result.get("decoded_content") or "")
    defanged_url = str(analysis_result.get("defanged_url") or analysis_result.get("defanged_content") or defang_url_safe(raw_url))
    prediction = str(analysis_result.get("prediction") or analysis_result.get("classification") or "Unclassified")
    risk_score = float(analysis_result.get("risk_score") or 0.0)
    risk_level = str(analysis_result.get("risk_level") or "Low Risk")
    features = analysis_result.get("features") or {}
    indicators = analysis_result.get("indicator_details") or analysis_result.get("indicators") or []
    reasons = analysis_result.get("reasons") or []
    recommendations = analysis_result.get("recommendations") or []
    created_at = str(analysis_result.get("created_at") or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"))
    is_qr = (analysis_result.get("source_type") == "qr_code_image") or ("qr_count" in analysis_result) or analysis_id.startswith("QR-")

    # Title & Subtitle
    story.append(Paragraph("PhishGuard AI — Security Assessment Report", styles["Title"]))
    if is_qr:
        story.append(Paragraph(
            "Optical QR-Code Ingestion & URL Phishing Triage for Small Organizations",
            styles["Subtitle"]
        ))
        story.append(create_meta_banner(analysis_id, created_at, "QR-Code Optical Assessment", styles))
    else:
        story.append(Paragraph(
            "Static Structural & Lexical URL Phishing Triage for Small Organizations",
            styles["Subtitle"]
        ))
        story.append(create_meta_banner(analysis_id, created_at, "URL Security Analysis", styles))
    story.append(Spacer(1, 10))

    # Executive Summary Box
    target_hdr = "Decoded QR URL (Defanged)" if is_qr else "Target URL (Defanged)"
    story.append(create_executive_summary_card(
        target_hdr,
        defanged_url,
        prediction,
        risk_score,
        risk_level,
        styles
    ))
    story.append(Spacer(1, 12))

    # Section 1: URL Technical & Structural Features
    story.append(Paragraph("1. Technical & Structural Feature Breakdown", styles["SectionHeader"]))
    
    scheme = features.get("scheme", "N/A").upper()
    is_ip = "YES (Numeric IP Hostname)" if features.get("is_ip") else "No (Registered Domain)"
    hostname = features.get("hostname", "N/A")
    defanged_host = defang_url_safe(hostname)
    decoded_host = features.get("decoded_hostname")
    subdomains_count = str(features.get("subdomains_count", 0))
    path_len = str(features.get("path_length", len(features.get("path", ""))))
    has_at = "YES (Potential credential obfuscation)" if features.get("has_at_symbol") else "No"
    
    # Extra row if IDN or QR code
    row2_label = "<b>Target Hostname</b>"
    row2_val = f"<font face='Courier'>{escape_xml(defanged_host)}</font>"
    if decoded_host and decoded_host != hostname:
        row2_val += f"<br/><font color='#64748B' size='7'>IDN Decoded: {escape_xml(defang_url_safe(decoded_host))}</font>"

    features_data = [
        [
            Paragraph("<b>Ingestion Source</b>" if is_qr else "<b>URL Scheme</b>", styles["TableCellBold"]),
            Paragraph("QR Image (Optical Extract)" if is_qr else f"<font color='{'#10B981' if scheme == 'HTTPS' else '#EF4444'}'><b>{scheme}</b></font> ({'Encrypted TLS' if scheme == 'HTTPS' else 'Plaintext HTTP'})", styles["TableCell"]),
            Paragraph("<b>IP Hostname</b>", styles["TableCellBold"]),
            Paragraph(escape_xml(is_ip), styles["TableCell"]),
        ],
        [
            Paragraph(row2_label, styles["TableCellBold"]),
            Paragraph(row2_val, styles["TableCell"]),
            Paragraph("<b>Subdomain Count</b>", styles["TableCellBold"]),
            Paragraph(f"{subdomains_count} subdomains", styles["TableCell"]),
        ],
        [
            Paragraph("<b>Path Length</b>", styles["TableCellBold"]),
            Paragraph(f"{path_len} characters", styles["TableCell"]),
            Paragraph("<b>'@' Symbol in URL</b>", styles["TableCellBold"]),
            Paragraph(escape_xml(has_at), styles["TableCell"]),
        ]
    ]
    t_feat = Table(features_data, colWidths=[120, 160, 110, 150])
    t_feat.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), COLOR_LIGHT_BG),
        ("BOX", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(t_feat)
    story.append(Spacer(1, 12))

    # Section 2: Detected Threat Indicators & Evidence
    story.append(Paragraph(f"2. Detected Threat Indicators & Evidence ({len(indicators)} Flagged)", styles["SectionHeader"]))
    if indicators:
        ind_rows = [
            [
                Paragraph("<b>Indicator Category</b>", styles["TableHeader"]),
                Paragraph("<b>Severity</b>", styles["TableHeader"]),
                Paragraph("<b>Weight</b>", styles["TableHeader"]),
                Paragraph("<b>Evidence & Findings</b>", styles["TableHeader"]),
                Paragraph("<b>Why It Matters</b>", styles["TableHeader"]),
            ]
        ]
        for ind in indicators:
            sev = str(ind.get("severity", "Medium"))
            sev_col = {
                "Critical": "#EF4444",
                "High": "#F97316",
                "Medium": "#F59E0B",
                "Low": "#10B981"
            }.get(sev, "#64748B")

            ind_rows.append([
                Paragraph(f"<b>{escape_xml(ind.get('category', 'Unknown'))}</b>", styles["TableCell"]),
                Paragraph(f"<font color='{sev_col}'><b>{escape_xml(sev)}</b></font>", styles["TableCell"]),
                Paragraph(f"+{ind.get('weight', 0)}", styles["TableCell"]),
                Paragraph(f"<font face='Courier' size='7'>{escape_xml(defang_url_safe(ind.get('evidence', 'N/A')))}</font>", styles["TableCell"]),
                Paragraph(escape_xml(ind.get("why_it_matters") or ind.get("description") or "N/A"), styles["TableCell"]),
            ])

        t_ind = Table(ind_rows, colWidths=[120, 50, 40, 160, 170])
        t_ind.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), COLOR_PRIMARY),
            ("BOX", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [COLOR_WHITE, COLOR_LIGHT_BG]),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(t_ind)
    else:
        story.append(Paragraph(
            "<i>✓ No high-risk structural or lexical indicators detected during static analysis.</i>",
            styles["Muted"]
        ))
    story.append(Spacer(1, 12))

    # Section 3: Analysis Reasons & Findings
    if reasons:
        story.append(Paragraph("3. Heuristic Decision Rationale", styles["SectionHeader"]))
        for r in reasons:
            story.append(Paragraph(f"• {escape_xml(defang_url_safe(str(r)))}", styles["Normal"]))
            story.append(Spacer(1, 2))
        story.append(Spacer(1, 8))

    # Section 4: Recommended Security Actions
    story.append(Paragraph("4. Recommended Security Actions", styles["SectionHeader"]))
    if recommendations:
        for idx, rec in enumerate(recommendations, 1):
            story.append(Paragraph(f"<b>{idx}.</b> {escape_xml(rec)}", styles["Normal"]))
            story.append(Spacer(1, 2))
    else:
        story.append(Paragraph("• Verify destination authenticity out-of-band before submitting credentials.", styles["Normal"]))
    story.append(Spacer(1, 12))

    # Section 5: False-Positive Warning & Limitation Box
    story.append(create_limitation_callout(
        "Static analysis assesses syntax, lexical patterns, and heuristic indicators without active network resolution "
        "or payload execution. Legitimate resources may occasionally exhibit unusual URL structures, and newly registered "
        "malicious domains may not trigger every heuristic. This score represents an estimated triage priority, not a certified "
        "adjudication of malice. Always verify through authoritative security channels before taking destructive action.",
        styles
    ))

    # Build document in memory
    doc.build(story, canvasmaker=NumberedCanvas)
    return buffer.getvalue()


# ============================================================================
# 2. EMAIL SECURITY REPORT GENERATOR
# ============================================================================
def generate_email_report(analysis_result: Dict[str, Any]) -> bytes:
    """
    Generates a professional Email & Spam Security Assessment PDF report.
    Returns the complete PDF as raw bytes.
    """
    if not isinstance(analysis_result, dict):
        raise ValueError("Invalid analysis_result: dictionary required")

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=45,
        bottomMargin=45
    )

    styles = build_report_styles()
    story: List[Any] = []

    # Safe extraction of attributes
    analysis_id = str(analysis_result.get("analysis_id") or analysis_result.get("id") or "EML-UNKNOWN")
    subject = str(analysis_result.get("subject") or "(No Subject)")
    safe_subject = redact_sensitive_text(subject)
    sender = str(analysis_result.get("sender") or "unspecified-sender@external.mail")
    safe_sender = redact_sensitive_text(sender)

    # Model Telemetry
    model_name = str(analysis_result.get("model_name") or "GowthamAdhikarla/email-spam-detector-distilbert")
    model_label = str(analysis_result.get("model_label") or "LABEL_0")
    classification_score = float(analysis_result.get("classification_score") or 0.0)
    inference_device = str(analysis_result.get("inference_device") or "cpu_fallback")
    text_truncated = bool(analysis_result.get("text_truncated", False))

    # Triage Scores
    risk_score = float(analysis_result.get("risk_score") or 0.0)
    risk_level = str(analysis_result.get("risk_level") or "Low Risk")
    prediction = str(analysis_result.get("prediction") or analysis_result.get("classification") or "Legitimate")

    email_indicators = analysis_result.get("email_indicators") or analysis_result.get("indicator_details") or []
    extracted_urls = analysis_result.get("extracted_urls") or []
    url_results = analysis_result.get("url_analysis_results") or []
    reasons = analysis_result.get("reasons") or []
    recommendations = analysis_result.get("recommendations") or []
    created_at = str(analysis_result.get("created_at") or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"))

    # Title & Subtitle
    story.append(Paragraph("PhishGuard AI — Email Triage Assessment Report", styles["Title"]))
    story.append(Paragraph(
        "Hybrid Machine Learning Spam Classification & Explainable Phishing Analysis",
        styles["Subtitle"]
    ))

    # Top Metadata Banner
    story.append(create_meta_banner(analysis_id, created_at, "Email Security Analysis", styles))
    story.append(Spacer(1, 10))

    # Executive Summary Box
    story.append(create_executive_summary_card(
        "Analyzed Subject",
        safe_subject[:90] + ("..." if len(safe_subject) > 90 else ""),
        prediction,
        risk_score,
        risk_level,
        styles
    ))
    story.append(Spacer(1, 12))

    # Section 1: Pretrained AI Model Telemetry
    story.append(Paragraph("1. Machine Learning Spam Classifier Telemetry", styles["SectionHeader"]))
    
    label_meaning = "Unsolicited Bulk Spam (LABEL_1)" if ("LABEL_1" in model_label or "SPAM" in model_label.upper()) else "Normal / Ham (LABEL_0)"
    trunc_status = "YES (Input exceeded 512 token boundary)" if text_truncated else "No (Complete message analyzed)"
    
    ai_telemetry_data = [
        [
            Paragraph("<b>Pretrained Model ID</b>", styles["TableCellBold"]),
            Paragraph(f"<font face='Courier' color='#0284C7'>{escape_xml(model_name)}</font>", styles["TableCell"]),
            Paragraph("<b>Inference Device</b>", styles["TableCellBold"]),
            Paragraph(f"<font color='{'#10B981' if 'cuda' in inference_device.lower() else '#64748B'}'><b>{escape_xml(inference_device)}</b></font>", styles["TableCell"]),
        ],
        [
            Paragraph("<b>Model Raw Output Label</b>", styles["TableCellBold"]),
            Paragraph(f"<b>{escape_xml(model_label)}</b> ({escape_xml(label_meaning)})", styles["TableCell"]),
            Paragraph("<b>Model Confidence</b>", styles["TableCellBold"]),
            Paragraph(f"<b>{classification_score:.1%}</b>", styles["TableCell"]),
        ],
        [
            Paragraph("<b>Input Truncation</b>", styles["TableCellBold"]),
            Paragraph(escape_xml(trunc_status), styles["TableCell"]),
            Paragraph("<b>Model Scope</b>", styles["TableCellBold"]),
            Paragraph("Promotional Spam Detector (Not Phishing)", styles["TableCell"]),
        ]
    ]

    t_ai = Table(ai_telemetry_data, colWidths=[120, 160, 110, 150])
    t_ai.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), COLOR_LIGHT_BG),
        ("BOX", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(t_ai)
    
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        "<i>Clarification: The DistilBERT model score measures similarity to unsolicited promotional bulk email. "
        "The overall triage risk score (0–100) is calculated separately by PhishGuard's multi-layered heuristic risk engine, "
        "which incorporates social engineering indicators and embedded URL risks.</i>",
        styles["Muted"]
    ))
    story.append(Spacer(1, 10))

    # Section 2: Explainable Email Pattern Indicators
    story.append(Paragraph(f"2. Explainable Email Threat Indicators ({len(email_indicators)} Flagged)", styles["SectionHeader"]))
    if email_indicators:
        ind_rows = [
            [
                Paragraph("<b>Indicator Name</b>", styles["TableHeader"]),
                Paragraph("<b>Severity</b>", styles["TableHeader"]),
                Paragraph("<b>Weight</b>", styles["TableHeader"]),
                Paragraph("<b>Message Evidence</b>", styles["TableHeader"]),
                Paragraph("<b>Why It Matters</b>", styles["TableHeader"]),
            ]
        ]
        for ind in email_indicators:
            sev = str(ind.get("severity", "Medium"))
            sev_col = {
                "Critical": "#EF4444",
                "High": "#F97316",
                "Medium": "#F59E0B",
                "Low": "#10B981"
            }.get(sev, "#64748B")

            ind_rows.append([
                Paragraph(f"<b>{escape_xml(ind.get('category', 'Unknown'))}</b>", styles["TableCell"]),
                Paragraph(f"<font color='{sev_col}'><b>{escape_xml(sev)}</b></font>", styles["TableCell"]),
                Paragraph(f"+{ind.get('weight', 0)}", styles["TableCell"]),
                Paragraph(f"<font face='Courier' size='7'>{escape_xml(redact_sensitive_text(ind.get('evidence', 'N/A')))}</font>", styles["TableCell"]),
                Paragraph(escape_xml(ind.get("why_it_matters") or ind.get("description") or "N/A"), styles["TableCell"]),
            ])

        t_ind = Table(ind_rows, colWidths=[120, 50, 40, 160, 170])
        t_ind.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), COLOR_PRIMARY),
            ("BOX", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [COLOR_WHITE, COLOR_LIGHT_BG]),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(t_ind)
    else:
        story.append(Paragraph(
            "<i>✓ No high-risk social engineering or urgent credential harvesting indicators identified in email text.</i>",
            styles["Muted"]
        ))
    story.append(Spacer(1, 10))

    # Section 3: Embedded URL Security Findings
    story.append(Paragraph(f"3. Embedded URL Security Findings ({len(extracted_urls)} Links Extracted)", styles["SectionHeader"]))
    if url_results:
        url_rows = [
            [
                Paragraph("<b>Defanged Link Destination</b>", styles["TableHeader"]),
                Paragraph("<b>Risk Score</b>", styles["TableHeader"]),
                Paragraph("<b>Risk Level</b>", styles["TableHeader"]),
                Paragraph("<b>Key Findings & Reasons</b>", styles["TableHeader"]),
            ]
        ]
        for u in url_results:
            u_score = float(u.get("risk_score") or 0.0)
            u_col = get_risk_color(u_score)
            u_hex = f"#{u_col.hexval()[2:]}"
            reasons_summary = "; ".join(u.get("reasons", [])[:2]) or "No high-risk indicators"

            url_rows.append([
                Paragraph(f"<font face='Courier' size='7'>{escape_xml(defang_url_safe(u.get('defanged_url') or u.get('url', '')))}</font>", styles["TableCell"]),
                Paragraph(f"<font color='{u_hex}'><b>{u_score:.1f}</b></font>", styles["TableCell"]),
                Paragraph(f"<font color='{u_hex}'><b>{escape_xml(u.get('risk_level', 'Low Risk'))}</b></font>", styles["TableCell"]),
                Paragraph(escape_xml(reasons_summary), styles["TableCell"]),
            ])

        t_urls = Table(url_rows, colWidths=[190, 50, 80, 220])
        t_urls.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), COLOR_PRIMARY),
            ("BOX", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [COLOR_WHITE, COLOR_LIGHT_BG]),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(t_urls)
    elif extracted_urls:
        for u_raw in extracted_urls:
            story.append(Paragraph(f"• <font face='Courier'>{escape_xml(defang_url_safe(str(u_raw)))}</font>", styles["Normal"]))
    else:
        story.append(Paragraph("<i>No embedded hyperlinks detected in email body or subject.</i>", styles["Muted"]))
    story.append(Spacer(1, 10))

    # Section 4: Contributing Reasons
    if reasons:
        story.append(Paragraph("4. Contributing Security Reasons", styles["SectionHeader"]))
        for r in reasons:
            story.append(Paragraph(f"• {escape_xml(defang_url_safe(redact_sensitive_text(str(r))))}", styles["Normal"]))
            story.append(Spacer(1, 2))
        story.append(Spacer(1, 8))

    # Section 5: Recommended Security Actions
    story.append(Paragraph("5. Recommended Security Actions", styles["SectionHeader"]))
    if recommendations:
        for idx, rec in enumerate(recommendations, 1):
            story.append(Paragraph(f"<b>{idx}.</b> {escape_xml(rec)}", styles["Normal"]))
            story.append(Spacer(1, 2))
    else:
        story.append(Paragraph("• Exercise caution and verify sender authenticity before responding or clicking.", styles["Normal"]))
    story.append(Spacer(1, 12))

    # Section 6: Limitations & False-Positive Advisory
    story.append(create_limitation_callout(
        "The DistilBERT language model is an open-source classifier trained on promotional and unsolicited spam datasets. "
        "It does not independently verify credential authenticity or identify zero-day targeted attacks. Furthermore, legitimate "
        "business emails frequently contain urgent deadlines, password renewal instructions, or links to third-party services. "
        "This report is an automated security advisory. Review suspicious communications with your security operations team.",
        styles
    ))

    # Build document in memory
    doc.build(story, canvasmaker=NumberedCanvas)
    return buffer.getvalue()


# ============================================================================
# Server-Side Analysis Result Store & Safe Lookup
# ============================================================================
# Bounded in-memory dictionary of completed analyses to guarantee authentic reports
_analysis_store: Dict[str, Dict[str, Any]] = {}

def store_server_analysis(analysis_id: str, data: Dict[str, Any]) -> None:
    """Stores the authoritative server-side analysis result for subsequent report generation."""
    if not analysis_id:
        return
    # Cap cache to last 500 items to avoid unbounded memory growth
    if len(_analysis_store) > 500:
        first_key = next(iter(_analysis_store))
        del _analysis_store[first_key]
    _analysis_store[analysis_id] = data

def get_server_analysis(analysis_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves authoritative server-side analysis result by ID."""
    if not analysis_id:
        return None
    return _analysis_store.get(analysis_id)


def reconstruct_url_analysis_from_db(record: Any) -> Dict[str, Any]:
    """Reconstructs authentic URL analysis dictionary from SQLite EmailAnalysis record."""
    raw_meta = record.raw_headers_summary if isinstance(record.raw_headers_summary, dict) else {}
    features = raw_meta.get("features", {})
    indicators = record.indicator_details or []
    return {
        "analysis_id": record.id,
        "id": record.id,
        "url": record.body_snippet or "",
        "defanged_url": defang_url_safe(record.body_snippet or ""),
        "prediction": raw_meta.get("prediction") or raw_meta.get("classification") or "Legitimate",
        "risk_score": float(record.risk_score or 0.0),
        "risk_level": record.risk_level or "Low Risk",
        "features": features,
        "indicator_details": indicators,
        "indicators": indicators,
        "reasons": [
            f"[{ind.get('category')}]: {ind.get('description', '')}"
            for ind in indicators
        ] or ["Heuristic static analysis completed."],
        "recommendations": record.recommendations or ["Exercise standard web hygiene."],
        "created_at": record.created_at.isoformat() if hasattr(record.created_at, "isoformat") else str(record.created_at)
    }


def reconstruct_email_analysis_from_db(record: Any) -> Dict[str, Any]:
    """Reconstructs authentic Email analysis dictionary from SQLite EmailAnalysis record."""
    raw_meta = record.raw_headers_summary if isinstance(record.raw_headers_summary, dict) else {}
    indicators = record.indicator_details or []
    extracted = record.extracted_urls or []
    return {
        "analysis_id": record.id,
        "id": record.id,
        "subject": record.subject or "(No Subject)",
        "sender": record.sender or "unspecified-sender@external.mail",
        "model_name": raw_meta.get("model_name", "GowthamAdhikarla/email-spam-detector-distilbert"),
        "model_label": raw_meta.get("model_label", "LABEL_0"),
        "classification_score": float(raw_meta.get("classification_score") or 0.88),
        "inference_device": raw_meta.get("inference_device", "cpu_fallback"),
        "text_truncated": bool(raw_meta.get("text_truncated", False)),
        "risk_score": float(record.risk_score or 0.0),
        "risk_level": record.risk_level or "Low Risk",
        "prediction": raw_meta.get("prediction", "Legitimate"),
        "email_indicators": indicators,
        "indicator_details": indicators,
        "extracted_urls": [
            (u.get("original_url") or u.get("url")) if isinstance(u, dict) else str(u)
            for u in extracted
        ],
        "url_analysis_results": [
            u for u in extracted if isinstance(u, dict)
        ],
        "reasons": [
            f"[{ind.get('category')}]: {ind.get('description', '')}"
            for ind in indicators
        ] or ["AI spam model and pattern evaluation completed."],
        "recommendations": record.recommendations or ["Verify sender credentials out-of-band."],
        "created_at": record.created_at.isoformat() if hasattr(record.created_at, "isoformat") else str(record.created_at)
    }


def generate_qr_report(analysis_result: Dict[str, Any]) -> bytes:
    """Convenience helper for generating PDF reports for QR-code triage results."""
    cloned = dict(analysis_result)
    cloned["source_type"] = "qr_code_image"
    return generate_url_report(cloned)

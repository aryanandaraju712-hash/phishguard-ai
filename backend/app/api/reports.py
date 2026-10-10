import csv
import io
import re
from typing import Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Response, status, Body
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.models import Incident, EmailAnalysis
from app.schemas.schemas import IncidentResponse, EmailAnalysisResponse, ReportDownloadRequest
from app.services.report_generator import (
    generate_url_report,
    generate_email_report,
    get_server_analysis,
    reconstruct_url_analysis_from_db,
    reconstruct_email_analysis_from_db
)

router = APIRouter(prefix="", tags=["Reports"])


def sanitize_csv_field(val: str) -> str:
    """Safely escapes fields for CSV to prevent formula injection (CSV injection)."""
    if not val:
        return ""
    val_str = str(val).strip()
    if val_str and val_str[0] in ("=", "+", "-", "@", "\t", "\r"):
        val_str = "'" + val_str
    return val_str


@router.get("/reports/{incident_id}")
def get_incident_json_report(incident_id: str, db: Session = Depends(get_db)):
    """Export single incident triage report in full structured JSON format."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    
    resp = IncidentResponse.model_validate(incident)
    if incident.assigned_analyst:
        resp.assigned_analyst_name = incident.assigned_analyst.full_name
    if incident.analysis:
        resp.analysis = EmailAnalysisResponse.model_validate(incident.analysis)
        
    return resp.model_dump()


@router.get("/reports/export/csv")
def export_incidents_csv(db: Session = Depends(get_db)):
    """
    Export incident triage logs as a secure, sanitized CSV file.
    Includes score, classification, evidence, uncertainty, recommendations, timestamp, and incident ID.
    """
    incidents = db.query(Incident).order_by(Incident.created_at.desc()).all()

    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_ALL)

    # Header row
    writer.writerow([
        "Incident ID",
        "Subject / Title",
        "Risk Score (0-100)",
        "Risk Level",
        "Triage Status",
        "Assigned Analyst",
        "Confidence / Uncertainty",
        "Key Indicators / Evidence",
        "Recommended Next Action",
        "Missing Evidence",
        "Is Sample",
        "Created At (UTC)"
    ])

    for inc in incidents:
        anl = inc.analysis
        indicators_summary = ""
        recs_summary = ""
        missing_summary = ""
        confidence = "Medium"

        if anl:
            confidence = anl.confidence_score or "Medium"
            if anl.indicator_details:
                indicators_summary = "; ".join(
                    [f"[{i.get('category')}]: {i.get('description', '')}" for i in anl.indicator_details]
                )
            if anl.recommendations:
                recs_summary = "; ".join(anl.recommendations)
            if anl.missing_evidence:
                missing_summary = "; ".join(anl.missing_evidence)

        analyst_name = inc.assigned_analyst.full_name if inc.assigned_analyst else "Unassigned"

        writer.writerow([
            sanitize_csv_field(inc.id),
            sanitize_csv_field(inc.title),
            str(inc.risk_score),
            sanitize_csv_field(inc.risk_level),
            sanitize_csv_field(inc.status),
            sanitize_csv_field(analyst_name),
            sanitize_csv_field(confidence),
            sanitize_csv_field(indicators_summary),
            sanitize_csv_field(recs_summary),
            sanitize_csv_field(missing_summary),
            "Yes" if inc.is_sample else "No",
            inc.created_at.strftime("%Y-%m-%d %H:%M:%S")
        ])

    output.seek(0)
    filename = "phishguard_incident_triage_report.csv"
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


# ============================================================================
# PDF Security Report Endpoints
# ============================================================================

def _resolve_url_analysis(payload: Dict[str, Any], db: Session) -> Dict[str, Any]:
    """
    Safely resolves the authentic server-side URL analysis result.
    Prefers retrieving authoritative server-stored results by analysis ID.
    """
    aid = payload.get("analysis_id") or payload.get("id")
    
    # 1. Check in-memory server cache
    if aid:
        cached = get_server_analysis(str(aid))
        if cached:
            return cached
        
        # 2. Check SQLite persistent database
        db_record = db.query(EmailAnalysis).filter(EmailAnalysis.id == str(aid)).first()
        if db_record:
            return reconstruct_url_analysis_from_db(db_record)

    # 3. If not found in server records, check if valid client-submitted payload is provided
    has_valid_fields = bool(
        payload.get("url") or 
        ("features" in payload and "risk_score" in payload) or
        ("prediction" in payload and "risk_score" in payload)
    )

    if has_valid_fields:
        # Validate critical fields
        raw_score = payload.get("risk_score", 0.0)
        try:
            score = float(raw_score)
            if not (0.0 <= score <= 100.0):
                score = max(0.0, min(100.0, score))
        except (ValueError, TypeError):
            score = 0.0

        validated_dict = dict(payload)
        validated_dict["risk_score"] = score
        if "analysis_id" not in validated_dict:
            validated_dict["analysis_id"] = str(aid or "URL-ADHOC")
        return validated_dict

    # 4. If an analysis_id was supplied but does not exist, return 404
    if aid:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"URL Analysis result not found for ID: {aid}"
        )

    # 5. Empty or malformed input
    raise HTTPException(
        status_code=getattr(status, "HTTP_422_UNPROCESSABLE_CONTENT", 422),
        detail="Missing analysis_id or valid URL analysis payload"
    )


def _resolve_email_analysis(payload: Dict[str, Any], db: Session) -> Dict[str, Any]:
    """
    Safely resolves the authentic server-side Email analysis result.
    Prefers retrieving authoritative server-stored results by analysis ID.
    """
    aid = payload.get("analysis_id") or payload.get("id")

    # 1. Check in-memory server cache
    if aid:
        cached = get_server_analysis(str(aid))
        if cached:
            return cached

        # 2. Check SQLite persistent database
        db_record = db.query(EmailAnalysis).filter(EmailAnalysis.id == str(aid)).first()
        if db_record:
            return reconstruct_email_analysis_from_db(db_record)

    # 3. If not found in server records, check if valid client-submitted payload is provided
    has_valid_fields = bool(
        payload.get("subject") or 
        payload.get("model_name") or
        ("email_indicators" in payload and "risk_score" in payload) or
        ("prediction" in payload and "risk_score" in payload)
    )

    if has_valid_fields:
        raw_score = payload.get("risk_score", 0.0)
        try:
            score = float(raw_score)
            if not (0.0 <= score <= 100.0):
                score = max(0.0, min(100.0, score))
        except (ValueError, TypeError):
            score = 0.0

        validated_dict = dict(payload)
        validated_dict["risk_score"] = score
        if "analysis_id" not in validated_dict:
            validated_dict["analysis_id"] = str(aid or "EML-ADHOC")
        return validated_dict

    # 4. If an analysis_id was supplied but does not exist, return 404
    if aid:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Email Analysis result not found for ID: {aid}"
        )

    # 5. Empty or malformed input
    raise HTTPException(
        status_code=getattr(status, "HTTP_422_UNPROCESSABLE_CONTENT", 422),
        detail="Missing analysis_id or valid Email analysis payload"
    )


@router.post("/report/url")
@router.post("/reports/url")
def create_url_pdf_report(
    payload: Dict[str, Any] = Body(...),
    db: Session = Depends(get_db)
):
    """
    Generates and downloads a professional URL Security Assessment PDF report.
    Validates input and prefers authentic server-side analysis records.
    """
    analysis_data = _resolve_url_analysis(payload, db)

    try:
        pdf_bytes = generate_url_report(analysis_data)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to compile URL report PDF: {str(exc)}"
        )

    raw_id = str(analysis_data.get("analysis_id") or analysis_data.get("id") or "URL-REPORT")
    safe_id = re.sub(r"[^A-Za-z0-9_-]", "", raw_id)[:40]
    filename = f"PhishGuard_URL_Report_{safe_id}.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Type": "application/pdf"
        }
    )


@router.post("/report/qr")
@router.post("/reports/qr")
def create_qr_pdf_report(
    payload: Dict[str, Any] = Body(...),
    db: Session = Depends(get_db)
):
    """
    Generates and downloads a professional QR-Code Optical Security Assessment PDF report.
    Validates input and prefers authentic server-side analysis records.
    """
    analysis_data = _resolve_url_analysis(payload, db)
    analysis_data = dict(analysis_data)
    analysis_data["source_type"] = "qr_code_image"

    try:
        pdf_bytes = generate_url_report(analysis_data)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to compile QR report PDF: {str(exc)}"
        )

    raw_id = str(analysis_data.get("analysis_id") or analysis_data.get("id") or "QR-REPORT")
    safe_id = re.sub(r"[^A-Za-z0-9_-]", "", raw_id)[:40]
    filename = f"PhishGuard_QR_Report_{safe_id}.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Type": "application/pdf"
        }
    )


@router.post("/report/email")
@router.post("/reports/email")
def create_email_pdf_report(
    payload: Dict[str, Any] = Body(...),
    db: Session = Depends(get_db)
):
    """
    Generates and downloads a professional Email & Spam Security Assessment PDF report.
    Validates input and prefers authentic server-side analysis records.
    """
    analysis_data = _resolve_email_analysis(payload, db)

    try:
        pdf_bytes = generate_email_report(analysis_data)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to compile Email report PDF: {str(exc)}"
        )

    raw_id = str(analysis_data.get("analysis_id") or analysis_data.get("id") or "EML-REPORT")
    safe_id = re.sub(r"[^A-Za-z0-9_-]", "", raw_id)[:40]
    filename = f"PhishGuard_Email_Report_{safe_id}.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Type": "application/pdf"
        }
    )

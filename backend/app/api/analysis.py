import uuid
import datetime
from typing import List, Optional, Dict, Any, Tuple
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, Query, status
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.models import EmailAnalysis, Incident, StatusHistory, User
from app.schemas.schemas import (
    EmailAnalyzeRequest, EmailAnalysisResponse, URLAnalyzeRequest, URLAnalysisResponse,
    EmailAIAnalysisResponse, QRAnalysisResponse
)
from app.services.email_parser import parse_manual_email_input, parse_eml_bytes
from app.services.phishing_analyzer import analyze_email_data, determine_classification
from app.services.url_analyzer import analyze_single_url_comprehensive, analyze_url_comprehensive
from app.services.email_analyzer import analyze_email_comprehensive, model_manager
from app.services.qr_analyzer import analyze_qr_image_bytes
from app.services.ai_explainer import explain_analysis
from app.services.report_generator import store_server_analysis
from app.api.deps import get_current_user
from app.core.config import settings

router = APIRouter(prefix="", tags=["Analysis"])

def generate_incident_id(db: Session) -> str:
    count = db.query(Incident).count() + 1
    return f"INC-2026-{count:04d}"

def process_and_persist_analysis(
    parsed_email: dict,
    db: Session,
    current_user: Optional[User],
    has_eml: bool = False,
    create_incident: bool = True
) -> Tuple[EmailAnalysis, Dict[str, Any]]:
    """Runs analysis, generates explanations, and persists to SQLite database."""
    # Run triage detection engine
    triage_result = analyze_email_data(parsed_email)

    # Generate explanations
    ai_explanations = explain_analysis(triage_result["indicator_details"], parsed_email)

    # Unique analysis ID
    analysis_id = f"ANL-{uuid.uuid4().hex[:8].upper()}"

    meta = {
        "classification": triage_result.get("classification", "Legitimate"),
        "is_spam": triage_result.get("is_spam", False),
        "highlighted_phrases": triage_result.get("highlighted_phrases", []),
        "analysis_type": parsed_email.get("analysis_type", "message"),
        "authentication": parsed_email.get("authentication")
    }

    # Build DB record
    analysis = EmailAnalysis(
        id=analysis_id,
        subject=parsed_email.get("subject") or "(No Subject)",
        sender=parsed_email.get("sender_raw") or parsed_email["sender"]["email"],
        reply_to=parsed_email.get("reply_to_raw") or (parsed_email.get("reply_to", {}).get("email") if parsed_email.get("reply_to") else None),
        recipient=parsed_email.get("recipient"),
        body_snippet=parsed_email.get("body_snippet"),
        has_eml=has_eml,
        raw_headers_summary=meta,
        urls_count=triage_result["urls_count"],
        attachments_count=triage_result["attachments_count"],
        risk_score=triage_result["risk_score"],
        risk_level=triage_result["risk_level"],
        confidence_score=triage_result["confidence_score"],
        indicator_details=triage_result["indicator_details"],
        ai_explanation=ai_explanations,
        recommendations=triage_result["recommendations"],
        missing_evidence=triage_result["missing_evidence"],
        extracted_urls=triage_result["extracted_urls"],
        attachment_names=triage_result["attachment_names"],
        is_synthetic=False,
        analyzed_by_user_id=current_user.id if current_user else None,
        created_at=datetime.datetime.utcnow()
    )
    db.add(analysis)
    db.flush()

    # Automatically create incident if requested
    if create_incident:
        inc_id = generate_incident_id(db)
        incident = Incident(
            id=inc_id,
            title=analysis.subject,
            risk_score=analysis.risk_score,
            risk_level=analysis.risk_level,
            status="New",
            assigned_to_user_id=current_user.id if (current_user and current_user.role == "analyst") else None,
            analysis_id=analysis.id,
            is_sample=False,
            created_at=datetime.datetime.utcnow(),
            updated_at=datetime.datetime.utcnow()
        )
        db.add(incident)
        db.flush()

        history = StatusHistory(
            incident_id=incident.id,
            user_id=current_user.id if current_user else None,
            user_name=current_user.full_name if current_user else "Automated Submission",
            old_status="None",
            new_status="New",
            comment="Initial automated triage categorization",
            timestamp=datetime.datetime.utcnow()
        )
        db.add(history)

    db.commit()
    db.refresh(analysis)
    return analysis, triage_result

@router.post("/analyze", response_model=EmailAnalysisResponse)
def analyze_manual_email(
    request: EmailAnalyzeRequest,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user)
):
    """Analyze email, message, or SMS content submitted via form text fields."""
    sender_val = (request.sender or "").strip()
    if not sender_val:
        sender_val = "unspecified-sender@external.mail"

    parsed = parse_manual_email_input(
        subject=request.subject or "Message Analysis",
        sender=sender_val,
        reply_to=request.reply_to,
        recipient=request.recipient,
        body=request.body,
        explicit_urls=request.urls
    )
    parsed["analysis_type"] = "message"

    analysis, triage_result = process_and_persist_analysis(
        parsed_email=parsed,
        db=db,
        current_user=current_user,
        has_eml=False,
        create_incident=request.create_incident if request.create_incident is not None else True
    )

    # Attach linked incident_id if available
    linked_inc = db.query(Incident).filter(Incident.analysis_id == analysis.id).first()
    res = EmailAnalysisResponse.model_validate(analysis)
    res.classification = triage_result.get("classification", "Legitimate")
    res.is_spam = triage_result.get("is_spam", False)
    res.highlighted_phrases = triage_result.get("highlighted_phrases", [])
    res.analysis_type = "message"
    if linked_inc:
        res.incident_id = linked_inc.id
    return res

@router.post("/analyze-email", response_model=EmailAIAnalysisResponse)
@router.post("/analyze-email-ai", response_model=EmailAIAnalysisResponse)
def analyze_email_endpoint(
    request: EmailAnalyzeRequest,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user)
):
    """
    Primary AI Email Spam Detection & Phishing Triage endpoint.
    Accepts JSON: {"subject": "...", "body": "..."}
    Performs DistilBERT spam classification, pattern analysis, and embedded URL triage.
    """
    clean_sub = (request.subject or "").strip()
    clean_body = (request.body or "").strip()
    if not clean_sub and not clean_body:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Email subject and body cannot both be empty"
        )

    try:
        triage_res = analyze_email_comprehensive(
            subject=clean_sub,
            body=clean_body,
            sender=request.sender,
            reply_to=request.reply_to
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))

    analysis_id = triage_res["analysis_id"]
    meta = {
        "model_name": triage_res["model_name"],
        "inference_device": triage_res["inference_device"],
        "model_label": triage_res["model_label"],
        "classification": triage_res["prediction"],
        "prediction": triage_res["prediction"],
        "is_spam": ("SPAM" in triage_res["model_label"].upper() or "LABEL_1" in triage_res["model_label"]),
        "analysis_type": "email"
    }

    analysis = EmailAnalysis(
        id=analysis_id,
        subject=clean_sub or "(No Subject)",
        sender=request.sender or "unspecified-sender@external.mail",
        reply_to=request.reply_to,
        recipient=request.recipient,
        body_snippet=clean_body[:400],
        has_eml=False,
        raw_headers_summary=meta,
        urls_count=len(triage_res["extracted_urls"]),
        attachments_count=0,
        risk_score=triage_res["risk_score"],
        risk_level=triage_res["risk_level"],
        confidence_score=f"{triage_res['classification_score']:.1%}",
        indicator_details=triage_res["email_indicators"],
        ai_explanation=[
            {
                "finding": ind["category"],
                "evidence": ind["evidence"],
                "why_it_matters": ind["why_it_matters"],
                "recommended_action": "Verify through official organizational channels."
            }
            for ind in triage_res["email_indicators"]
        ],
        recommendations=triage_res["recommendations"],
        missing_evidence=["Raw mailserver DKIM/SPF cryptographic telemetry"],
        extracted_urls=[
            {
                "original_url": u["url"],
                "defanged_url": u["defanged_url"],
                "domain": u["url"].split("/")[2] if "://" in u["url"] else u["url"],
                "is_ip": False,
                "is_suspicious_tld": False,
                "is_shortener": False,
                "is_lookalike": False,
                "reasons": u["reasons"]
            }
            for u in triage_res["url_analysis_results"]
        ],
        attachment_names=[],
        is_synthetic=False,
        analyzed_by_user_id=current_user.id if current_user else None,
        created_at=datetime.datetime.now(datetime.timezone.utc)
    )
    db.add(analysis)
    db.flush()

    if request.create_incident:
        inc_id = generate_incident_id(db)
        incident = Incident(
            id=inc_id,
            title=analysis.subject,
            risk_score=analysis.risk_score,
            risk_level=analysis.risk_level,
            status="New",
            assigned_to_user_id=current_user.id if (current_user and current_user.role == "analyst") else None,
            analysis_id=analysis.id,
            is_sample=False,
            created_at=datetime.datetime.now(datetime.timezone.utc),
            updated_at=datetime.datetime.now(datetime.timezone.utc)
        )
        db.add(incident)
        db.flush()

    db.commit()
    db.refresh(analysis)

    triage_res["analysis_id"] = analysis.id
    triage_res["id"] = analysis.id
    triage_res["subject"] = clean_sub or "(No Subject)"
    triage_res["created_at"] = analysis.created_at.isoformat() if hasattr(analysis.created_at, "isoformat") else str(analysis.created_at)
    store_server_analysis(analysis.id, triage_res)

    return EmailAIAnalysisResponse(
        success=True,
        analysis_id=analysis.id,
        id=analysis.id,
        subject=clean_sub or "(No Subject)",
        model_name=triage_res["model_name"],
        inference_device=triage_res["inference_device"],
        model_label=triage_res["model_label"],
        prediction=triage_res["prediction"],
        classification=triage_res["prediction"],
        classification_score=triage_res["classification_score"],
        risk_score=triage_res["risk_score"],
        risk_level=triage_res["risk_level"],
        email_indicators=triage_res["email_indicators"],
        indicator_details=triage_res["email_indicators"],
        extracted_urls=triage_res["extracted_urls"],
        url_analysis_results=triage_res["url_analysis_results"],
        reasons=triage_res["reasons"],
        recommendations=triage_res["recommendations"],
        model_disclaimer=triage_res["model_disclaimer"],
        created_at=analysis.created_at.isoformat() if hasattr(analysis.created_at, "isoformat") else str(analysis.created_at),
        text_truncated=triage_res["text_truncated"]
    )

def process_and_persist_url_analysis(
    target_url: str,
    create_incident: bool,
    db: Session,
    current_user: Optional[User]
) -> Tuple[EmailAnalysis, Dict[str, Any]]:
    clean_url = target_url.strip()
    if not clean_url:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="URL cannot be empty")

    try:
        url_triage = analyze_url_comprehensive(clean_url)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))

    analysis_id = f"URL-{uuid.uuid4().hex[:8].upper()}"
    meta = {
        "classification": url_triage.get("classification", "Legitimate"),
        "prediction": url_triage.get("prediction", "Legitimate"),
        "is_spam": False,
        "highlighted_phrases": url_triage.get("highlighted_phrases", []),
        "analysis_type": "url",
        "features": url_triage.get("features", {})
    }

    defanged_repr = url_triage.get("defanged_url", clean_url)

    analysis = EmailAnalysis(
        id=analysis_id,
        subject=f"URL Triage: {defanged_repr}",
        sender="URL Static Inspector",
        reply_to=None,
        recipient=None,
        body_snippet=clean_url[:400],
        has_eml=False,
        raw_headers_summary=meta,
        urls_count=1,
        attachments_count=0,
        risk_score=url_triage["risk_score"],
        risk_level=url_triage["risk_level"],
        confidence_score=url_triage.get("confidence_score", "Moderate (75%)"),
        indicator_details=url_triage["indicators"],
        ai_explanation=url_triage["ai_explanation"],
        recommendations=url_triage["recommendations"],
        missing_evidence=url_triage["missing_evidence"],
        extracted_urls=url_triage["extracted_urls"],
        attachment_names=[],
        is_synthetic=False,
        analyzed_by_user_id=current_user.id if current_user else None,
        created_at=datetime.datetime.now(datetime.timezone.utc)
    )
    db.add(analysis)
    db.flush()

    if create_incident:
        inc_id = generate_incident_id(db)
        incident = Incident(
            id=inc_id,
            title=analysis.subject,
            risk_score=analysis.risk_score,
            risk_level=analysis.risk_level,
            status="New",
            assigned_to_user_id=current_user.id if (current_user and current_user.role == "analyst") else None,
            analysis_id=analysis.id,
            is_sample=False,
            created_at=datetime.datetime.now(datetime.timezone.utc),
            updated_at=datetime.datetime.now(datetime.timezone.utc)
        )
        db.add(incident)
        db.flush()

    db.commit()
    db.refresh(analysis)

    url_triage["analysis_id"] = analysis.id
    url_triage["id"] = analysis.id
    url_triage["created_at"] = analysis.created_at.isoformat() if hasattr(analysis.created_at, "isoformat") else str(analysis.created_at)
    store_server_analysis(analysis.id, url_triage)

    return analysis, url_triage


@router.post("/analyze-url", response_model=URLAnalysisResponse)
def analyze_url_endpoint(
    request: URLAnalyzeRequest,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user)
):
    """
    Dedicated URL Phishing Detection endpoint.
    Accepts JSON: {"url": "https://example.com"}
    Returns explainable triage result with features, indicators, risk level, reasons, and actions.
    """
    analysis, url_triage = process_and_persist_url_analysis(
        request.url, request.create_incident or False, db, current_user
    )
    return URLAnalysisResponse(
        success=True,
        analysis_id=analysis.id,
        id=analysis.id,
        url=request.url.strip(),
        defanged_url=url_triage["defanged_url"],
        prediction=url_triage["prediction"],
        classification=url_triage["prediction"],
        risk_score=url_triage["risk_score"],
        risk_level=url_triage["risk_level"],
        features=url_triage["features"],
        indicators=url_triage["indicators"],
        indicator_details=url_triage["indicators"],
        reasons=url_triage["reasons"],
        recommendations=url_triage["recommendations"],
        ai_explanation=url_triage["ai_explanation"],
        extracted_urls=url_triage["extracted_urls"],
        created_at=analysis.created_at.isoformat() if hasattr(analysis.created_at, "isoformat") else str(analysis.created_at)
    )


@router.post("/analyze/url", response_model=EmailAnalysisResponse)
def analyze_single_url_endpoint(
    request: URLAnalyzeRequest,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user)
):
    """Analyze a single target URL statically and safely without network execution."""
    analysis, url_triage = process_and_persist_url_analysis(
        request.url, request.create_incident or False, db, current_user
    )
    res = EmailAnalysisResponse.model_validate(analysis)
    res.classification = url_triage["prediction"]
    res.is_spam = False
    res.highlighted_phrases = url_triage.get("highlighted_phrases", [])
    res.analysis_type = "url"
    return res


@router.post("/analyze-qr", response_model=QRAnalysisResponse)
@router.post("/analyze/qr", response_model=QRAnalysisResponse)
async def analyze_qr_endpoint(
    file: UploadFile = File(...),
    create_incident: bool = Query(default=False),
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user)
):
    """
    Dedicated QR-Code URL Extraction and Threat Analysis endpoint.
    Accepts supported image upload (PNG, JPEG, WebP, etc.).
    Extracts QR content statically using OpenCV without opening or visiting URLs.
    Passes extracted URLs into comprehensive static URL phishing analysis.
    """
    if not file:
        raise HTTPException(
            status_code=getattr(status, "HTTP_422_UNPROCESSABLE_CONTENT", 422),
            detail="No image file provided."
        )

    file_bytes = await file.read()
    if not file_bytes:
        raise HTTPException(
            status_code=getattr(status, "HTTP_422_UNPROCESSABLE_CONTENT", 422),
            detail="Uploaded image file is empty."
        )

    # Decode and analyze QR image safely
    qr_triage = analyze_qr_image_bytes(
        file_bytes=file_bytes,
        filename=file.filename or "upload.png",
        content_type=file.content_type
    )

    analysis_id = qr_triage["analysis_id"]
    timestamp = datetime.datetime.now(datetime.timezone.utc)
    qr_triage["created_at"] = timestamp.isoformat()

    # Store authoritative server result for subsequent PDF generation & API lookups
    store_server_analysis(analysis_id, qr_triage)

    # Persist record in database for triage logs and incident creation
    if qr_triage.get("qr_detected"):
        defanged_title = qr_triage.get("defanged_content", "")[:60]
        meta = {
            "source_type": "qr_code_image",
            "classification": qr_triage.get("classification", "Legitimate"),
            "prediction": qr_triage.get("prediction", "Legitimate"),
            "is_spam": False,
            "analysis_type": "qr_code",
            "features": qr_triage.get("features", {})
        }
        db_record = EmailAnalysis(
            id=analysis_id,
            subject=f"QR Triage: {defanged_title}",
            sender="QR Optical Scanner",
            reply_to=None,
            recipient=None,
            body_snippet=qr_triage.get("decoded_content", "")[:400],
            has_eml=False,
            raw_headers_summary=meta,
            urls_count=1 if qr_triage.get("is_url") else 0,
            attachments_count=0,
            risk_score=qr_triage["risk_score"],
            risk_level=qr_triage["risk_level"],
            confidence_score="High (Optical Decoded)",
            indicator_details=qr_triage.get("indicators", []),
            ai_explanation=qr_triage.get("ai_explanation", []),
            recommendations=qr_triage.get("recommendations", []),
            missing_evidence=["Offline image analysis (no network connection made to destination)"],
            extracted_urls=qr_triage.get("extracted_urls", []),
            attachment_names=[],
            is_synthetic=False,
            analyzed_by_user_id=current_user.id if current_user else None,
            created_at=timestamp
        )
        db.add(db_record)
        db.flush()

        if create_incident and qr_triage.get("risk_score", 0) >= 25.0:
            inc_id = generate_incident_id(db)
            incident = Incident(
                id=inc_id,
                title=db_record.subject,
                risk_score=db_record.risk_score,
                risk_level=db_record.risk_level,
                status="New",
                assigned_to_user_id=current_user.id if (current_user and current_user.role == "analyst") else None,
                analysis_id=db_record.id,
                is_sample=False,
                created_at=timestamp,
                updated_at=timestamp
            )
            db.add(incident)
            db.flush()

        db.commit()

    return QRAnalysisResponse(**qr_triage)

@router.post("/analyze/upload", response_model=EmailAnalysisResponse)
async def analyze_uploaded_eml(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user)
):
    """Safely parse and analyze an uploaded .eml email file."""
    # Validate file extension
    filename = file.filename or "unknown.eml"
    if not (filename.lower().endswith(".eml") or filename.lower().endswith(".msg") or filename.lower().endswith(".txt")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid file format. Please upload a standard RFC 822 .eml file."
        )

    # Read bytes safely with size check
    contents = await file.read()
    if len(contents) > settings.MAX_UPLOAD_SIZE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Uploaded file exceeds maximum limit of {settings.MAX_UPLOAD_SIZE_BYTES // (1024*1024)} MB"
        )
    if len(contents) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty"
        )

    try:
        parsed = parse_eml_bytes(contents)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Could not parse email headers: {str(e)}"
        )

    analysis, triage_result = process_and_persist_analysis(
        parsed_email=parsed,
        db=db,
        current_user=current_user,
        has_eml=True,
        create_incident=True
    )

    linked_inc = db.query(Incident).filter(Incident.analysis_id == analysis.id).first()
    res = EmailAnalysisResponse.model_validate(analysis)
    res.classification = triage_result.get("classification", "Legitimate")
    res.is_spam = triage_result.get("is_spam", False)
    res.highlighted_phrases = triage_result.get("highlighted_phrases", [])
    res.analysis_type = "email"
    if linked_inc:
        res.incident_id = linked_inc.id
    return res

@router.get("/history", response_model=List[EmailAnalysisResponse])
def get_analysis_history(
    search: Optional[str] = Query(None, description="Search in subject or sender"),
    risk_level: Optional[str] = Query(None, description="Filter by risk level"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    """Retrieve history of completed analyses with filtering and pagination."""
    query = db.query(EmailAnalysis)
    if risk_level:
        query = query.filter(EmailAnalysis.risk_level == risk_level)
    if search:
        s = f"%{search}%"
        query = query.filter((EmailAnalysis.subject.ilike(s)) | (EmailAnalysis.sender.ilike(s)))

    analyses = query.order_by(EmailAnalysis.created_at.desc()).offset(offset).limit(limit).all()
    results = []
    for a in analyses:
        item = EmailAnalysisResponse.model_validate(a)
        meta = a.raw_headers_summary if isinstance(a.raw_headers_summary, dict) else {}
        item.classification = meta.get("classification") or determine_classification(a.risk_score, a.indicator_details or [])
        item.is_spam = meta.get("is_spam", item.classification == "Spam")
        item.highlighted_phrases = meta.get("highlighted_phrases", [])
        item.analysis_type = meta.get("analysis_type", "message")
        linked_inc = db.query(Incident).filter(Incident.analysis_id == a.id).first()
        if linked_inc:
            item.incident_id = linked_inc.id
        results.append(item)
    return results

@router.get("/analysis/{analysis_id}", response_model=EmailAnalysisResponse)
def get_single_analysis(
    analysis_id: str,
    db: Session = Depends(get_db)
):
    """Retrieve details of a single analysis by ID."""
    analysis = db.query(EmailAnalysis).filter(EmailAnalysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis not found")
    
    meta = analysis.raw_headers_summary if isinstance(analysis.raw_headers_summary, dict) else {}
    res = EmailAnalysisResponse.model_validate(analysis)
    res.classification = meta.get("classification") or determine_classification(analysis.risk_score, analysis.indicator_details or [])
    res.is_spam = meta.get("is_spam", res.classification == "Spam")
    res.highlighted_phrases = meta.get("highlighted_phrases", [])
    res.analysis_type = meta.get("analysis_type", "message")
    linked_inc = db.query(Incident).filter(Incident.analysis_id == analysis.id).first()
    if linked_inc:
        res.incident_id = linked_inc.id
    return res

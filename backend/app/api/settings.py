from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.database import get_db
from app.core.config import settings
from app.schemas.schemas import SettingsResponse, SettingsUpdate
from app.api.deps import require_admin_role, get_current_user
from app.models.models import EmailAnalysis

router = APIRouter(prefix="/settings", tags=["Settings"])

@router.get("", response_model=SettingsResponse)
def get_system_settings():
    """Retrieve system configuration, triage risk thresholds, and active AI engine status."""
    return SettingsResponse(
        project_name=settings.PROJECT_NAME,
        ai_provider=settings.AI_PROVIDER,
        has_openai_key=bool(settings.OPENAI_API_KEY),
        has_gemini_key=bool(settings.GEMINI_API_KEY),
        retain_full_body=settings.RETAIN_FULL_BODY,
        threshold_low_max=settings.THRESHOLD_LOW_MAX,
        threshold_med_max=settings.THRESHOLD_MED_MAX,
        threshold_high_max=settings.THRESHOLD_HIGH_MAX,
        threshold_critical_min=settings.THRESHOLD_CRITICAL_MIN
    )

@router.post("", response_model=SettingsResponse)
def update_system_settings(
    update: SettingsUpdate,
    current_admin=Depends(require_admin_role)
):
    """Update system triage thresholds and AI integration settings (Admin only)."""
    if update.ai_provider is not None:
        settings.AI_PROVIDER = update.ai_provider
    if update.openai_api_key is not None:
        settings.OPENAI_API_KEY = update.openai_api_key
    if update.gemini_api_key is not None:
        settings.GEMINI_API_KEY = update.gemini_api_key
    if update.retain_full_body is not None:
        settings.RETAIN_FULL_BODY = update.retain_full_body
    if update.threshold_low_max is not None:
        settings.THRESHOLD_LOW_MAX = update.threshold_low_max
    if update.threshold_med_max is not None:
        settings.THRESHOLD_MED_MAX = update.threshold_med_max
    if update.threshold_high_max is not None:
        settings.THRESHOLD_HIGH_MAX = update.threshold_high_max
        settings.THRESHOLD_CRITICAL_MIN = update.threshold_high_max + 1

    return SettingsResponse(
        project_name=settings.PROJECT_NAME,
        ai_provider=settings.AI_PROVIDER,
        has_openai_key=bool(settings.OPENAI_API_KEY),
        has_gemini_key=bool(settings.GEMINI_API_KEY),
        retain_full_body=settings.RETAIN_FULL_BODY,
        threshold_low_max=settings.THRESHOLD_LOW_MAX,
        threshold_med_max=settings.THRESHOLD_MED_MAX,
        threshold_high_max=settings.THRESHOLD_HIGH_MAX,
        threshold_critical_min=settings.THRESHOLD_CRITICAL_MIN
    )

@router.post("/purge-stored-bodies")
def purge_stored_email_bodies(
    db: Session = Depends(get_db),
    current_admin=Depends(require_admin_role)
):
    """Data retention enforcement: securely redacts message bodies across historical records."""
    analyses = db.query(EmailAnalysis).all()
    count = 0
    for a in analyses:
        if a.body_snippet and a.body_snippet != "[REDACTED FOR PRIVACY POLICY]":
            a.body_snippet = "[REDACTED FOR PRIVACY POLICY]"
            count += 1
    db.commit()
    return {"status": "success", "message": f"Successfully redacted body data for {count} historical email records."}

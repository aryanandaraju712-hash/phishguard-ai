import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.models import Incident, AnalystNote, StatusHistory, User, EmailAnalysis
from app.schemas.schemas import (
    IncidentResponse, IncidentUpdate, AnalystNoteCreate, AnalystNoteResponse, EmailAnalysisResponse
)
from app.api.deps import require_current_user, get_current_user

router = APIRouter(prefix="/incidents", tags=["Incidents"])

@router.get("", response_model=List[IncidentResponse])
def get_incidents(
    search: Optional[str] = Query(None, description="Search by title or ID"),
    risk_level: Optional[str] = Query(None, description="Filter by risk level"),
    incident_status: Optional[str] = Query(None, alias="status", description="Filter by status"),
    assigned_to: Optional[int] = Query(None, description="Filter by assigned user ID"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    """Retrieve all incidents with filtering, search, and pagination."""
    query = db.query(Incident)

    if risk_level:
        query = query.filter(Incident.risk_level == risk_level)
    if incident_status:
        query = query.filter(Incident.status == incident_status)
    if assigned_to:
        query = query.filter(Incident.assigned_to_user_id == assigned_to)
    if search:
        s = f"%{search}%"
        query = query.filter((Incident.title.ilike(s)) | (Incident.id.ilike(s)))

    incidents = query.order_by(Incident.updated_at.desc()).offset(offset).limit(limit).all()
    results = []
    for inc in incidents:
        resp = IncidentResponse.model_validate(inc)
        if inc.assigned_analyst:
            resp.assigned_analyst_name = inc.assigned_analyst.full_name
        if inc.analysis:
            resp.analysis = EmailAnalysisResponse.model_validate(inc.analysis)
        results.append(resp)
    return results

@router.get("/{incident_id}", response_model=IncidentResponse)
def get_incident_detail(
    incident_id: str,
    db: Session = Depends(get_db)
):
    """Retrieve full incident details including notes, history, and linked analysis."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Incident '{incident_id}' not found")
    
    resp = IncidentResponse.model_validate(incident)
    if incident.assigned_analyst:
        resp.assigned_analyst_name = incident.assigned_analyst.full_name
    if incident.analysis:
        resp.analysis = EmailAnalysisResponse.model_validate(incident.analysis)
    return resp

@router.patch("/{incident_id}", response_model=IncidentResponse)
def update_incident(
    incident_id: str,
    update_data: IncidentUpdate,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user)
):
    """Update incident status and/or assigned analyst with audit trail."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Incident '{incident_id}' not found")

    old_status = incident.status
    has_changes = False

    # Status update
    if update_data.status and update_data.status != incident.status:
        valid_statuses = ["New", "Investigating", "Escalated", "Resolved", "False Positive"]
        if update_data.status not in valid_statuses:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid status '{update_data.status}'. Must be one of: {', '.join(valid_statuses)}"
            )
        
        # Record history
        history = StatusHistory(
            incident_id=incident.id,
            user_id=current_user.id if current_user else None,
            user_name=current_user.full_name if current_user else "Security Analyst",
            old_status=old_status,
            new_status=update_data.status,
            comment=update_data.comment or f"Status changed from {old_status} to {update_data.status}",
            timestamp=datetime.datetime.utcnow()
        )
        db.add(history)
        incident.status = update_data.status
        has_changes = True

    # Reassignment
    if update_data.assigned_to_user_id is not None:
        if update_data.assigned_to_user_id == 0:
            incident.assigned_to_user_id = None
        else:
            target_user = db.query(User).filter(User.id == update_data.assigned_to_user_id).first()
            if not target_user:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target user not found")
            incident.assigned_to_user_id = target_user.id
        has_changes = True

    if has_changes:
        incident.updated_at = datetime.datetime.utcnow()
        db.commit()
        db.refresh(incident)

    resp = IncidentResponse.model_validate(incident)
    if incident.assigned_analyst:
        resp.assigned_analyst_name = incident.assigned_analyst.full_name
    if incident.analysis:
        resp.analysis = EmailAnalysisResponse.model_validate(incident.analysis)
    return resp

@router.post("/{incident_id}/notes", response_model=AnalystNoteResponse)
def add_incident_note(
    incident_id: str,
    note_in: AnalystNoteCreate,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user)
):
    """Add a security investigation note to an incident."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Incident '{incident_id}' not found")

    author_name = current_user.full_name if current_user else "Security Analyst"
    author_id = current_user.id if current_user else None

    note = AnalystNote(
        incident_id=incident.id,
        user_id=author_id,
        author_name=author_name,
        note_text=note_in.note_text.strip(),
        created_at=datetime.datetime.utcnow()
    )
    db.add(note)
    incident.updated_at = datetime.datetime.utcnow()
    db.commit()
    db.refresh(note)
    return note

import datetime
from typing import List, Dict, Any
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.database import get_db
from app.models.models import EmailAnalysis, Incident
from app.schemas.schemas import (
    DashboardStatsResponse, RiskDistribution, StatusOverview,
    DailyActivity, EmailAnalysisResponse
)

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])

@router.get("/stats", response_model=DashboardStatsResponse)
def get_dashboard_statistics(db: Session = Depends(get_db)):
    """Calculate and return live dashboard metrics from database."""
    total_analyzed = db.query(EmailAnalysis).count()

    # Risk level counts
    low_count = db.query(EmailAnalysis).filter(EmailAnalysis.risk_level == "Low").count()
    med_count = db.query(EmailAnalysis).filter(EmailAnalysis.risk_level == "Medium").count()
    high_count = db.query(EmailAnalysis).filter(EmailAnalysis.risk_level == "High").count()
    crit_count = db.query(EmailAnalysis).filter(EmailAnalysis.risk_level == "Critical").count()

    # Incident status counts
    new_inc = db.query(Incident).filter(Incident.status == "New").count()
    inv_inc = db.query(Incident).filter(Incident.status == "Investigating").count()
    esc_inc = db.query(Incident).filter(Incident.status == "Escalated").count()
    res_inc = db.query(Incident).filter(Incident.status == "Resolved").count()
    fp_inc = db.query(Incident).filter(Incident.status == "False Positive").count()

    # Average score
    avg_score_res = db.query(func.avg(EmailAnalysis.risk_score)).scalar()
    avg_score = round(float(avg_score_res or 0.0), 1)

    # Verdict counts based on real records
    all_analyses = db.query(EmailAnalysis).all()
    phishing_count = 0
    spam_count = 0
    suspicious_count = 0
    legitimate_count = 0

    for a in all_analyses:
        meta = a.raw_headers_summary if isinstance(a.raw_headers_summary, dict) else {}
        cls = meta.get("classification")
        if not cls:
            if a.risk_score >= 50 or a.risk_level in ["High", "Critical"]:
                cls = "Potential Phishing"
            elif a.risk_score >= 25 or a.risk_level == "Medium":
                cls = "Suspicious"
            else:
                cls = "Legitimate"

        if cls == "Potential Phishing":
            phishing_count += 1
        elif cls == "Spam":
            spam_count += 1
        elif cls == "Suspicious":
            suspicious_count += 1
        else:
            legitimate_count += 1

    # Daily activity for last 7 days
    today = datetime.datetime.utcnow().date()
    daily_stats = []
    for i in range(6, -1, -1):
        day = today - datetime.timedelta(days=i)
        day_start = datetime.datetime.combine(day, datetime.time.min)
        day_end = datetime.datetime.combine(day, datetime.time.max)

        day_count = db.query(EmailAnalysis).filter(
            EmailAnalysis.created_at >= day_start,
            EmailAnalysis.created_at <= day_end
        ).count()

        day_avg = db.query(func.avg(EmailAnalysis.risk_score)).filter(
            EmailAnalysis.created_at >= day_start,
            EmailAnalysis.created_at <= day_end
        ).scalar()

        daily_stats.append(DailyActivity(
            date=day.strftime("%b %d"),
            count=day_count,
            avg_score=round(float(day_avg or 0.0), 1)
        ))

    # Recent analyses
    recent = db.query(EmailAnalysis).order_by(EmailAnalysis.created_at.desc()).limit(10).all()
    recent_responses = []
    for r in recent:
        item = EmailAnalysisResponse.model_validate(r)
        meta = r.raw_headers_summary if isinstance(r.raw_headers_summary, dict) else {}
        item.classification = meta.get("classification") or ("Potential Phishing" if r.risk_score >= 50 else "Suspicious" if r.risk_score >= 25 else "Legitimate")
        item.is_spam = meta.get("is_spam", item.classification == "Spam")
        item.highlighted_phrases = meta.get("highlighted_phrases", [])
        item.analysis_type = meta.get("analysis_type", "message")
        linked_inc = db.query(Incident).filter(Incident.analysis_id == r.id).first()
        if linked_inc:
            item.incident_id = linked_inc.id
        recent_responses.append(item)

    return DashboardStatsResponse(
        total_emails_analyzed=total_analyzed,
        high_critical_count=high_count + crit_count,
        average_triage_score=avg_score,
        suspicious_count=suspicious_count,
        phishing_count=phishing_count,
        spam_count=spam_count,
        legitimate_count=legitimate_count,
        risk_distribution=RiskDistribution(
            low=low_count,
            medium=med_count,
            high=high_count,
            critical=crit_count
        ),
        status_overview=StatusOverview(
            new=new_inc,
            investigating=inv_inc,
            escalated=esc_inc,
            resolved=res_inc,
            false_positive=fp_inc
        ),
        daily_activity=daily_stats,
        recent_analyses=recent_responses
    )

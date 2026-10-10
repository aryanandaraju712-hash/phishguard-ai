import datetime
from sqlalchemy import (
    Column, Integer, String, Text, Boolean, Float, DateTime, ForeignKey, JSON
)
from sqlalchemy.orm import relationship, declarative_base

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=False)
    role = Column(String(50), default="analyst", nullable=False)  # "admin" or "analyst"
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    
    # Relationships
    analyses = relationship("EmailAnalysis", back_populates="analyzed_by")
    assigned_incidents = relationship("Incident", back_populates="assigned_analyst")
    notes = relationship("AnalystNote", back_populates="author")

class EmailAnalysis(Base):
    __tablename__ = "email_analyses"
    
    id = Column(String(64), primary_key=True, index=True)  # UUID or ANL-xxxx
    subject = Column(String(500), nullable=False, default="(No Subject)")
    sender = Column(String(500), nullable=False)
    reply_to = Column(String(500), nullable=True)
    recipient = Column(String(500), nullable=True)
    body_snippet = Column(Text, nullable=True)
    has_eml = Column(Boolean, default=False)
    raw_headers_summary = Column(JSON, nullable=True)
    urls_count = Column(Integer, default=0)
    attachments_count = Column(Integer, default=0)
    
    risk_score = Column(Float, nullable=False)
    risk_level = Column(String(50), nullable=False)  # "Low", "Medium", "High", "Critical"
    confidence_score = Column(String(50), default="Medium")
    
    # Structured indicators & explainability
    indicator_details = Column(JSON, default=list)
    ai_explanation = Column(JSON, default=list)
    recommendations = Column(JSON, default=list)
    missing_evidence = Column(JSON, default=list)
    extracted_urls = Column(JSON, default=list)
    attachment_names = Column(JSON, default=list)
    
    is_synthetic = Column(Boolean, default=False)
    analyzed_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    
    # Relationships
    analyzed_by = relationship("User", back_populates="analyses")
    incident = relationship("Incident", back_populates="analysis", uselist=False)

class Incident(Base):
    __tablename__ = "incidents"
    
    id = Column(String(64), primary_key=True, index=True)  # e.g. INC-2026-0001
    title = Column(String(500), nullable=False)
    risk_score = Column(Float, nullable=False)
    risk_level = Column(String(50), nullable=False)
    status = Column(String(50), default="New", nullable=False)  # New, Investigating, Escalated, Resolved, False Positive
    
    assigned_to_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    analysis_id = Column(String(64), ForeignKey("email_analyses.id"), nullable=True)
    is_sample = Column(Boolean, default=False)  # Clearly flags seeded demonstration incidents
    
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    
    # Relationships
    assigned_analyst = relationship("User", back_populates="assigned_incidents")
    analysis = relationship("EmailAnalysis", back_populates="incident")
    notes = relationship("AnalystNote", back_populates="incident", cascade="all, delete-orphan", order_by="desc(AnalystNote.created_at)")
    history = relationship("StatusHistory", back_populates="incident", cascade="all, delete-orphan", order_by="desc(StatusHistory.timestamp)")

class AnalystNote(Base):
    __tablename__ = "analyst_notes"
    
    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(String(64), ForeignKey("incidents.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    author_name = Column(String(255), nullable=False)
    note_text = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    
    # Relationships
    incident = relationship("Incident", back_populates="notes")
    author = relationship("User", back_populates="notes")

class StatusHistory(Base):
    __tablename__ = "status_history"
    
    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(String(64), ForeignKey("incidents.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    user_name = Column(String(255), default="System")
    old_status = Column(String(50), nullable=False)
    new_status = Column(String(50), nullable=False)
    comment = Column(String(500), nullable=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    
    # Relationships
    incident = relationship("Incident", back_populates="history")

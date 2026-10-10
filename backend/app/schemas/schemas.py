import datetime
from typing import List, Optional, Any, Dict
from pydantic import BaseModel, EmailStr, Field, ConfigDict

# User Schemas
class UserLogin(BaseModel):
    email: str
    password: str

class UserResponse(BaseModel):
    id: int
    email: str
    full_name: str
    role: str
    is_active: bool
    created_at: datetime.datetime

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse

class TokenData(BaseModel):
    email: Optional[str] = None
    role: Optional[str] = None

# Indicator Item
class IndicatorItem(BaseModel):
    category: str
    severity: str  # "Low", "Medium", "High", "Critical"
    weight: float
    description: str
    evidence: Optional[str] = None
    why_it_matters: Optional[str] = None

class AIExplanationItem(BaseModel):
    finding: str
    evidence: str
    why_it_matters: str
    recommended_action: str

# Email Analysis Input & Output
class EmailAnalyzeRequest(BaseModel):
    subject: str = Field(default="", description="Subject line of the email or message title")
    sender: Optional[str] = Field(default="unspecified-sender@external.mail", description="Sender from header or raw string")
    reply_to: Optional[str] = Field(default=None, description="Reply-to header if available")
    recipient: Optional[str] = Field(default=None, description="Target recipient if available")
    body: str = Field(default="", description="Email plain text, message, or HTML body")
    urls: Optional[List[str]] = Field(default=[], description="Explicitly extracted URLs")
    create_incident: Optional[bool] = Field(default=True, description="Automatically track as incident if suspicious")

class URLAnalyzeRequest(BaseModel):
    url: str = Field(..., description="Target URL to inspect statically")
    create_incident: Optional[bool] = Field(default=False, description="Automatically track as incident if suspicious")

class URLAnalysisResponse(BaseModel):
    success: bool = True
    analysis_id: str
    url: str
    defanged_url: Optional[str] = None
    prediction: str
    risk_score: float
    risk_level: str
    features: Dict[str, Any]
    indicators: Optional[List[Dict[str, Any]]] = None
    reasons: List[str]
    recommendations: List[str]
    created_at: Optional[str] = None

    # Optional compatibility fields for frontend & incident integration
    id: Optional[str] = None
    classification: Optional[str] = None
    indicator_details: Optional[List[Dict[str, Any]]] = None
    ai_explanation: Optional[List[Dict[str, Any]]] = None
    extracted_urls: Optional[List[Dict[str, Any]]] = None
    confidence_score: Optional[str] = None

class QRAnalysisResponse(BaseModel):
    success: bool = True
    analysis_id: str
    id: Optional[str] = None
    source_type: str = "qr_code_image"
    qr_detected: bool = True
    qr_count: int = 1
    decoded_content: str
    defanged_content: str
    all_decoded_texts: Optional[List[str]] = None
    is_url: bool = True
    url: Optional[str] = None
    defanged_url: Optional[str] = None
    prediction: str
    classification: Optional[str] = None
    risk_score: float
    risk_level: str
    features: Optional[Dict[str, Any]] = None
    indicators: Optional[List[Dict[str, Any]]] = None
    indicator_details: Optional[List[Dict[str, Any]]] = None
    reasons: List[str]
    recommendations: List[str]
    ai_explanation: Optional[List[Dict[str, Any]]] = None
    extracted_urls: Optional[List[Dict[str, Any]]] = None
    url_analysis: Optional[Dict[str, Any]] = None
    message: Optional[str] = None
    created_at: Optional[str] = None

class EmailAIAnalysisResponse(BaseModel):
    success: bool = True
    analysis_id: str
    subject: Optional[str] = ""
    model_name: str
    inference_device: str
    model_label: str
    prediction: str
    classification_score: float
    risk_score: float
    risk_level: str
    email_indicators: List[Dict[str, Any]]
    extracted_urls: List[str]
    url_analysis_results: List[Dict[str, Any]]
    reasons: List[str]
    recommendations: List[str]
    model_disclaimer: Optional[str] = None
    created_at: Optional[str] = None
    text_truncated: bool = False

    # Optional compatibility fields for frontend & incident integration
    id: Optional[str] = None
    classification: Optional[str] = None
    indicator_details: Optional[List[Dict[str, Any]]] = None

class ModelStatusResponse(BaseModel):
    model_id: str
    model_loaded: bool
    inference_device: str
    cuda_available: bool
    gpu_name: Optional[str] = None
    status: str
    error_message: Optional[str] = None

class HighlightedPhrase(BaseModel):
    phrase: str
    category: str
    explanation: str

class InspectedURL(BaseModel):
    original_url: str
    defanged_url: str
    domain: str
    is_ip: bool
    is_suspicious_tld: bool
    reasons: List[str]

class InspectedAttachment(BaseModel):
    filename: str
    extension: str
    is_dangerous: bool
    risk_reason: Optional[str] = None
    size_bytes: Optional[int] = None

class EmailAnalysisResponse(BaseModel):
    id: str
    subject: str
    sender: str
    reply_to: Optional[str]
    recipient: Optional[str]
    body_snippet: Optional[str]
    has_eml: bool
    urls_count: int
    attachments_count: int
    
    risk_score: float
    risk_level: str  # "Low", "Medium", "High", "Critical"
    confidence_score: str
    classification: Optional[str] = "Legitimate"  # "Legitimate", "Spam", "Suspicious", "Potential Phishing"
    is_spam: Optional[bool] = False
    analysis_type: Optional[str] = "message"  # "message", "email", "url"
    
    indicator_details: List[IndicatorItem]
    ai_explanation: List[AIExplanationItem]
    recommendations: List[str]
    missing_evidence: List[str]
    highlighted_phrases: Optional[List[Dict[str, Any]]] = []
    
    extracted_urls: List[InspectedURL]
    attachment_names: List[InspectedAttachment]
    
    incident_id: Optional[str] = None
    is_synthetic: bool = False
    created_at: datetime.datetime

    class Config:
        from_attributes = True

# Incident Schemas
class AnalystNoteCreate(BaseModel):
    note_text: str = Field(..., min_length=1, max_length=5000)

class AnalystNoteResponse(BaseModel):
    id: int
    incident_id: str
    user_id: Optional[int]
    author_name: str
    note_text: str
    created_at: datetime.datetime

    class Config:
        from_attributes = True

class StatusHistoryResponse(BaseModel):
    id: int
    incident_id: str
    user_name: str
    old_status: str
    new_status: str
    comment: Optional[str]
    timestamp: datetime.datetime

    class Config:
        from_attributes = True

class IncidentResponse(BaseModel):
    id: str
    title: str
    risk_score: float
    risk_level: str
    status: str
    assigned_to_user_id: Optional[int]
    assigned_analyst_name: Optional[str] = None
    analysis_id: Optional[str]
    is_sample: bool
    created_at: datetime.datetime
    updated_at: datetime.datetime
    analysis: Optional[EmailAnalysisResponse] = None
    notes: List[AnalystNoteResponse] = []
    history: List[StatusHistoryResponse] = []

    class Config:
        from_attributes = True

class IncidentUpdate(BaseModel):
    status: Optional[str] = None  # "New", "Investigating", "Escalated", "Resolved", "False Positive"
    assigned_to_user_id: Optional[int] = None
    comment: Optional[str] = None

# Dashboard Stats Schema
class RiskDistribution(BaseModel):
    low: int
    medium: int
    high: int
    critical: int

class StatusOverview(BaseModel):
    new: int
    investigating: int
    escalated: int
    resolved: int
    false_positive: int

class DailyActivity(BaseModel):
    date: str
    count: int
    avg_score: float

class DashboardStatsResponse(BaseModel):
    total_emails_analyzed: int
    high_critical_count: int
    average_triage_score: float
    suspicious_count: Optional[int] = 0
    phishing_count: Optional[int] = 0
    spam_count: Optional[int] = 0
    legitimate_count: Optional[int] = 0
    risk_distribution: RiskDistribution
    status_overview: StatusOverview
    daily_activity: List[DailyActivity]
    recent_analyses: List[EmailAnalysisResponse]

# Settings Schemas
class SettingsUpdate(BaseModel):
    ai_provider: Optional[str] = None
    openai_api_key: Optional[str] = None
    gemini_api_key: Optional[str] = None
    retain_full_body: Optional[bool] = None
    threshold_low_max: Optional[int] = None
    threshold_med_max: Optional[int] = None
    threshold_high_max: Optional[int] = None

class SettingsResponse(BaseModel):
    project_name: str
    ai_provider: str
    has_openai_key: bool
    has_gemini_key: bool
    retain_full_body: bool
    threshold_low_max: int
    threshold_med_max: int
    threshold_high_max: int
    threshold_critical_min: int


# PDF Report Request Schema
class ReportDownloadRequest(BaseModel):
    analysis_id: Optional[str] = None
    id: Optional[str] = None
    url: Optional[str] = None
    subject: Optional[str] = None
    risk_score: Optional[float] = None
    risk_level: Optional[str] = None
    prediction: Optional[str] = None
    classification: Optional[str] = None
    model_config = ConfigDict(extra="allow")

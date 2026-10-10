"""
Proxy module exposing Risk Engine from app.services.risk_engine
"""
from app.services.risk_engine import (
    RiskLevel,
    PredictionCategory,
    calculate_url_risk,
    calculate_email_risk
)

__all__ = [
    "RiskLevel",
    "PredictionCategory",
    "calculate_url_risk",
    "calculate_email_risk"
]

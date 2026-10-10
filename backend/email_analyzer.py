"""
Proxy module exposing email analyzer from app.services.email_analyzer
"""
from app.services.email_analyzer import (
    MODEL_IDENTIFIER,
    EmailSpamModelManager,
    model_manager,
    extract_embedded_urls,
    analyze_email_comprehensive
)

__all__ = [
    "MODEL_IDENTIFIER",
    "EmailSpamModelManager",
    "model_manager",
    "extract_embedded_urls",
    "analyze_email_comprehensive"
]

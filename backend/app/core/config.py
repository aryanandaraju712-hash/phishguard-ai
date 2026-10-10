import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "PhishGuard AI"
    API_V1_STR: str = "/api"
    SECRET_KEY: str = os.getenv("SECRET_KEY", "phishguard-ai-secret-key-super-secure-change-in-prod-2026")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours
    
    # SQLite Database URI
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./phishguard.db")
    
    # Maximum upload size for .eml files (default: 5 MB)
    MAX_UPLOAD_SIZE_BYTES: int = 5 * 1024 * 1024
    
    # Triage Risk Thresholds (Configurable: 0-24 Low, 25-49 Moderate, 50-74 High, 75-100 Critical)
    THRESHOLD_LOW_MAX: int = 24
    THRESHOLD_MED_MAX: int = 49
    THRESHOLD_HIGH_MAX: int = 74
    THRESHOLD_CRITICAL_MIN: int = 75
    
    # AI Integration Settings
    AI_PROVIDER: str = os.getenv("AI_PROVIDER", "local")  # "local", "openai", "gemini"
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    
    # Retention & Privacy
    RETAIN_FULL_BODY: bool = False  # Privacy default: do not retain complete raw bodies in long-term DB
    
    class Config:
        case_sensitive = True

settings = Settings()

from contextlib import asynccontextmanager
from fastapi import FastAPI, status
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.database import init_db
from app.api import auth, analysis, dashboard, incidents, reports, samples, settings as settings_api

from app.schemas.schemas import ModelStatusResponse

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize SQLite database and seed initial demo data
    init_db()
    # Initialize local AI email spam model
    try:
        from app.services.email_analyzer import model_manager
        model_manager.initialize()
    except Exception:
        pass
    yield

app = FastAPI(
    title="PhishGuard AI — AI-Powered Phishing Triage API",
    description="Explainable, heuristic & AI-augmented phishing triage platform for small organizations.",
    version="1.0.0",
    lifespan=lifespan
)

# CORS configuration for frontend development (Vite, Live Server, local file servers)
origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:5500",
    "http://127.0.0.1:5500",
    "http://localhost:8080",
    "http://127.0.0.1:8080",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:[0-9]+)?$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API routers
app.include_router(auth.router, prefix=settings.API_V1_STR)
app.include_router(analysis.router, prefix=settings.API_V1_STR)
app.include_router(dashboard.router, prefix=settings.API_V1_STR)
app.include_router(incidents.router, prefix=settings.API_V1_STR)
app.include_router(reports.router, prefix=settings.API_V1_STR)
app.include_router(samples.router, prefix=settings.API_V1_STR)
app.include_router(settings_api.router, prefix=settings.API_V1_STR)

@app.get("/api/health", status_code=status.HTTP_200_OK, tags=["Health"])
def health_check():
    """Health check endpoint to verify backend operational readiness."""
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "database": "sqlite_ready",
        "engine": "local_heuristics_active",
        "version": "1.0.0"
    }

@app.get("/api/model-status", response_model=ModelStatusResponse, tags=["Model"])
def model_status():
    """Returns current operational and hardware inference state of the local AI model."""
    from app.services.email_analyzer import model_manager
    if model_manager.device == "uninitialized":
        model_manager.initialize()
    status_str = "ready" if model_manager.is_loaded else ("fallback_active" if model_manager.device != "uninitialized" else "uninitialized")
    return {
        "model_id": model_manager.model_id,
        "model_loaded": model_manager.is_loaded,
        "inference_device": model_manager.device,
        "cuda_available": model_manager.cuda_available,
        "gpu_name": model_manager.gpu_name,
        "status": status_str,
        "error_message": model_manager.error_message
    }

@app.get("/", tags=["Root"])
def root():
    return {
        "message": "Welcome to PhishGuard AI API",
        "docs_url": "/docs",
        "health_check": "/api/health"
    }
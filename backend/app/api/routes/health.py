"""Health and Status Route for AI-NIDS."""
from datetime import datetime, timezone
from fastapi import APIRouter
from backend.app.capture.live_capture import LiveCaptureEngine
from backend.app.ml.model_registry import get_model_registry
from backend.app.schemas.api_schemas import HealthResponse

router = APIRouter(tags=["Health"])

# Singleton capture engine instance for the application
_capture_engine = LiveCaptureEngine()

def get_live_capture_engine() -> LiveCaptureEngine:
    return _capture_engine

@router.get("/health", response_model=HealthResponse)
async def check_health():
    registry = get_model_registry()
    engine = get_live_capture_engine()
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        active_model=registry.active_model_name,
        models_loaded=list(registry.models.keys()),
        capture_running=engine.is_running,
        active_interface=engine.interface,
        timestamp=datetime.now(timezone.utc).isoformat()
    )

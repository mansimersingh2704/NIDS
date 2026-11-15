"""
FastAPI Application Entry Point for AI-Powered Network Intrusion Detection System (AI-NIDS).
Provides RESTful APIs and WebSocket live feeds for SOC monitoring, ML inference,
PCAP processing, and historical security analytics.
"""

from contextlib import asynccontextmanager
import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.api.routes import (
    alerts,
    capture,
    dashboard,
    detections,
    health,
    interfaces,
    models,
    pcap,
    reports,
    ws,
)
from backend.app.core.config import settings
from backend.app.database.database import get_sync_db, init_db
from backend.app.database.models import DBAlert, DBNetworkFlow
from backend.app.detection.detection_engine import get_detection_engine
from backend.app.ml.model_registry import get_model_registry

logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("AI-NIDS")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup sequence
    logger.info("Initializing AI-NIDS Backend Service...")
    init_db()

    # Pre-load ML models
    registry = get_model_registry()
    logger.info(f"Loaded Machine Learning models: {list(registry.models.keys())}")
    logger.info(f"Active Champion Model: {registry.active_model_name}")

    # Synchronize in-memory engine counters with existing database records
    try:
        db = get_sync_db()
        engine = get_detection_engine()
        engine.total_flows_seen = db.query(DBNetworkFlow).count()
        engine.malicious_flows_count = db.query(DBNetworkFlow).filter(DBNetworkFlow.is_malicious == True).count()
        engine.benign_flows_count = engine.total_flows_seen - engine.malicious_flows_count
        engine.active_alerts_count = db.query(DBAlert).count()
        db.close()
        logger.info(f"Initialized database counters: {engine.total_flows_seen} flows, {engine.active_alerts_count} alerts.")
    except Exception as e:
        logger.warning(f"Could not sync initial database counts: {e}")

    yield

    # Shutdown sequence
    logger.info("Stopping active captures and shutting down AI-NIDS...")
    from backend.app.api.routes.health import get_live_capture_engine
    cap = get_live_capture_engine()
    if cap.is_running:
        cap.stop()

app = FastAPI(
    title="AI-Powered Network Intrusion Detection System (AI-NIDS)",
    description=(
        "Enterprise-grade passive Network Intrusion Detection System featuring directional flow analysis, "
        "machine learning classification (Random Forest & XGBoost), unsupervised anomaly scoring, "
        "live traffic capture, offline PCAP analysis, and real-time SOC alerting."
    ),
    version="1.0.0",
    lifespan=lifespan
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Permits local Vite dev server and production builds
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Routers
app.include_router(health.router, prefix="/api")
app.include_router(interfaces.router, prefix="/api")
app.include_router(capture.router, prefix="/api")
app.include_router(pcap.router, prefix="/api")
app.include_router(dashboard.router, prefix="/api")
app.include_router(alerts.router, prefix="/api")
app.include_router(detections.router, prefix="/api")
app.include_router(models.router, prefix="/api")
app.include_router(reports.router, prefix="/api")
app.include_router(ws.router, prefix="/api")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app.main:app", host=settings.HOST, port=settings.PORT, reload=True)

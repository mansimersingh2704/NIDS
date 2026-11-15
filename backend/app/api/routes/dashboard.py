"""Dashboard Analytics Routes for AI-NIDS."""
from typing import Any, Dict, List
from fastapi import APIRouter
from backend.app.detection.detection_engine import get_detection_engine
from backend.app.schemas.api_schemas import DashboardOverviewResponse

router = APIRouter(tags=["Dashboard"])

@router.get("/dashboard/overview", response_model=DashboardOverviewResponse)
async def get_overview():
    """Returns SOC dashboard overview KPIs, attack charts, and recent activity."""
    engine = get_detection_engine()
    return DashboardOverviewResponse(**engine.get_dashboard_overview())

@router.get("/dashboard/traffic")
async def get_traffic_history():
    """Returns time-series flow and volume data for traffic line charts."""
    engine = get_detection_engine()
    with engine._lock:
        return {"traffic": list(engine.traffic_history)}

@router.get("/dashboard/attacks")
async def get_attack_breakdown():
    """Returns attack category distribution and severity breakdown."""
    engine = get_detection_engine()
    with engine._lock:
        return {
            "attack_distribution": dict(engine.attack_counts),
            "malicious_total": engine.malicious_flows_count,
            "benign_total": engine.benign_flows_count
        }

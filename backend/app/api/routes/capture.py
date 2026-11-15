"""Live Passive Capture Control Routes for AI-NIDS."""
from fastapi import APIRouter, HTTPException, status
from backend.app.api.routes.health import get_live_capture_engine
from backend.app.detection.detection_engine import get_detection_engine
from backend.app.schemas.api_schemas import (
    CaptureControlResponse,
    CaptureStatusResponse,
    StartCaptureRequest,
)

router = APIRouter(tags=["Capture"])

@router.post("/capture/start", response_model=CaptureControlResponse)
async def start_capture(request: StartCaptureRequest):
    """
    Starts passive packet capture on the chosen interface.
    Strictly passive monitoring mode: never injects or blocks traffic.
    """
    capture_engine = get_live_capture_engine()
    detection_engine = get_detection_engine()

    # Wire detection callback
    def flow_callback(flow):
        detection_engine.process_directional_flow(flow, session_id="live-session")

    capture_engine.flow_callback = flow_callback
    res = capture_engine.start(interface=request.interface)

    if not res.get("success"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=res.get("message", "Failed to start capture.")
        )

    return CaptureControlResponse(
        success=True,
        message=res["message"],
        interface=res.get("interface"),
        started_at=res.get("started_at")
    )

@router.post("/capture/stop", response_model=CaptureControlResponse)
async def stop_capture():
    """Stops the active passive capture session and flushes pending flows."""
    capture_engine = get_live_capture_engine()
    res = capture_engine.stop()

    if not res.get("success"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=res.get("message", "Failed to stop capture.")
        )

    return CaptureControlResponse(
        success=True,
        message=res["message"],
        interface=res.get("interface"),
        duration_sec=res.get("duration_sec"),
        total_packets=res.get("total_packets"),
        total_flows=res.get("total_flows")
    )

@router.get("/capture/status", response_model=CaptureStatusResponse)
async def get_capture_status():
    """Returns current live monitoring status and packet statistics."""
    capture_engine = get_live_capture_engine()
    stats = capture_engine.get_stats()
    return CaptureStatusResponse(**stats)

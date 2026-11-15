"""Real-time WebSocket Live Feed Route for AI-NIDS."""
import asyncio
import json
import logging
from typing import Any, Dict, List
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from backend.app.detection.detection_engine import get_detection_engine

logger = logging.getLogger(__name__)
router = APIRouter(tags=["WebSocket"])

class WebSocketConnectionManager:
    """Manages active browser WebSocket connections for real-time traffic updates."""

    def __init__(self) -> None:
        self.active_connections: List[WebSocket] = []
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket client connected. Total clients: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(f"WebSocket client disconnected. Total clients: {len(self.active_connections)}")

    async def broadcast_json(self, message: Dict[str, Any]) -> None:
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.debug(f"Error sending to WebSocket client: {e}")
                self.disconnect(connection)

    def dispatch_from_thread(self, event_type: str, payload: Dict[str, Any]) -> None:
        """Invoked synchronously by DetectionEngine background threads."""
        if not self.active_connections:
            return

        message = {"type": event_type, "data": payload}
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.run_coroutine_threadsafe(self.broadcast_json(message), loop)
        except Exception as e:
            logger.debug(f"Could not dispatch websocket event: {e}")

ws_manager = WebSocketConnectionManager()

# Hook websocket dispatcher to detection engine
get_detection_engine().register_subscriber(ws_manager.dispatch_from_thread)

@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        # Send initial status
        engine = get_detection_engine()
        overview = engine.get_dashboard_overview()
        await websocket.send_json({"type": "init", "data": overview})

        while True:
            # Keep connection alive & handle incoming pings
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception as e:
        logger.debug(f"WebSocket error: {e}")
        ws_manager.disconnect(websocket)

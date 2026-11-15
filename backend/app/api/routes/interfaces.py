"""Network Interfaces Route for AI-NIDS."""
from typing import List
from fastapi import APIRouter
from backend.app.capture.live_capture import list_network_interfaces
from backend.app.schemas.api_schemas import InterfaceInfo

router = APIRouter(tags=["Interfaces"])

@router.get("/interfaces", response_model=List[InterfaceInfo])
async def get_interfaces():
    """Lists available network capture interfaces on the host system."""
    raw_interfaces = list_network_interfaces()
    return [InterfaceInfo(**iface) for iface in raw_interfaces]

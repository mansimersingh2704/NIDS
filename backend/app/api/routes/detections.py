"""Detections and Flow History Routes for AI-NIDS."""
from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from backend.app.database.database import get_async_db
from backend.app.database.models import DBNetworkFlow
from backend.app.schemas.api_schemas import DetectionsListResponse, FlowItemResponse

router = APIRouter(tags=["Detections"])

@router.get("/detections", response_model=DetectionsListResponse)
async def list_detections(
    page: int = Query(1, ge=1),
    limit: int = Query(25, ge=1, le=100),
    is_malicious: Optional[bool] = Query(None),
    predicted_class: Optional[str] = Query(None),
    ip: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_async_db)
):
    """Retrieves paginated detection history from the database."""
    query = select(DBNetworkFlow)

    if is_malicious is not None:
        query = query.filter(DBNetworkFlow.is_malicious == is_malicious)
    if predicted_class:
        query = query.filter(DBNetworkFlow.predicted_class.ilike(predicted_class))
    if ip:
        query = query.filter((DBNetworkFlow.src_ip.contains(ip)) | (DBNetworkFlow.dst_ip.contains(ip)))

    query = query.order_by(desc(DBNetworkFlow.timestamp))

    result = await db.execute(query)
    all_rows = result.scalars().all()
    total = len(all_rows)

    offset = (page - 1) * limit
    paginated_rows = all_rows[offset : offset + limit]

    flow_items = []
    for r in paginated_rows:
        proto_str = "TCP" if r.protocol == 6 else ("UDP" if r.protocol == 17 else ("ICMP" if r.protocol == 1 else f"P-{r.protocol}"))
        flow_items.append(
            FlowItemResponse(
                id=r.id,
                flow_id=r.flow_id,
                timestamp=r.timestamp.isoformat() if r.timestamp else None,
                src_ip=r.src_ip,
                dst_ip=r.dst_ip,
                src_port=r.src_port,
                dst_port=r.dst_port,
                protocol=r.protocol,
                protocol_name=proto_str,
                duration_sec=r.duration_sec,
                total_packets=r.total_packets,
                total_bytes=r.total_bytes,
                predicted_class=r.predicted_class,
                threat_category=r.predicted_class if r.is_malicious else "None",
                is_malicious=r.is_malicious,
                confidence=r.confidence,
                risk_level=r.risk_level,
                session_id=r.session_id
            )
        )

    return DetectionsListResponse(
        total=total,
        page=page,
        limit=limit,
        detections=flow_items
    )

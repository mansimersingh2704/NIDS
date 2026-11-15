"""Alert Management Routes for AI-NIDS."""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import desc
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from backend.app.database.database import get_async_db
from backend.app.database.models import DBAlert
from backend.app.schemas.api_schemas import AlertDetailResponse, AlertsListResponse

router = APIRouter(tags=["Alerts"])

@router.get("/alerts", response_model=AlertsListResponse)
async def list_alerts(
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(20, ge=1, le=100, description="Items per page"),
    severity: Optional[str] = Query(None, description="Filter by severity: Low, Medium, High, Critical"),
    attack_type: Optional[str] = Query(None, description="Filter by attack category"),
    ip: Optional[str] = Query(None, description="Filter by source or destination IP"),
    db: AsyncSession = Depends(get_async_db)
):
    """Retrieves paginated alerts with optional severity and IP search filters."""
    query = select(DBAlert)

    if severity:
        query = query.filter(DBAlert.severity.ilike(severity))
    if attack_type:
        query = query.filter(DBAlert.attack_type.ilike(f"%{attack_type}%"))
    if ip:
        query = query.filter((DBAlert.source_ip.contains(ip)) | (DBAlert.destination_ip.contains(ip)))

    # Order by newest first
    query = query.order_by(desc(DBAlert.timestamp))

    # Total count
    result = await db.execute(query)
    all_rows = result.scalars().all()
    total = len(all_rows)

    # Paginate
    offset = (page - 1) * limit
    paginated_rows = all_rows[offset : offset + limit]

    alert_responses = [AlertDetailResponse(**row.to_dict()) for row in paginated_rows]

    return AlertsListResponse(
        total=total,
        page=page,
        limit=limit,
        alerts=alert_responses
    )

@router.get("/alerts/{alert_id}", response_model=AlertDetailResponse)
async def get_alert(alert_id: str, db: AsyncSession = Depends(get_async_db)):
    """Fetches full alert forensic evidence and network flow metadata by alert ID."""
    result = await db.execute(select(DBAlert).filter(DBAlert.alert_id == alert_id))
    alert = result.scalar_one_or_none()

    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert '{alert_id}' not found."
        )

    return AlertDetailResponse(**alert.to_dict())

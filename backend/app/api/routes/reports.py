"""Security Reporting and Export Routes for AI-NIDS."""
import csv
import io
from typing import Optional
from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import desc
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from backend.app.database.database import get_async_db
from backend.app.database.models import DBAlert, DBNetworkFlow
from backend.app.detection.detection_engine import get_detection_engine

router = APIRouter(tags=["Reports"])

@router.get("/reports/summary")
async def get_report_summary():
    """Generates an executive SOC detection and traffic report summary."""
    engine = get_detection_engine()
    overview = engine.get_dashboard_overview()

    total_flows = overview["total_flows"]
    malicious = overview["malicious_count"]
    benign = overview["benign_count"]
    detection_rate = overview["detection_rate_pct"]

    return {
        "report_title": "AI-NIDS Security Operations Executive Report",
        "timestamp": overview.get("recent_detections", [{}])[0].get("timestamp"),
        "traffic_summary": {
            "total_packets": overview["total_packets"],
            "total_flows": total_flows,
            "benign_flows": benign,
            "malicious_flows": malicious,
            "active_alerts": overview["active_alerts"],
            "threat_detection_rate_pct": detection_rate,
        },
        "attack_breakdown": overview["attack_distribution"],
        "protocol_breakdown": overview["protocol_distribution"]
    }

@router.get("/reports/export")
async def export_csv_report(
    export_type: str = Query("flows", pattern="^(flows|alerts)$", description="Type of data to export ('flows' or 'alerts')"),
    db: AsyncSession = Depends(get_async_db)
):
    """Exports structured detection or alert logs as a downloadable CSV report."""
    output = io.StringIO()
    writer = csv.writer(output)

    if export_type == "alerts":
        writer.writerow([
            "Alert ID", "Timestamp", "Source IP", "Destination IP",
            "Source Port", "Destination Port", "Protocol", "Attack Type",
            "Severity", "Confidence", "Occurrences", "Model"
        ])
        result = await db.execute(select(DBAlert).order_by(desc(DBAlert.timestamp)))
        alerts = result.scalars().all()
        for a in alerts:
            writer.writerow([
                a.alert_id,
                a.timestamp.isoformat() if a.timestamp else "",
                a.source_ip,
                a.destination_ip,
                a.source_port,
                a.destination_port,
                a.protocol,
                a.attack_type,
                a.severity,
                f"{a.confidence:.4f}",
                a.occurrence_count,
                a.model_name
            ])
        filename = "nids_security_alerts.csv"

    else:
        writer.writerow([
            "Flow ID", "Timestamp", "Source IP", "Destination IP",
            "Source Port", "Destination Port", "Protocol", "Duration (s)",
            "Packets", "Bytes", "Predicted Class", "Is Malicious",
            "Confidence", "Risk Level", "Session ID"
        ])
        result = await db.execute(select(DBNetworkFlow).order_by(desc(DBNetworkFlow.timestamp)).limit(5000))
        flows = result.scalars().all()
        for f in flows:
            writer.writerow([
                f.flow_id,
                f.timestamp.isoformat() if f.timestamp else "",
                f.src_ip,
                f.dst_ip,
                f.src_port,
                f.dst_port,
                f.protocol,
                f"{f.duration_sec:.4f}",
                f.total_packets,
                f.total_bytes,
                f.predicted_class,
                "YES" if f.is_malicious else "NO",
                f"{f.confidence:.4f}",
                f.risk_level,
                f.session_id or ""
            ])
        filename = "nids_flow_detections.csv"

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

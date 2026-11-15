"""
SQLAlchemy ORM Database Models for AI-NIDS.
Stores alerts, network flows, sessions, and detection history.
"""

from datetime import datetime, timezone
import json
from typing import Any, Dict
from sqlalchemy import Boolean, Column, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import declarative_base

Base = declarative_base()

class DBAlert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    alert_id = Column(String(64), unique=True, index=True, nullable=False)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    source_ip = Column(String(64), index=True, nullable=False)
    destination_ip = Column(String(64), index=True, nullable=False)
    source_port = Column(Integer, nullable=False)
    destination_port = Column(Integer, nullable=False)
    protocol = Column(Integer, nullable=False)
    attack_type = Column(String(64), index=True, nullable=False)
    severity = Column(String(32), index=True, nullable=False)  # Low, Medium, High, Critical
    confidence = Column(Float, nullable=False)
    anomaly_score = Column(Float, default=0.0)
    model_name = Column(String(64), default="random_forest")
    occurrence_count = Column(Integer, default=1)
    evidence_json = Column(Text, nullable=True)  # Detailed flow features as JSON string

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "alert_id": self.alert_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "attack_type": self.attack_type,
            "severity": self.severity,
            "confidence": self.confidence,
            "anomaly_score": self.anomaly_score,
            "model_name": self.model_name,
            "occurrence_count": self.occurrence_count,
            "evidence": json.loads(self.evidence_json) if self.evidence_json else {}
        }

class DBNetworkFlow(Base):
    __tablename__ = "network_flows"

    id = Column(Integer, primary_key=True, autoincrement=True)
    flow_id = Column(String(64), index=True, nullable=False)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    src_ip = Column(String(64), index=True, nullable=False)
    dst_ip = Column(String(64), index=True, nullable=False)
    src_port = Column(Integer, nullable=False)
    dst_port = Column(Integer, nullable=False)
    protocol = Column(Integer, nullable=False)
    duration_sec = Column(Float, nullable=False)
    total_packets = Column(Integer, nullable=False)
    total_bytes = Column(Integer, nullable=False)
    predicted_class = Column(String(64), index=True, nullable=False)
    is_malicious = Column(Boolean, index=True, nullable=False)
    confidence = Column(Float, nullable=False)
    risk_level = Column(String(32), nullable=False)
    session_id = Column(String(64), index=True, nullable=True)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "flow_id": self.flow_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "duration_sec": self.duration_sec,
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "predicted_class": self.predicted_class,
            "is_malicious": self.is_malicious,
            "confidence": self.confidence,
            "risk_level": self.risk_level,
            "session_id": self.session_id
        }

class DBCaptureSession(Base):
    __tablename__ = "capture_sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(64), unique=True, index=True, nullable=False)
    mode = Column(String(32), nullable=False)  # "live" or "pcap"
    source = Column(String(256), nullable=False)  # Interface name or PCAP filename
    start_time = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    end_time = Column(DateTime, nullable=True)
    total_packets = Column(Integer, default=0)
    total_flows = Column(Integer, default=0)
    benign_count = Column(Integer, default=0)
    malicious_count = Column(Integer, default=0)
    status = Column(String(32), default="active")  # "active", "completed", "failed"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "mode": self.mode,
            "source": self.source,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "total_packets": self.total_packets,
            "total_flows": self.total_flows,
            "benign_count": self.benign_count,
            "malicious_count": self.malicious_count,
            "status": self.status
        }

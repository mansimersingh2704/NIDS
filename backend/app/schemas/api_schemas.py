"""
Pydantic API Request/Response Schemas for AI-NIDS.
Provides robust input validation, data modeling, and documentation.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

class HealthResponse(BaseModel):
    status: str
    version: str
    active_model: str
    models_loaded: List[str]
    capture_running: bool
    active_interface: Optional[str]
    timestamp: str

class InterfaceInfo(BaseModel):
    id: str
    name: str
    is_default: bool
    is_loopback: bool
    status: str

class StartCaptureRequest(BaseModel):
    interface: Optional[str] = Field(None, description="Network interface name. Defaults to system primary interface.")

class CaptureControlResponse(BaseModel):
    success: bool
    message: str
    interface: Optional[str] = None
    started_at: Optional[str] = None
    duration_sec: Optional[float] = None
    total_packets: Optional[int] = None
    total_flows: Optional[int] = None

class CaptureStatusResponse(BaseModel):
    is_running: bool
    interface: Optional[str]
    uptime_seconds: float
    packets_captured: int
    active_flows: int
    completed_flows: int
    packets_per_sec: float

class AlertDetailResponse(BaseModel):
    id: int
    alert_id: str
    timestamp: Optional[str]
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: int
    attack_type: str
    severity: str
    confidence: float
    anomaly_score: float
    model_name: str
    occurrence_count: int
    evidence: Dict[str, Any]

class AlertsListResponse(BaseModel):
    total: int
    page: int
    limit: int
    alerts: List[AlertDetailResponse]

class FlowItemResponse(BaseModel):
    id: Optional[int] = None
    flow_id: str
    timestamp: Optional[str]
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    protocol_name: Optional[str] = None
    duration_sec: float
    total_packets: int
    total_bytes: int
    predicted_class: str
    threat_category: Optional[str] = None
    is_malicious: bool
    confidence: float
    risk_level: str
    session_id: Optional[str] = None

class DetectionsListResponse(BaseModel):
    total: int
    page: int
    limit: int
    detections: List[FlowItemResponse]

class DashboardOverviewResponse(BaseModel):
    total_packets: int
    total_flows: int
    benign_count: int
    malicious_count: int
    active_alerts: int
    detection_rate_pct: float
    attack_distribution: Dict[str, int]
    protocol_distribution: Dict[str, int]
    recent_detections: List[Dict[str, Any]]
    traffic_history: List[Dict[str, Any]]

class ModelInfoResponse(BaseModel):
    active_model: str
    available_models: List[str]
    dataset: str
    total_training_samples: int
    features_count: int
    classes: List[str]
    metadata: Dict[str, Any]

class SwitchModelRequest(BaseModel):
    model_name: str = Field(..., description="Name of the model to activate ('random_forest' or 'xgboost')")

class AnalyzePcapRequest(BaseModel):
    filename: str = Field(..., description="Uploaded PCAP filename in server storage")
    max_packets: Optional[int] = Field(None, description="Optional packet limit")

class PcapAnalysisResponse(BaseModel):
    success: bool
    filename: str
    packets_count: int
    flows_count: int
    benign_count: int
    malicious_count: int
    attacks_detected: Dict[str, int]
    processing_time_sec: float
    alerts_generated: int
    detections: List[FlowItemResponse]

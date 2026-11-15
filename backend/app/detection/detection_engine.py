"""
Modular Detection Engine for AI-NIDS.
Integrates Directional Flows, Machine Learning Inference,
Database Persistence, Alert Deduplication, and Real-time Broadcasting.
Optimized for high-throughput batching and sub-millisecond per-flow processing.
"""

from collections import deque
from datetime import datetime, timezone
import json
import logging
import threading
import time
import uuid
from typing import Any, Callable, Deque, Dict, List, Optional
from sqlalchemy.orm import Session

from backend.app.database.database import get_sync_db
from backend.app.database.models import DBAlert, DBNetworkFlow
from backend.app.detection.alert_manager import AlertManager
from backend.app.flow.flow_features import DirectionalFlow
from backend.app.ml.predict import predict_flow

logger = logging.getLogger(__name__)

class DetectionEngine:
    """Central orchestrator for traffic classification and threat alerting."""

    _instance: Optional["DetectionEngine"] = None

    def __new__(cls) -> "DetectionEngine":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self) -> None:
        if getattr(self, "_initialized", False):
            return

        self.alert_manager = AlertManager(deduplication_window_sec=30.0)
        self.subscribers: List[Callable[[str, Dict[str, Any]], None]] = []
        self._lock = threading.Lock()

        # In-memory rolling statistics for instant dashboard responses
        self.total_packets_seen: int = 0
        self.total_flows_seen: int = 0
        self.benign_flows_count: int = 0
        self.malicious_flows_count: int = 0
        self.active_alerts_count: int = 0

        self.attack_counts: Dict[str, int] = {}
        self.protocol_counts: Dict[str, int] = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}

        # Rolling window of recent detections (last 200)
        self.recent_detections: Deque[Dict[str, Any]] = deque(maxlen=200)
        # Rolling traffic history by minute
        self.traffic_history: Deque[Dict[str, Any]] = deque(maxlen=60)

        self._initialized = True

    def register_subscriber(self, callback: Callable[[str, Dict[str, Any]], None]) -> None:
        """Subscribes a WebSocket or listener callback to live events."""
        with self._lock:
            if callback not in self.subscribers:
                self.subscribers.append(callback)

    def unregister_subscriber(self, callback: Callable[[str, Dict[str, Any]], None]) -> None:
        with self._lock:
            if callback in self.subscribers:
                self.subscribers.remove(callback)

    def _broadcast(self, event_type: str, payload: Dict[str, Any]) -> None:
        """Dispatches an event to all connected WebSocket subscribers."""
        with self._lock:
            callbacks = list(self.subscribers)

        for cb in callbacks:
            try:
                cb(event_type, payload)
            except Exception as e:
                logger.debug(f"Broadcast delivery error: {e}")

    def process_directional_flow(
        self,
        flow: DirectionalFlow,
        session_id: Optional[str] = None,
        db_session: Optional[Session] = None
    ) -> Dict[str, Any]:
        """Processes a single directional flow."""
        results = self.process_flow_batch([flow], session_id=session_id, db_session=db_session)
        return results[0] if results else {}

    def process_flow_batch(
        self,
        flows: List[DirectionalFlow],
        session_id: Optional[str] = None,
        db_session: Optional[Session] = None
    ) -> List[Dict[str, Any]]:
        """
        Processes a batch of flows with high-throughput database batch insertion.
        """
        if not flows:
            return []

        results = []
        db_flow_records = []
        alerts_to_broadcast = []

        own_db = False
        db = db_session
        if db is None:
            db = get_sync_db()
            own_db = True

        try:
            for flow in flows:
                features = flow.to_features()
                metadata = features.get("_metadata", {})
                prediction = predict_flow(features)

                is_malicious = prediction["is_malicious"]
                predicted_class = prediction["predicted_class"]
                risk_level = prediction["risk_level"]
                confidence = prediction["confidence_score"]

                proto_num = metadata.get("protocol", 0)
                if proto_num == 6:
                    proto_str = "TCP"
                elif proto_num == 17:
                    proto_str = "UDP"
                elif proto_num == 1:
                    proto_str = "ICMP"
                else:
                    proto_str = f"Proto-{proto_num}"

                flow_uuid = f"FLW-{uuid.uuid4().hex[:12].upper()}"
                flow_record = {
                    "flow_id": flow_uuid,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "src_ip": metadata.get("src_ip", "0.0.0.0"),
                    "dst_ip": metadata.get("dst_ip", "0.0.0.0"),
                    "src_port": metadata.get("src_port", 0),
                    "dst_port": metadata.get("dst_port", 0),
                    "protocol": proto_num,
                    "protocol_name": proto_str,
                    "duration_sec": metadata.get("duration_sec", 0.0),
                    "total_packets": flow.total_packets,
                    "total_bytes": flow.total_bytes,
                    "predicted_class": predicted_class,
                    "threat_category": prediction.get("threat_category", "None"),
                    "is_malicious": is_malicious,
                    "confidence": confidence,
                    "risk_level": risk_level,
                    "is_anomaly": prediction.get("is_anomaly", False),
                    "anomaly_score": prediction.get("anomaly_score", 0.0),
                    "session_id": session_id,
                    "features": {k: v for k, v in features.items() if not k.startswith("_")}
                }

                db_flow = DBNetworkFlow(
                    flow_id=flow_uuid,
                    timestamp=datetime.now(timezone.utc),
                    src_ip=flow_record["src_ip"],
                    dst_ip=flow_record["dst_ip"],
                    src_port=flow_record["src_port"],
                    dst_port=flow_record["dst_port"],
                    protocol=proto_num,
                    duration_sec=flow_record["duration_sec"],
                    total_packets=flow.total_packets,
                    total_bytes=flow.total_bytes,
                    predicted_class=predicted_class,
                    is_malicious=is_malicious,
                    confidence=confidence,
                    risk_level=risk_level,
                    session_id=session_id
                )
                db_flow_records.append(db_flow)

                # Alerting
                alert_dict = None
                if is_malicious or risk_level in ("Medium", "High", "Critical"):
                    alert_dict = self.alert_manager.process_detection(
                        db=db,
                        detection_result=prediction,
                        flow_features=features
                    )
                    if alert_dict:
                        self.active_alerts_count += 1
                        alerts_to_broadcast.append(alert_dict)

                res_item = {
                    "flow": flow_record,
                    "prediction": prediction,
                    "alert": alert_dict
                }
                results.append(res_item)

                # Update in-memory stats
                with self._lock:
                    self.total_packets_seen += flow.total_packets
                    self.total_flows_seen += 1
                    if is_malicious:
                        self.malicious_flows_count += 1
                        cat = prediction.get("threat_category", "Unknown")
                        self.attack_counts[cat] = self.attack_counts.get(cat, 0) + 1
                    else:
                        self.benign_flows_count += 1

                    if proto_str in self.protocol_counts:
                        self.protocol_counts[proto_str] += 1
                    else:
                        self.protocol_counts["Other"] += 1

                    self.recent_detections.appendleft(flow_record)
                    self._update_traffic_timeline(flow.total_bytes, is_malicious)

            # Bulk commit all flow records
            db.bulk_save_objects(db_flow_records)
            db.commit()

        except Exception as e:
            logger.error(f"Error persisting flow batch: {e}")
            if db:
                db.rollback()
        finally:
            if own_db and db:
                db.close()

        # Broadcast events
        for alert in alerts_to_broadcast:
            self._broadcast("alert", alert)

        for item in results:
            self._broadcast("flow", item["flow"])

        return results

    def _update_traffic_timeline(self, bytes_count: int, is_malicious: bool) -> None:
        """Aggregates traffic stats into one-minute time buckets."""
        current_minute = datetime.now(timezone.utc).strftime("%H:%M")
        if self.traffic_history and self.traffic_history[-1]["time"] == current_minute:
            bucket = self.traffic_history[-1]
            bucket["total_flows"] += 1
            bucket["total_bytes"] += bytes_count
            if is_malicious:
                bucket["malicious_flows"] += 1
            else:
                bucket["benign_flows"] += 1
        else:
            self.traffic_history.append({
                "time": current_minute,
                "total_flows": 1,
                "benign_flows": 0 if is_malicious else 1,
                "malicious_flows": 1 if is_malicious else 0,
                "total_bytes": bytes_count
            })

    def get_dashboard_overview(self) -> Dict[str, Any]:
        """Provides instant high-level SOC statistics."""
        with self._lock:
            total_flows = max(self.total_flows_seen, 0)
            det_rate = (self.malicious_flows_count / total_flows * 100.0) if total_flows > 0 else 0.0

            return {
                "total_packets": self.total_packets_seen,
                "total_flows": self.total_flows_seen,
                "benign_count": self.benign_flows_count,
                "malicious_count": self.malicious_flows_count,
                "active_alerts": self.active_alerts_count,
                "detection_rate_pct": round(det_rate, 2),
                "attack_distribution": dict(self.attack_counts),
                "protocol_distribution": dict(self.protocol_counts),
                "recent_detections": list(self.recent_detections)[:15],
                "traffic_history": list(self.traffic_history)
            }

def get_detection_engine() -> DetectionEngine:
    return DetectionEngine()

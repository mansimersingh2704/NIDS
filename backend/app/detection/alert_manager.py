"""
Alert Management and Deduplication Engine for AI-NIDS.
Prevents alert flooding by deduplicating repeated attack signatures
within a sliding temporal window while updating counters and evidence.
"""

from datetime import datetime, timezone
import json
import logging
import threading
import time
import uuid
from typing import Any, Dict, Optional, Tuple
from sqlalchemy.orm import Session

from backend.app.database.models import DBAlert

logger = logging.getLogger(__name__)

class AlertManager:
    """Manages alert deduplication, risk classification, and database storage."""

    def __init__(self, deduplication_window_sec: float = 30.0) -> None:
        self.deduplication_window_sec = deduplication_window_sec
        # Map: (src_ip, dst_ip, attack_type) -> (alert_db_id, last_timestamp, occurrence_count)
        self._recent_alerts: Dict[Tuple[str, str, str], Tuple[str, float, int]] = {}
        self._lock = threading.Lock()

    def process_detection(
        self,
        db: Session,
        detection_result: Dict[str, Any],
        flow_features: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Creates or deduplicates an alert if the flow is classified as malicious or anomalous.
        """
        is_malicious = detection_result.get("is_malicious", False)
        risk_level = detection_result.get("risk_level", "Low")

        # Only generate alerts for non-trivial threats
        if not is_malicious and risk_level == "Low":
            return None

        metadata = flow_features.get("_metadata", {})
        src_ip = metadata.get("src_ip", "0.0.0.0")
        dst_ip = metadata.get("dst_ip", "0.0.0.0")
        src_port = int(metadata.get("src_port", 0))
        dst_port = int(metadata.get("dst_port", flow_features.get("destination_port", 0)))
        protocol = int(metadata.get("protocol", 0))

        attack_type = detection_result.get("threat_category", "Unknown")
        confidence = float(detection_result.get("confidence_score", 0.0))
        anomaly_score = float(detection_result.get("anomaly_score", 0.0))
        model_name = detection_result.get("model_used", "random_forest")

        now = time.time()
        dedup_key = (src_ip, dst_ip, attack_type)

        with self._lock:
            # Check for existing active alert in deduplication window
            if dedup_key in self._recent_alerts:
                existing_alert_id, last_time, count = self._recent_alerts[dedup_key]
                if (now - last_time) <= self.deduplication_window_sec:
                    # Update existing alert occurrence count in database
                    db_alert = db.query(DBAlert).filter(DBAlert.alert_id == existing_alert_id).first()
                    if db_alert:
                        db_alert.occurrence_count += 1
                        db_alert.timestamp = datetime.now(timezone.utc)
                        db.commit()
                        db.refresh(db_alert)
                        self._recent_alerts[dedup_key] = (existing_alert_id, now, count + 1)
                        logger.debug(f"Deduplicated alert {existing_alert_id} (count={count+1})")
                        return db_alert.to_dict()

            # Clean expired deduplication entries
            expired = [k for k, v in self._recent_alerts.items() if (now - v[1]) > self.deduplication_window_sec]
            for k in expired:
                del self._recent_alerts[k]

            # Create brand new alert
            alert_id = f"ALT-{uuid.uuid4().hex[:10].upper()}"

            evidence = {
                "flow_features": {
                    k: v for k, v in flow_features.items() if not k.startswith("_")
                },
                "detection_probabilities": detection_result.get("probabilities", {}),
                "is_anomaly": detection_result.get("is_anomaly", False),
                "anomaly_score": anomaly_score,
            }

            new_alert = DBAlert(
                alert_id=alert_id,
                timestamp=datetime.now(timezone.utc),
                source_ip=src_ip,
                destination_ip=dst_ip,
                source_port=src_port,
                destination_port=dst_port,
                protocol=protocol,
                attack_type=attack_type,
                severity=risk_level,
                confidence=confidence,
                anomaly_score=anomaly_score,
                model_name=model_name,
                occurrence_count=1,
                evidence_json=json.dumps(evidence)
            )

            db.add(new_alert)
            db.commit()
            db.refresh(new_alert)

            self._recent_alerts[dedup_key] = (alert_id, now, 1)
            logger.info(f"Generated new {risk_level} alert: {alert_id} - {attack_type} from {src_ip} to {dst_ip}")
            return new_alert.to_dict()

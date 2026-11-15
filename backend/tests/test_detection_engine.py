"""
Unit Tests for Detection Engine, Database Storage, and Alert Deduplication.
"""

import time
import pytest
from backend.app.database.database import get_sync_db, init_db
from backend.app.database.models import DBAlert, DBNetworkFlow
from backend.app.detection.alert_manager import AlertManager
from backend.app.detection.detection_engine import get_detection_engine
from backend.app.flow.flow_features import DirectionalFlow, DirectionalFlowKey

@pytest.fixture(autouse=True)
def setup_db():
    init_db()

def test_alert_deduplication():
    """
    Verifies that multiple attacks matching (src_ip, dst_ip, attack_type)
    within the deduplication window increment occurrence_count rather than creating duplicate alerts.
    """
    db = get_sync_db()
    manager = AlertManager(deduplication_window_sec=5.0)

    detection_result = {
        "is_malicious": True,
        "threat_category": "DDoS",
        "confidence_score": 0.95,
        "risk_level": "Critical",
        "model_used": "xgboost"
    }

    features = {
        "destination_port": 80,
        "_metadata": {
            "src_ip": "198.51.100.99",
            "dst_ip": "192.168.1.1",
            "src_port": 50000,
            "dst_port": 80,
            "protocol": 6
        }
    }

    # First detection -> brand new alert
    alert1 = manager.process_detection(db, detection_result, features)
    assert alert1 is not None
    assert alert1["occurrence_count"] == 1
    first_id = alert1["alert_id"]

    # Second detection 0.1s later with same signature -> deduplicated
    alert2 = manager.process_detection(db, detection_result, features)
    assert alert2 is not None
    assert alert2["alert_id"] == first_id
    assert alert2["occurrence_count"] == 2

    # Verify in DB
    db_alert = db.query(DBAlert).filter(DBAlert.alert_id == first_id).first()
    assert db_alert.occurrence_count == 2

    db.close()

def test_detection_engine_process_batch():
    """Verifies batch processing of directional flows and dashboard stats update."""
    engine = get_detection_engine()

    key1 = DirectionalFlowKey("192.168.1.5", "10.0.0.1", 45000, 80, 6)
    f1 = DirectionalFlow(key=key1, first_seen=10.0, last_seen=10.1)
    f1.add_packet(100, 10.0, tcp_flags="S")
    f1.add_packet(150, 10.1, tcp_flags="A")

    initial_total_flows = engine.total_flows_seen

    results = engine.process_flow_batch([f1], session_id="test-batch")
    assert len(results) == 1
    assert engine.total_flows_seen == initial_total_flows + 1

    overview = engine.get_dashboard_overview()
    assert overview["total_flows"] == engine.total_flows_seen

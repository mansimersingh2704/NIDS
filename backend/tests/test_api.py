"""
Integration Tests for FastAPI REST Endpoints in AI-NIDS.
"""

from pathlib import Path
import pytest
from starlette.testclient import TestClient

from backend.app.main import app

@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c

def test_health_endpoint(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert "active_model" in data
    assert "models_loaded" in data

def test_interfaces_endpoint(client):
    res = client.get("/api/interfaces")
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)

def test_dashboard_overview_endpoint(client):
    res = client.get("/api/dashboard/overview")
    assert res.status_code == 200
    data = res.json()
    assert "total_packets" in data
    assert "total_flows" in data
    assert "benign_count" in data
    assert "malicious_count" in data
    assert "detection_rate_pct" in data

def test_dashboard_traffic_endpoint(client):
    res = client.get("/api/dashboard/traffic")
    assert res.status_code == 200
    assert "traffic" in res.json()

def test_dashboard_attacks_endpoint(client):
    res = client.get("/api/dashboard/attacks")
    assert res.status_code == 200
    assert "attack_distribution" in res.json()

def test_alerts_endpoint(client):
    res = client.get("/api/alerts?page=1&limit=10")
    assert res.status_code == 200
    data = res.json()
    assert "alerts" in data
    assert "total" in data

def test_detections_endpoint(client):
    res = client.get("/api/detections?page=1&limit=10")
    assert res.status_code == 200
    data = res.json()
    assert "detections" in data
    assert "total" in data

def test_models_info_and_switch(client):
    res = client.get("/api/models/info")
    assert res.status_code == 200
    info = res.json()
    assert "active_model" in info
    assert "random_forest" in info["available_models"]
    assert "xgboost" in info["available_models"]

    # Test switching
    switch_res = client.post("/api/models/switch", json={"model_name": "xgboost"})
    assert switch_res.status_code == 200
    assert switch_res.json()["active_model"] == "xgboost"

    # Switch back
    client.post("/api/models/switch", json={"model_name": "random_forest"})

def test_models_metrics_endpoint(client):
    res = client.get("/api/models/metrics")
    assert res.status_code == 200
    metrics = res.json()
    assert "models" in metrics
    assert "random_forest" in metrics["models"]
    assert "xgboost" in metrics["models"]

def test_pcap_samples_and_analysis(client):
    res = client.get("/api/pcap/samples")
    assert res.status_code == 200
    samples = res.json()["samples"]
    assert len(samples) > 0

    first_sample = samples[0]["filename"]

    # Run analysis on the sample PCAP
    analyze_res = client.post("/api/pcap/analyze", json={"filename": first_sample})
    assert analyze_res.status_code == 200
    analysis = analyze_res.json()
    assert analysis["success"] is True
    assert "packets_count" in analysis
    assert "flows_count" in analysis
    assert "detections" in analysis

def test_reports_summary_and_export(client):
    summary_res = client.get("/api/reports/summary")
    assert summary_res.status_code == 200
    assert "traffic_summary" in summary_res.json()

    export_res = client.get("/api/reports/export?export_type=flows")
    assert export_res.status_code == 200
    assert "text/csv" in export_res.headers["content-type"]
    assert "Flow ID" in export_res.text

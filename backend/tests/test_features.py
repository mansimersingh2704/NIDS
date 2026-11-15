"""
Unit Tests for Flow Feature Extraction and Statistics in AI-NIDS.
"""

import json
from pathlib import Path
import numpy as np
import pytest
from backend.app.flow.flow_features import DirectionalFlow, DirectionalFlowKey

def test_flow_features_calculation():
    key = DirectionalFlowKey("192.168.1.100", "8.8.8.8", 50000, 53, 17)
    flow = DirectionalFlow(key=key, first_seen=100.0, last_seen=100.0)

    # Add 3 packets: lengths 50, 100, 150 at t=100.0, t=100.5, t=101.0
    flow.add_packet(length=50, timestamp=100.0)
    flow.add_packet(length=100, timestamp=100.5)
    flow.add_packet(length=150, timestamp=101.0)

    feats = flow.to_features()

    assert feats["destination_port"] == 53
    assert feats["total_packets"] == 3
    assert feats["total_bytes"] == 300
    assert feats["packet_len_min"] == 50.0
    assert feats["packet_len_max"] == 150.0
    assert feats["packet_len_mean"] == 100.0
    assert feats["avg_packet_size"] == 100.0

    # Duration: 1.0 second = 1,000,000 microseconds
    assert pytest.approx(feats["flow_duration"], rel=1e-3) == 1_000_000.0

    # Rates
    assert pytest.approx(feats["flow_bytes_per_sec"], rel=1e-3) == 300.0
    assert pytest.approx(feats["flow_packets_per_sec"], rel=1e-3) == 3.0

    # Inter-arrival times: diffs are [0.5s, 0.5s] = [500000 usec, 500000 usec]
    assert pytest.approx(feats["flow_iat_mean"], rel=1e-3) == 500_000.0
    assert pytest.approx(feats["flow_iat_min"], rel=1e-3) == 500_000.0
    assert pytest.approx(feats["flow_iat_max"], rel=1e-3) == 500_000.0
    assert pytest.approx(feats["flow_iat_std"], abs=1e-3) == 0.0

def test_feature_schema_conformance():
    """Verifies that to_features() provides every feature expected by the ML schema."""
    schema_path = Path("data/processed/feature_schema.json")
    if not schema_path.exists():
        pytest.skip("feature_schema.json not yet generated")

    with open(schema_path, "r") as f:
        schema = json.load(f)

    expected_features = schema["feature_columns"]

    key = DirectionalFlowKey("1.1.1.1", "2.2.2.2", 1000, 80, 6)
    flow = DirectionalFlow(key=key, first_seen=0.0, last_seen=0.0)
    flow.add_packet(length=64, timestamp=0.0, tcp_flags="S")
    feats = flow.to_features()

    for col in expected_features:
        assert col in feats, f"Missing expected feature '{col}' in flow extractor"
        assert isinstance(feats[col], (int, float)), f"Feature '{col}' must be numeric"

"""
Unit Tests for Machine Learning Inference and Preprocessing in AI-NIDS.
"""

import pytest
from backend.app.ml.model_registry import get_model_registry
from backend.app.ml.predict import predict_flow
from backend.app.ml.preprocessing import NIDSPreprocessor

SAMPLE_BENIGN_FLOW = {
    "destination_port": 80,
    "flow_duration": 15000.0,
    "total_packets": 5,
    "total_bytes": 450,
    "packet_len_min": 40.0,
    "packet_len_max": 200.0,
    "packet_len_mean": 90.0,
    "packet_len_std": 25.0,
    "packet_len_var": 625.0,
    "flow_bytes_per_sec": 30000.0,
    "flow_packets_per_sec": 333.3,
    "flow_iat_mean": 3750.0,
    "flow_iat_std": 500.0,
    "flow_iat_max": 4500.0,
    "flow_iat_min": 3000.0,
    "fin_flag_count": 1,
    "syn_flag_count": 1,
    "rst_flag_count": 0,
    "psh_flag_count": 1,
    "ack_flag_count": 4,
    "urg_flag_count": 0,
    "avg_packet_size": 90.0
}

def test_model_registry_loaded():
    registry = get_model_registry()
    assert registry.preprocessor is not None
    assert "random_forest" in registry.models
    assert "xgboost" in registry.models
    assert registry.isolation_forest is not None

def test_preprocessor_validation():
    registry = get_model_registry()
    preprocessor = registry.preprocessor

    # Valid transformation
    X_scaled = preprocessor.transform_features(SAMPLE_BENIGN_FLOW)
    assert X_scaled.shape == (1, len(preprocessor.feature_columns))

    # Missing column should raise ValueError
    invalid_flow = dict(SAMPLE_BENIGN_FLOW)
    del invalid_flow["destination_port"]
    with pytest.raises(ValueError) as exc:
        preprocessor.transform_features(invalid_flow)
    assert "destination_port" in str(exc.value)

def test_predict_flow_benign():
    result = predict_flow(SAMPLE_BENIGN_FLOW, model_name="random_forest")

    assert "predicted_class" in result
    assert "confidence_score" in result
    assert "risk_level" in result
    assert "probabilities" in result
    assert isinstance(result["confidence_score"], float)
    assert 0.0 <= result["confidence_score"] <= 1.0

def test_model_switching():
    registry = get_model_registry()
    original_model = registry.active_model_name

    registry.set_active_model("xgboost")
    assert registry.active_model_name == "xgboost"

    res_xgb = predict_flow(SAMPLE_BENIGN_FLOW)
    assert res_xgb["model_used"] == "xgboost"

    registry.set_active_model("random_forest")
    assert registry.active_model_name == "random_forest"

    res_rf = predict_flow(SAMPLE_BENIGN_FLOW)
    assert res_rf["model_used"] == "random_forest"

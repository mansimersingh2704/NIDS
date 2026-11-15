"""
Inference Engine for AI-NIDS.
Performs real-time supervised classification and anomaly scoring on flow features.
"""

from typing import Any, Dict, List, Optional, Tuple, Union
import numpy as np
import pandas as pd

from backend.app.ml.model_registry import get_model_registry

def predict_flow(
    flow_features: Dict[str, Any],
    model_name: Optional[str] = None
) -> Dict[str, Any]:
    """
    Performs inference on a single flow feature dictionary.
    Returns predicted class, threat category, risk level, confidence score, and anomaly score.
    """
    registry = get_model_registry()
    if registry.preprocessor is None:
        raise RuntimeError("ML preprocessor is not loaded. Train the model first.")

    model = registry.models.get(model_name or registry.active_model_name)
    if model is None:
        raise RuntimeError(f"Requested model '{model_name}' is not loaded.")

    # 1. Transform features
    X_scaled = registry.preprocessor.transform_features(flow_features)

    # 2. Supervised Classification
    pred_idx = int(model.predict(X_scaled)[0])
    probas = model.predict_proba(X_scaled)[0]
    confidence_score = float(probas[pred_idx])

    classes = registry.preprocessor.label_encoder.classes_.tolist()
    predicted_class = classes[pred_idx]

    is_malicious = predicted_class != "BENIGN"
    threat_category = predicted_class if is_malicious else "None"

    # 3. Unsupervised Anomaly Detection (Isolation Forest)
    is_anomaly = False
    anomaly_score = 0.0
    if registry.isolation_forest is not None:
        # decision_function yields negative for anomalies, positive for normal
        raw_score = float(registry.isolation_forest.decision_function(X_scaled)[0])
        # Normalize to 0..1 where higher means more anomalous
        anomaly_score = float(1.0 / (1.0 + np.exp(raw_score * 5.0)))
        is_anomaly = bool(registry.isolation_forest.predict(X_scaled)[0] == -1)

    # 4. Calibrated Risk Level Assignment
    # Constraint: Do not equate model confidence with actual threat severity
    if not is_malicious:
        if is_anomaly and anomaly_score > 0.65:
            risk_level = "Medium"  # Statistical outlier / abnormal benign flow
            threat_category = "Abnormal Traffic Pattern"
        else:
            risk_level = "Low"
    else:
        if predicted_class == "DDoS":
            risk_level = "Critical"
        elif predicted_class == "PortScan":
            risk_level = "High" if flow_features.get("total_packets", 1) > 2 else "Medium"
        else:
            risk_level = "High" if confidence_score > 0.8 else "Medium"

    return {
        "predicted_class": predicted_class,
        "threat_category": threat_category,
        "is_malicious": is_malicious,
        "confidence_score": round(confidence_score, 4),
        "risk_level": risk_level,
        "is_anomaly": is_anomaly,
        "anomaly_score": round(anomaly_score, 4),
        "model_used": model_name or registry.active_model_name,
        "probabilities": {
            cls_name: round(float(prob), 4)
            for cls_name, prob in zip(classes, probas)
        }
    }

"""
Training Pipeline for AI-NIDS Models.
Trains Random Forest, XGBoost, and Isolation Forest.
Evaluates on held-out test split and serializes models + metadata.
"""

from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, Tuple
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.model_selection import train_test_split
import xgboost as xgb

from backend.app.ml.evaluate import evaluate_classifier
from backend.app.ml.preprocessing import NIDSPreprocessor

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

def train_and_evaluate_models(
    dataset_path: Path = Path("data/processed/cicids2017_cleaned.csv"),
    output_model_dir: Path = Path("data/models"),
    random_seed: int = 42
) -> Dict[str, Any]:
    """Orchestrates model training, evaluation, comparison, and serialization."""
    output_model_dir.mkdir(parents=True, exist_ok=True)

    if not dataset_path.exists():
        raise FileNotFoundError(f"Cleaned dataset not found at {dataset_path}")

    logger.info(f"Loading cleaned dataset from {dataset_path}...")
    df = pd.read_csv(dataset_path)

    # 1. Feature Preprocessing
    preprocessor = NIDSPreprocessor()
    feature_cols = preprocessor.feature_columns
    logger.info(f"Using {len(feature_cols)} features: {feature_cols}")

    X = df[feature_cols]
    y = df["label"]

    # 2. Train/Validation/Test Splits (70% train, 15% val, 15% test)
    X_train_raw, X_temp_raw, y_train_raw, y_temp_raw = train_test_split(
        X, y, test_size=0.30, random_state=random_seed, stratify=y
    )
    X_val_raw, X_test_raw, y_val_raw, y_test_raw = train_test_split(
        X_temp_raw, y_temp_raw, test_size=0.50, random_state=random_seed, stratify=y_temp_raw
    )

    logger.info(f"Split sizes: Train={len(X_train_raw)}, Val={len(X_val_raw)}, Test={len(X_test_raw)}")

    # 3. Fit Preprocessor only on Training set to prevent data leakage
    preprocessor.fit(X_train_raw, y_train_raw)

    X_train = preprocessor.transform_features(X_train_raw)
    X_val = preprocessor.transform_features(X_val_raw)
    X_test = preprocessor.transform_features(X_test_raw)

    y_train = preprocessor.transform_labels(y_train_raw)
    y_val = preprocessor.transform_labels(y_val_raw)
    y_test = preprocessor.transform_labels(y_test_raw)

    class_names = preprocessor.label_encoder.classes_.tolist()
    logger.info(f"Classes: {class_names}")

    # 4. Train Model 1: Random Forest
    logger.info("Training Random Forest Classifier...")
    rf_model = RandomForestClassifier(
        n_estimators=100,
        max_depth=16,
        min_samples_split=5,
        class_weight="balanced",
        random_state=random_seed,
        n_jobs=-1
    )
    rf_model.fit(X_train, y_train)

    rf_pred = rf_model.predict(X_test)
    rf_proba = rf_model.predict_proba(X_test)
    rf_metrics = evaluate_classifier(y_test, rf_pred, rf_proba, class_names)
    logger.info(f"Random Forest Test Accuracy: {rf_metrics['accuracy']:.4f}, F1-Macro: {rf_metrics['f1_macro']:.4f}")

    # 5. Train Model 2: XGBoost
    logger.info("Training XGBoost Classifier...")
    xgb_model = xgb.XGBClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        objective="multi:softprob" if len(class_names) > 2 else "binary:logistic",
        random_state=random_seed,
        n_jobs=-1,
        eval_metric="mlogloss"
    )
    xgb_model.fit(X_train, y_train)

    xgb_pred = xgb_model.predict(X_test)
    xgb_proba = xgb_model.predict_proba(X_test)
    xgb_metrics = evaluate_classifier(y_test, xgb_pred, xgb_proba, class_names)
    logger.info(f"XGBoost Test Accuracy: {xgb_metrics['accuracy']:.4f}, F1-Macro: {xgb_metrics['f1_macro']:.4f}")

    # 6. Train Model 3: Isolation Forest (unsupervised anomaly detection on benign flows)
    logger.info("Training Isolation Forest on benign baseline flows...")
    benign_class_idx = class_names.index("BENIGN") if "BENIGN" in class_names else 0
    X_train_benign = X_train[y_train == benign_class_idx]

    iso_forest = IsolationForest(
        n_estimators=100,
        contamination=0.03,
        random_state=random_seed,
        n_jobs=-1
    )
    iso_forest.fit(X_train_benign)

    # Anomaly evaluation: -1 is anomaly, 1 is normal
    iso_test_scores = iso_forest.decision_function(X_test)
    iso_test_preds = iso_forest.predict(X_test)
    anomalies_detected = int(np.sum(iso_test_preds == -1))
    logger.info(f"Isolation Forest flagged {anomalies_detected}/{len(X_test)} test instances as anomalies.")

    # 7. Extract Feature Importances
    rf_importances = {
        col: round(float(imp), 4)
        for col, imp in zip(feature_cols, rf_model.feature_importances_)
    }
    rf_importances_sorted = dict(sorted(rf_importances.items(), key=lambda item: item[1], reverse=True))

    xgb_importances = {
        col: round(float(imp), 4)
        for col, imp in zip(feature_cols, xgb_model.feature_importances_)
    }
    xgb_importances_sorted = dict(sorted(xgb_importances.items(), key=lambda item: item[1], reverse=True))

    # 8. Determine Best Model
    best_model_name = "xgboost" if xgb_metrics["f1_macro"] >= rf_metrics["f1_macro"] else "random_forest"
    logger.info(f"Selected Champion Model: {best_model_name.upper()}")

    # 9. Save Artifacts
    preprocessor_path = output_model_dir / "preprocessor.joblib"
    rf_path = output_model_dir / "random_forest.joblib"
    xgb_path = output_model_dir / "xgboost.joblib"
    iso_path = output_model_dir / "isolation_forest.joblib"

    preprocessor.save(preprocessor_path)
    joblib.dump(rf_model, rf_path)
    joblib.dump(xgb_model, xgb_path)
    joblib.dump(iso_forest, iso_path)

    metadata = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "dataset": "CIC-IDS2017",
        "total_samples": len(df),
        "train_samples": len(X_train_raw),
        "val_samples": len(X_val_raw),
        "test_samples": len(X_test_raw),
        "features": feature_cols,
        "classes": class_names,
        "champion_model": best_model_name,
        "models": {
            "random_forest": {
                "name": "Random Forest",
                "type": "Ensemble (Bagging)",
                "hyperparameters": {
                    "n_estimators": 100,
                    "max_depth": 16,
                    "min_samples_split": 5,
                    "class_weight": "balanced"
                },
                "metrics": rf_metrics,
                "feature_importances": rf_importances_sorted,
                "model_file": "random_forest.joblib"
            },
            "xgboost": {
                "name": "XGBoost",
                "type": "Gradient Boosted Trees",
                "hyperparameters": {
                    "n_estimators": 100,
                    "max_depth": 6,
                    "learning_rate": 0.1,
                    "subsample": 0.8
                },
                "metrics": xgb_metrics,
                "feature_importances": xgb_importances_sorted,
                "model_file": "xgboost.joblib"
            },
            "isolation_forest": {
                "name": "Isolation Forest",
                "type": "Unsupervised Anomaly Detector",
                "hyperparameters": {
                    "n_estimators": 100,
                    "contamination": 0.03
                },
                "anomalies_detected_on_test": anomalies_detected,
                "model_file": "isolation_forest.joblib"
            }
        }
    }

    metadata_file = output_model_dir / "models_metadata.json"
    with open(metadata_file, "w") as f:
        json.dump(metadata, f, indent=2)

    logger.info(f"Serialized all models and metadata to {output_model_dir}")
    return metadata

if __name__ == "__main__":
    train_and_evaluate_models()

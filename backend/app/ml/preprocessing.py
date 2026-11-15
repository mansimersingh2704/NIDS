"""
ML Preprocessing Pipeline for AI-NIDS.
Handles feature scaling, imputation, schema validation, and label encoding.
Ensures training and inference pipelines share the exact same transformations.
"""

from __future__ import annotations
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler

DEFAULT_SCHEMA_PATH = Path("data/processed/feature_schema.json")

class NIDSPreprocessor:
    """Standardized preprocessor for network flow features."""

    def __init__(self, schema_path: Optional[Path] = None):
        self.schema_path = schema_path or DEFAULT_SCHEMA_PATH
        self.feature_columns: List[str] = []
        self.medians: Dict[str, float] = {}
        self.scaler: StandardScaler = StandardScaler()
        self.label_encoder: LabelEncoder = LabelEncoder()
        self.is_fitted: bool = False
        self._load_schema()

    def _load_schema(self) -> None:
        if self.schema_path.exists():
            with open(self.schema_path, "r") as f:
                schema = json.load(f)
                self.feature_columns = schema.get("feature_columns", [])
                self.medians = schema.get("medians", {})

    def fit(self, X: pd.DataFrame, y: Optional[pd.Series] = None) -> "NIDSPreprocessor":
        """Fits the scaler and label encoder on training data."""
        self._validate_input_columns(X)
        X_clean = self._clean_data(X)
        self.scaler.fit(X_clean[self.feature_columns])

        if y is not None:
            self.label_encoder.fit(y)

        self.is_fitted = True
        return self

    def transform_features(self, X: Union[pd.DataFrame, Dict[str, Any]]) -> np.ndarray:
        """Transforms raw input features into scaled numpy array ready for inference."""
        if isinstance(X, dict):
            df = pd.DataFrame([X])
        else:
            df = X.copy()

        self._validate_input_columns(df)
        df_clean = self._clean_data(df)
        X_selected = df_clean[self.feature_columns]
        return self.scaler.transform(X_selected)

    def transform_labels(self, y: pd.Series) -> np.ndarray:
        """Encodes string labels into integer classes."""
        return self.label_encoder.transform(y)

    def inverse_transform_labels(self, y_encoded: Union[np.ndarray, List[int]]) -> List[str]:
        """Converts integer class indices back to label strings."""
        return self.label_encoder.inverse_transform(y_encoded).tolist()

    def _validate_input_columns(self, df: pd.DataFrame) -> None:
        """Validates that all expected features are present."""
        missing = [col for col in self.feature_columns if col not in df.columns]
        if missing:
            raise ValueError(f"Input features missing required columns: {missing}")

    def _clean_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """Replaces infs, negative values, and imputes NaNs with medians."""
        df_clean = df.copy()
        df_clean.replace([np.inf, -np.inf], np.nan, inplace=True)

        for col in self.feature_columns:
            if col in df_clean.columns:
                df_clean[col] = pd.to_numeric(df_clean[col], errors="coerce")
                df_clean[col] = df_clean[col].clip(lower=0.0)
                if col in self.medians:
                    df_clean[col] = df_clean[col].fillna(self.medians[col])
                else:
                    df_clean[col] = df_clean[col].fillna(0.0)

        return df_clean

    def save(self, filepath: Union[str, Path]) -> None:
        """Serializes the fitted preprocessor."""
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, filepath)

    @classmethod
    def load(cls, filepath: Union[str, Path]) -> "NIDSPreprocessor":
        """Loads a serialized preprocessor."""
        return joblib.load(filepath)

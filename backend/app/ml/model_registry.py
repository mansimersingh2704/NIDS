"""
Model Registry for AI-NIDS.
Loads, manages, and switches trained ML models, preprocessors, and metadata in memory.
"""

from __future__ import annotations
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional
import joblib

from backend.app.ml.preprocessing import NIDSPreprocessor

logger = logging.getLogger(__name__)

class ModelRegistry:
    """In-memory singleton registry for trained NIDS models."""

    _instance: Optional["ModelRegistry"] = None

    def __new__(cls, model_dir: Path = Path("data/models")) -> "ModelRegistry":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, model_dir: Path = Path("data/models")) -> None:
        if getattr(self, "_initialized", False):
            return

        self.model_dir = Path(model_dir)
        self.metadata: Dict[str, Any] = {}
        self.preprocessor: Optional[NIDSPreprocessor] = None
        self.models: Dict[str, Any] = {}
        self.isolation_forest: Optional[Any] = None
        self.active_model_name: str = "random_forest"
        self._load()
        self._initialized = True

    def _load(self) -> None:
        metadata_file = self.model_dir / "models_metadata.json"
        if not metadata_file.exists():
            logger.warning(f"Model metadata not found at {metadata_file}. Models need training.")
            return

        with open(metadata_file, "r") as f:
            self.metadata = json.load(f)

        preprocessor_file = self.model_dir / "preprocessor.joblib"
        if preprocessor_file.exists():
            self.preprocessor = NIDSPreprocessor.load(preprocessor_file)
            logger.info("Loaded NIDS preprocessor.")

        rf_file = self.model_dir / "random_forest.joblib"
        if rf_file.exists():
            self.models["random_forest"] = joblib.load(rf_file)
            logger.info("Loaded Random Forest model.")

        xgb_file = self.model_dir / "xgboost.joblib"
        if xgb_file.exists():
            self.models["xgboost"] = joblib.load(xgb_file)
            logger.info("Loaded XGBoost model.")

        iso_file = self.model_dir / "isolation_forest.joblib"
        if iso_file.exists():
            self.isolation_forest = joblib.load(iso_file)
            logger.info("Loaded Isolation Forest model.")

        self.active_model_name = self.metadata.get("champion_model", "random_forest")
        logger.info(f"ModelRegistry initialized. Active model: {self.active_model_name}")

    def get_active_model(self) -> Any:
        if self.active_model_name not in self.models:
            raise RuntimeError(f"Active model '{self.active_model_name}' is not loaded.")
        return self.models[self.active_model_name]

    def set_active_model(self, name: str) -> None:
        if name not in self.models:
            raise ValueError(f"Model '{name}' not found. Available: {list(self.models.keys())}")
        self.active_model_name = name
        logger.info(f"Active detection model switched to: {name}")

    def get_metadata(self) -> Dict[str, Any]:
        return self.metadata

    def get_model_metrics(self, model_name: Optional[str] = None) -> Dict[str, Any]:
        name = model_name or self.active_model_name
        return self.metadata.get("models", {}).get(name, {})

# Global accessor
def get_model_registry() -> ModelRegistry:
    return ModelRegistry()

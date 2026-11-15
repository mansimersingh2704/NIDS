"""Machine Learning Model Inspection and Switching Routes for AI-NIDS."""
from fastapi import APIRouter, HTTPException, status
from backend.app.ml.model_registry import get_model_registry
from backend.app.schemas.api_schemas import (
    ModelInfoResponse,
    SwitchModelRequest,
)

router = APIRouter(tags=["Models"])

@router.get("/models/info", response_model=ModelInfoResponse)
async def get_model_info():
    """Returns metadata regarding active models, training datasets, and features."""
    registry = get_model_registry()
    meta = registry.get_metadata()

    return ModelInfoResponse(
        active_model=registry.active_model_name,
        available_models=list(registry.models.keys()),
        dataset=meta.get("dataset", "CIC-IDS2017"),
        total_training_samples=meta.get("total_samples", 0),
        features_count=len(meta.get("features", [])),
        classes=meta.get("classes", []),
        metadata=meta
    )

@router.get("/models/metrics")
async def get_model_metrics():
    """
    Returns comparative evaluation metrics on the held-out test split:
    Accuracy, Precision, Recall, F1-Score, Confusion Matrix, FPR, and Feature Importances.
    """
    registry = get_model_registry()
    meta = registry.get_metadata()
    return {
        "champion_model": meta.get("champion_model", registry.active_model_name),
        "active_model": registry.active_model_name,
        "models": meta.get("models", {}),
        "features": meta.get("features", [])
    }

@router.post("/models/switch")
async def switch_model(request: SwitchModelRequest):
    """Dynamically switches the active inference model (e.g. 'random_forest' <-> 'xgboost')."""
    registry = get_model_registry()
    try:
        registry.set_active_model(request.model_name)
        return {
            "success": True,
            "active_model": registry.active_model_name,
            "message": f"Successfully switched active detection model to '{request.model_name}'."
        }
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve)
        )

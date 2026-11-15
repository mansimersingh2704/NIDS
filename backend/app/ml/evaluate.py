"""
Evaluation utilities for AI-NIDS Machine Learning models.
Computes multi-class and binary metrics, ROC curves, confusion matrices, and FPR.
"""

from typing import Any, Dict, List, Optional
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

def evaluate_classifier(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_proba: Optional[np.ndarray],
    class_names: List[str]
) -> Dict[str, Any]:
    """Calculates comprehensive classification metrics for model evaluation."""
    acc = float(accuracy_score(y_true, y_pred))
    prec_macro = float(precision_score(y_true, y_pred, average="macro", zero_division=0))
    rec_macro = float(recall_score(y_true, y_pred, average="macro", zero_division=0))
    f1_macro = float(f1_score(y_true, y_pred, average="macro", zero_division=0))

    prec_weighted = float(precision_score(y_true, y_pred, average="weighted", zero_division=0))
    rec_weighted = float(recall_score(y_true, y_pred, average="weighted", zero_division=0))
    f1_weighted = float(f1_score(y_true, y_pred, average="weighted", zero_division=0))

    cm = confusion_matrix(y_true, y_pred)
    cm_list = cm.tolist()

    # Calculate False Positive Rate (FPR) treating class 0 (BENIGN) as negative
    # Benign is index 0 in sorted classes ['BENIGN', 'DDoS', 'PortScan']
    benign_idx = 0 if "BENIGN" in class_names else 0
    fp = float(np.sum(cm[:, benign_idx]) - cm[benign_idx, benign_idx])
    tn = float(np.sum(cm) - np.sum(cm[benign_idx, :]) - np.sum(cm[:, benign_idx]) + cm[benign_idx, benign_idx])
    # For actual Benign negative instances:
    total_actual_negatives = float(np.sum(cm[benign_idx, :]))
    actual_benign_false_positives = float(np.sum(cm[benign_idx, :]) - cm[benign_idx, benign_idx])
    fpr = actual_benign_false_positives / total_actual_negatives if total_actual_negatives > 0 else 0.0

    # ROC AUC calculation
    roc_auc = None
    if y_proba is not None and len(class_names) > 1:
        try:
            if len(class_names) == 2:
                roc_auc = float(roc_auc_score(y_true, y_proba[:, 1]))
            else:
                roc_auc = float(roc_auc_score(y_true, y_proba, multi_class="ovr", average="macro"))
        except Exception:
            roc_auc = None

    report = classification_report(y_true, y_pred, target_names=class_names, output_dict=True, zero_division=0)

    # Per-class summary
    per_class = {}
    for cls in class_names:
        if cls in report:
            per_class[cls] = {
                "precision": float(report[cls]["precision"]),
                "recall": float(report[cls]["recall"]),
                "f1_score": float(report[cls]["f1-score"]),
                "support": int(report[cls]["support"]),
            }

    return {
        "accuracy": round(acc, 4),
        "precision_macro": round(prec_macro, 4),
        "recall_macro": round(rec_macro, 4),
        "f1_macro": round(f1_macro, 4),
        "precision_weighted": round(prec_weighted, 4),
        "recall_weighted": round(rec_weighted, 4),
        "f1_weighted": round(f1_weighted, 4),
        "false_positive_rate": round(fpr, 4),
        "roc_auc": round(roc_auc, 4) if roc_auc is not None else None,
        "confusion_matrix": {
            "matrix": cm_list,
            "classes": class_names,
        },
        "per_class": per_class,
        "classification_report": report,
    }

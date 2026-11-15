"""Script entrypoint to run ML model training and evaluation."""
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.app.ml.train import train_and_evaluate_models

if __name__ == "__main__":
    train_and_evaluate_models()

"""
Core application configuration for AI-NIDS.
Loads settings from environment variables and provides centralized defaults.
"""

from pathlib import Path
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    ENVIRONMENT: str = "development"
    LOG_LEVEL: str = "INFO"
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    # Paths
    BASE_DIR: Path = Path(__file__).resolve().parent.parent.parent.parent
    DATA_DIR: Path = BASE_DIR / "data"
    MODEL_DIR: Path = DATA_DIR / "models"
    PROCESSED_DATA_DIR: Path = DATA_DIR / "processed"
    PCAP_STORAGE_DIR: Path = DATA_DIR / "uploads"
    SAMPLE_PCAP_DIR: Path = DATA_DIR / "sample_pcaps"
    DB_PATH: Path = DATA_DIR / "nids.db"

    # Database
    DATABASE_URL: str = f"sqlite+aiosqlite:///{DB_PATH.resolve()}"
    SYNC_DATABASE_URL: str = f"sqlite:///{DB_PATH.resolve()}"

    # Flow Engine
    FLOW_ACTIVE_TIMEOUT_SEC: float = 60.0
    FLOW_IDLE_TIMEOUT_SEC: float = 15.0
    MAX_PCAP_FILE_SIZE_MB: int = 50

    # Detection & ML
    ACTIVE_MODEL_NAME: str = "random_forest"
    ANOMALY_DETECTION_ENABLED: bool = True
    ALERT_DEDUPLICATION_WINDOW_SEC: float = 30.0

    # CORS
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:8000"
    ]

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()

# Ensure required directories exist
settings.DATA_DIR.mkdir(parents=True, exist_ok=True)
settings.MODEL_DIR.mkdir(parents=True, exist_ok=True)
settings.PCAP_STORAGE_DIR.mkdir(parents=True, exist_ok=True)
settings.SAMPLE_PCAP_DIR.mkdir(parents=True, exist_ok=True)

"""
Configuration settings for the FastAPI Backend.
Credentials are loaded from the .env file for security.
"""

import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "PhishGuard AI"
    API_V1_STR: str = "/api/v1"
    
    # Security — loaded from .env file
    ADMIN_USERNAME: str = "admin"
    ADMIN_PASSWORD: str = "PhishGuard@2026!"  # Override in .env file
    SECRET_KEY: str = "PG_ultra_secret_cyber_key_x9#2026!random"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    
    # File Limits
    MAX_CONTENT_LENGTH: int = 5 * 1024 * 1024  # 5MB max email size
    ALLOWED_EXTENSIONS: set = {"txt", "eml", "msg"}
    
    # Paths
    BASE_DIR: str = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    DATABASE_URL: str = f"sqlite:///{os.path.join(BASE_DIR, 'phishguard.db')}"
    
    # Model configuration
    MODEL_DIR: str = os.path.join(os.path.dirname(BASE_DIR), "model", "save")
    FALLBACK_MODEL_PATH: str = os.path.join(MODEL_DIR, "fallback_model.pkl")
    VECTORIZER_PATH: str = os.path.join(MODEL_DIR, "vectorizer.pkl")
    TRANSFORMER_MODEL_PATH: str = os.path.join(MODEL_DIR, "distilbert")
    
    class Config:
        env_file = ".env"           # Load from .env automatically
        env_file_encoding = "utf-8"
        case_sensitive = True

settings = Settings()

# Runtime-mutable admin password (supports in-session password change)
# This is updated in memory by the /admin/change-password endpoint.
_runtime_admin_password: str = settings.ADMIN_PASSWORD

def get_admin_password() -> str:
    """Returns the current active admin password (may differ from .env if changed at runtime)."""
    return _runtime_admin_password

def set_admin_password(new_password: str) -> None:
    """Updates the admin password in memory for the current session."""
    global _runtime_admin_password
    _runtime_admin_password = new_password

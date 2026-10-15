"""Environment-backed configuration for SecureMind AI.

The .env path is anchored to the backend folder, so launching Uvicorn from
another current working directory does not silently skip local configuration.
"""
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parents[1]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=BACKEND_DIR / ".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_env: str = "development"
    jwt_secret: str = "development-only-change-this-secret-before-deployment-8bf142"
    jwt_issuer: str = "securemind-ai"
    jwt_ttl_minutes: int = 30
    allow_demo_login: bool = False
    demo_username: str = "demo"
    demo_password: str = "change-me-now"
    demo_role: str = "admin"
    default_profile: str = "enterprise"
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    rate_limit_per_minute: int = 30
    mcp_transport: str = "demo"
    mcp_server_url: str = "http://127.0.0.1:9000/mcp"
    mcp_server_token: str = ""
    mcp_stdio_command: str = ""
    mcp_stdio_args: str = "[]"


settings = Settings()

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT_DIR = Path(__file__).resolve().parents[3]


class Settings(BaseSettings):
    app_env: str = "development"
    session_secret: str = "development-only-change-me-please-32-chars"
    frontend_url: str = "http://localhost:5173"
    cors_origins: str = "http://localhost:5173"

    github_app_id: str = ""
    github_app_slug: str = ""
    github_client_id: str = ""
    github_client_secret: str = ""
    github_private_key_path: str = ""
    github_private_key: str = ""
    github_webhook_secret: str = ""
    github_api_base_url: str = "https://api.github.com"
    github_api_version: str = "2022-11-28"

    nebius_api_key: str = ""
    nebius_base_url: str = "https://api.tokenfactory.nebius.com/v1"
    nebius_model: str = "nvidia/Nemotron-3_5-Lightning"

    tavily_api_key: str = ""
    sandbox_provider: str = "demo"
    nebius_sandbox_base_url: str = "https://api.tokenfactory.nebius.com/sandboxes"
    nebius_project: str = ""
    sandbox_timeout_seconds: int = 180
    sandbox_max_archive_bytes: int = 8_388_608

    max_repository_files: int = 60
    max_file_bytes: int = 180_000
    max_repository_bytes: int = 1_200_000
    max_findings: int = 10

    opengrep_enabled: bool = False
    opengrep_image: str = "raksa-opengrep:v1.30.0"
    opengrep_timeout_seconds: int = 120

    database_url: str = "postgresql+asyncpg://raksa:raksa@localhost:5432/raksa"
    worker_enabled: bool = True
    worker_poll_interval_seconds: float = 1.0
    worker_heartbeat_interval_seconds: float = 5.0
    worker_stale_timeout_seconds: int = 180
    worker_max_attempts: int = 3

    model_config = SettingsConfigDict(
        env_file=str(ROOT_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @property
    def allowed_origins(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def async_database_url(self) -> str:
        url = self.database_url.strip()
        if url.startswith("postgresql://"):
            return url.replace("postgresql://", "postgresql+asyncpg://", 1)
        if url.startswith("postgres://"):
            return url.replace("postgres://", "postgresql+asyncpg://", 1)
        return url

    @property
    def resolved_github_private_key(self) -> str:
        if self.github_private_key.strip():
            return self.github_private_key.replace("\\n", "\n")
        if self.github_private_key_path:
            path = Path(self.github_private_key_path).expanduser()
            if path.exists():
                return path.read_text(encoding="utf-8")
        return ""


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()

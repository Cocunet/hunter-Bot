from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class AppConfig(BaseSettings):
    """Application configuration, loaded from environment variables / .env.

    All settings are prefixed with ``HUNTERBOT_`` (e.g. ``HUNTERBOT_DATABASE_URL``)
    to avoid clashing with unrelated environment variables.
    """

    model_config = SettingsConfigDict(
        env_prefix="HUNTERBOT_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "HunterBot"
    debug: bool = False
    log_level: str = "INFO"
    database_url: str = "sqlite:///./hunterbot.db"
    api_key: str | None = None
    """When set, hunterbot.api requires every request to carry this value as
    an ``Authorization: Bearer <api_key>`` header. Unset (the default) means
    the API is open — fine for local development, not for anything network-
    reachable, since it can register Scopes and run scans."""


@lru_cache
def get_config() -> AppConfig:
    """Return the process-wide AppConfig singleton.

    Cached because BaseSettings re-reads the environment on every
    instantiation; callers that need a fresh read (e.g. tests) should
    construct ``AppConfig()`` directly instead of going through this.
    """
    return AppConfig()

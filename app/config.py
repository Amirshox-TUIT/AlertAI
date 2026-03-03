from functools import lru_cache
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "Wazuh AI Alert Service"
    wazuh_log_path: str = Field(default="alerts.json", description="Path to Wazuh alert log file")
    default_max_lines: int = 500
    contamination: float = 0.08
    min_rule_level_alert: int = 10
    send_telegram_by_default: bool = True

    telegram_bot_token: str | None = None
    telegram_chat_id: str | None = None


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
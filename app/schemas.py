from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class AnalyzeRequest(BaseModel):
    file_path: str | None = Field(default=None, description="Wazuh log file path")
    max_lines: int | None = Field(default=None, ge=10, le=5000)
    send_telegram: bool | None = Field(default=None, description="Send alert to Telegram")


class SuspiciousItem(BaseModel):
    timestamp: datetime | None = None
    source: str | None = None
    message: str
    reasons: list[str]
    anomaly_score: float
    rule_level: int | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class AnalyzeResponse(BaseModel):
    total_logs: int
    suspicious_count: int
    suspicious_items: list[SuspiciousItem]
    telegram_sent: bool
    telegram_error: str | None = None


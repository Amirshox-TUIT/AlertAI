import json
import re
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class LogEvent:
    timestamp: datetime | None
    source: str | None
    message: str
    rule_level: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def feature_text(self) -> str:
        parts = [self.message]
        if self.source:
            parts.append(f"source:{self.source}")
        if self.rule_level is not None:
            parts.append(f"rule_level:{self.rule_level}")
        for key, value in self.metadata.items():
            parts.append(f"{key}:{value}")
        return " ".join(str(p) for p in parts if p)


def read_last_lines(file_path: str, max_lines: int) -> list[str]:
    path = Path(file_path)
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"Log file not found: {file_path}")

    json_lines = _read_json_payload_if_any(path=path, max_lines=max_lines)
    if json_lines is not None:
        return json_lines

    buffer: deque[str] = deque(maxlen=max_lines)
    with path.open("r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            stripped = line.strip()
            if stripped:
                buffer.append(stripped)
    return list(buffer)


def _read_json_payload_if_any(path: Path, max_lines: int) -> list[str] | None:
    # Some exported alert files are JSON arrays, not NDJSON; parse those directly.
    with path.open("r", encoding="utf-8", errors="ignore") as file:
        probe = file.read(2048)

    first_non_space = probe.lstrip()
    if not first_non_space:
        return []
    if not first_non_space.startswith("["):
        return None

    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except json.JSONDecodeError:
        return None

    if not isinstance(payload, list):
        return None

    items = payload[-max_lines:]
    normalized_lines: list[str] = []
    for item in items:
        if isinstance(item, (dict, list)):
            normalized_lines.append(json.dumps(item, ensure_ascii=False))
        elif item is not None:
            normalized_lines.append(str(item))

    return normalized_lines


def parse_lines(raw_lines: list[str]) -> list[LogEvent]:
    events: list[LogEvent] = []
    for line in raw_lines:
        event = parse_line(line)
        if event:
            events.append(event)
    return events


def parse_line(line: str) -> LogEvent | None:
    try:
        data = json.loads(line)
        if isinstance(data, dict):
            return _parse_json_log(data)
    except json.JSONDecodeError:
        pass
    return _parse_plain_log(line)


def _parse_json_log(data: dict[str, Any]) -> LogEvent:
    timestamp = _parse_timestamp(data.get("timestamp") or data.get("@timestamp"))
    rule = data.get("rule") if isinstance(data.get("rule"), dict) else {}
    agent = data.get("agent") if isinstance(data.get("agent"), dict) else {}
    manager = data.get("manager") if isinstance(data.get("manager"), dict) else {}

    message = (
        rule.get("description")
        or data.get("full_log")
        or data.get("log")
        or data.get("message")
        or "No message"
    )
    source = agent.get("name") or manager.get("name") or data.get("hostname")
    rule_level = _safe_int(rule.get("level"))

    metadata: dict[str, Any] = {}
    if rule.get("id") is not None:
        metadata["rule_id"] = rule.get("id")
    if data.get("decoder") and isinstance(data.get("decoder"), dict):
        metadata["decoder"] = data["decoder"].get("name")
    if data.get("data") and isinstance(data.get("data"), dict):
        srcip = data["data"].get("srcip")
        dstip = data["data"].get("dstip")
        if srcip:
            metadata["srcip"] = srcip
        if dstip:
            metadata["dstip"] = dstip

    return LogEvent(
        timestamp=timestamp,
        source=source,
        message=str(message),
        rule_level=rule_level,
        metadata=metadata,
    )


def _parse_plain_log(line: str) -> LogEvent:
    pattern = r"^(?P<ts>\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z)?)?\s*(?P<msg>.*)$"
    match = re.match(pattern, line)
    timestamp = None
    message = line
    if match:
        timestamp = _parse_timestamp(match.group("ts"))
        message = match.group("msg")
    return LogEvent(timestamp=timestamp, source=None, message=message.strip())


def _parse_timestamp(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        candidate = value.replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(candidate)
        except ValueError:
            return None
    return None


def _safe_int(value: Any) -> int | None:
    try:
        if value is None:
            return None
        return int(value)
    except (TypeError, ValueError):
        return None

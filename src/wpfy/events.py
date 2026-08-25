from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .settings import current_paths

_MAX_EVENT_BYTES = 1024 * 1024
_SECRET_KEY = re.compile(
    r"(?<![A-Z0-9])(?:PASSWORD|SECRET|TOKEN|KEY|PWD|PASS|CREDENTIAL|AUTHORIZATION|AUTH)(?![A-Z0-9])",
    re.IGNORECASE,
)
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)(?<![A-Z0-9])(PASSWORD|SECRET|TOKEN|KEY|PWD|PASS|CREDENTIAL|AUTHORIZATION|AUTH)(?![A-Z0-9])"
    r"(\s*[=:]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)
_AUTHORIZATION_ASSIGNMENT = re.compile(
    r"(?i)(?<![A-Z0-9])(AUTHORIZATION)(?![A-Z0-9])(\s*[=:]\s*)(?:\"[^\"]*\"|'[^']*'|[^,;\r\n]+)"
)
_QUOTED_KEY_ASSIGNMENT = re.compile(
    r"(?i)(?<![A-Z0-9])(['\"])(PASSWORD|SECRET|TOKEN|KEY|PWD|PASS|CREDENTIAL|AUTHORIZATION|AUTH)\1"
    r"(\s*[=:]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s,;}]+)"
)


def event_log_path() -> Path:
    return Path(current_paths().state_dir) / "events" / "events.jsonl"


def _redact(value: Any, key: str = "") -> Any:
    if key and _SECRET_KEY.search(key):
        return "***REDACTED***"
    if isinstance(value, dict):
        return {str(item_key): _redact(item_value, str(item_key)) for item_key, item_value in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact(item) for item in value]
    if isinstance(value, str):
        value = _QUOTED_KEY_ASSIGNMENT.sub(r"\1\2\1\3***REDACTED***", value)
        value = _AUTHORIZATION_ASSIGNMENT.sub(r"\1\2***REDACTED***", value)
        return _SECRET_ASSIGNMENT.sub(r"\1\2***REDACTED***", value)
    return value


def _json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    try:
        json.dumps(value)
    except (TypeError, ValueError):
        # Stringification is itself an information boundary: exception
        # messages and other custom objects can contain credential material.
        return _redact(str(value))
    return value


def _rotate(path: Path) -> None:
    if not path.exists() or path.stat().st_size <= _MAX_EVENT_BYTES:
        return
    rotated = path.with_name(path.name + ".1")
    if rotated.exists():
        rotated.unlink()
    path.rename(rotated)


def record_event(
    action,
    *,
    domain=None,
    outcome="ok",
    detail="",
    actor="cli",
    job_id=None,
) -> dict:
    event = _json_safe(_redact({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": str(action),
        "domain": domain,
        "outcome": str(outcome),
        "detail": detail,
        "actor": str(actor),
        "job_id": job_id,
    }))
    path = event_log_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        _rotate(path)
        line = json.dumps(event, ensure_ascii=True, separators=(",", ":")) + "\n"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, line.encode("utf-8"))
        finally:
            os.close(fd)
    except (OSError, TypeError, ValueError):
        return event
    return event


def list_events(limit=200, domain=None, action=None) -> list[dict]:
    try:
        requested = max(0, int(limit))
    except (TypeError, ValueError):
        requested = 200
    if requested == 0:
        return []

    events: list[dict] = []
    path = event_log_path()
    for candidate in (path, path.with_name(path.name + ".1")):
        try:
            lines = candidate.read_text(encoding="utf-8", errors="replace").splitlines()
        except FileNotFoundError:
            continue
        except OSError:
            continue
        for line in reversed(lines):
            try:
                event = json.loads(line)
            except (json.JSONDecodeError, TypeError):
                continue
            if not isinstance(event, dict):
                continue
            event = _redact(event)
            if domain is not None and event.get("domain") != domain:
                continue
            if action is not None and event.get("action") != action:
                continue
            events.append(event)
            if len(events) >= requested:
                return events
    return events

from __future__ import annotations

import importlib
import json


def test_event_redaction_and_filters(tmp_wpfy_home):
    import wpfy.events as events
    importlib.reload(events)

    events.record_event(
        "site.config",
        domain="example.com",
        detail={"DB_PASSWORD": "secret-value", "message": "TOKEN=other-secret"},
    )

    rows = events.list_events(domain="example.com", action="site.config")
    assert len(rows) == 1
    serialized = json.dumps(rows[0])
    assert "secret-value" not in serialized
    assert "other-secret" not in serialized
    assert "REDACTED" in serialized


def test_event_log_rotates(tmp_wpfy_home, monkeypatch):
    import wpfy.events as events
    importlib.reload(events)
    monkeypatch.setattr(events, "_MAX_EVENT_BYTES", 1)

    events.record_event("first")
    events.record_event("second")

    path = events.event_log_path()
    assert path.exists()
    assert path.with_name(path.name + ".1").exists()
    assert [row["action"] for row in events.list_events()] == ["second", "first"]

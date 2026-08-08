from __future__ import annotations

import importlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest


DOMAIN = "files.example.com"


def _seed_site(paths) -> Path:
    site = Path(paths.sites_dir) / DOMAIN
    (site / "app").mkdir(parents=True)
    (site / "nginx").mkdir()
    (site / ".env").write_text(f"DOMAIN={DOMAIN}\n", encoding="utf-8")
    (site / "compose.yaml").write_text("services: {}\n", encoding="utf-8")
    return site


@pytest.fixture
def quantum_env(tmp_wpfy_home, tmp_path, monkeypatch):
    docker_log = tmp_path / "docker.log"
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    docker = bin_dir / "docker"
    docker.write_text(
        "#!/bin/sh\n"
        "printf '%s\\n' \"$*\" >> \"$WPFY_TEST_DOCKER_LOG\"\n"
        "case \"$*\" in\n"
        "  *'compose version'*) echo 'Docker Compose version v2.0.0' ;;\n"
        "  inspect*) echo '/wpfy-fm-files-example-com' ;;\n"
        "esac\n"
        "exit 0\n",
        encoding="utf-8",
    )
    docker.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
    monkeypatch.setenv("WPFY_TEST_DOCKER_LOG", str(docker_log))
    monkeypatch.delenv("WPFY_SKIP_RUNTIME", raising=False)
    site = _seed_site(tmp_wpfy_home)

    import wpfy.file_manager
    import wpfy.site_runtime
    import wpfy.file_manager_providers.quantum as quantum

    importlib.reload(wpfy.site_runtime)
    importlib.reload(wpfy.file_manager)
    importlib.reload(quantum)
    wpfy.site_runtime.docker_available.cache_clear()
    return tmp_wpfy_home, site, docker_log, quantum


def _serve_health(port: int, status: int = 204):
    class HealthHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(status)
            self.end_headers()

        def log_message(self, format: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", port), HealthHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def test_ensure_config_is_idempotent(quantum_env):
    _, site, _, quantum = quantum_env

    quantum.ensure_config(DOMAIN)
    first = (site / ".wpfy" / "file-manager" / "config.yaml").read_text(encoding="utf-8")
    quantum.ensure_config(DOMAIN)
    second = (site / ".wpfy" / "file-manager" / "config.yaml").read_text(encoding="utf-8")

    assert first == second


def test_ensure_config_writes_quantum_config_and_compose(quantum_env):
    _, site, _, quantum = quantum_env

    quantum.ensure_config(DOMAIN)
    fm_dir = site / ".wpfy" / "file-manager"
    config = (fm_dir / "config.yaml").read_text(encoding="utf-8")
    compose = (fm_dir.parent / "file-manager-compose.yaml").read_text(encoding="utf-8")

    assert "auth:" in config
    assert "proxy:" in config
    assert 'header: "X-Forwarded-User"' in config
    assert "  key:" in config
    assert "aadfaa026ebae24e373e523662cd9e8f562b5e3c404ac1df65ef13ddcd14b2fc" in compose
    assert "--noauth" not in compose
    assert "127.0.0.1:" in compose and ":80" in compose
    assert "curl" in compose
    assert "read_only: true" in compose
    assert "cap_drop:" in compose and "- ALL" in compose
    assert "external: true" not in compose


def test_health_accepts_2xx_and_rejects_non_2xx_or_refused(quantum_env):
    _, site, _, quantum = quantum_env
    quantum.ensure_config(DOMAIN)
    port = int((site / ".wpfy" / "file-manager" / "port").read_text(encoding="utf-8"))

    healthy, healthy_thread = _serve_health(port)
    try:
        assert quantum.health(DOMAIN) is True
    finally:
        healthy.shutdown()
        healthy.server_close()
        healthy_thread.join(timeout=2)

    unhealthy, unhealthy_thread = _serve_health(port, 503)
    try:
        assert quantum.health(DOMAIN) is False
    finally:
        unhealthy.shutdown()
        unhealthy.server_close()
        unhealthy_thread.join(timeout=2)

    assert quantum.health(DOMAIN) is False


def test_enable_file_manager_completes_first_run(quantum_env):
    _, _, _, quantum = quantum_env
    import wpfy.file_manager as file_manager

    quantum.ensure_config(DOMAIN)
    port = int((Path(quantum._fm_dir(DOMAIN)) / "port").read_text(encoding="utf-8"))
    server, thread = _serve_health(port)
    try:
        result = file_manager.enable_file_manager(DOMAIN, "alice", quantum)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert result == {"state": "ready", "url": f"/api/sites/{DOMAIN}/file-manager/proxy/"}


class _StubProvider:
    def __init__(
        self,
        *,
        start_error: Exception | None = None,
        healthy: bool = True,
        launch_path: str | None = None,
    ) -> None:
        self.start_error = start_error
        self.healthy = healthy
        self.launch_path = launch_path
        self.calls: list[tuple[str, str]] = []
        self.stopped: list[str] = []

    def ensure_config(self, domain: str) -> None:
        self.calls.append(("ensure_config", domain))

    def start(self, domain: str) -> None:
        self.calls.append(("start", domain))
        if self.start_error is not None:
            raise self.start_error

    def stop(self, domain: str) -> None:
        self.calls.append(("stop", domain))
        self.stopped.append(domain)

    def status(self, domain: str) -> dict:
        self.calls.append(("status", domain))
        return {"running": False}

    def health(self, domain: str) -> bool:
        self.calls.append(("health", domain))
        return self.healthy

    def create_launch_session(self, domain: str, username: str) -> str:
        self.calls.append(("create_launch_session", f"{domain}/{username}"))
        return self.launch_path or f"/{domain}/{username}"

    def reset_metadata(self, domain: str) -> None:
        self.calls.append(("reset_metadata", domain))


def test_concurrency_cap_rejects_when_full(quantum_env, monkeypatch):
    paths, site, _, _ = quantum_env
    import wpfy.file_manager as file_manager

    second_domain = "second.example.com"
    second_site = Path(paths.sites_dir) / second_domain
    (second_site / "app").mkdir(parents=True)
    (second_site / "compose.yaml").write_text("services: {}\n", encoding="utf-8")
    (second_site / ".env").write_text(f"DOMAIN={second_domain}\n", encoding="utf-8")
    monkeypatch.setenv("WPFY_FM_MAX", "1")
    monkeypatch.setattr(file_manager, "count_running_file_managers", lambda: 1)

    with pytest.raises(file_manager.FileManagerError) as raised:
        file_manager.enable_file_manager(second_domain, "alice", _StubProvider())

    assert raised.value.code == "limit_reached"
    assert str(raised.value) == (
        "The server has reached its active file-manager limit. "
        "Disable an inactive file manager or try again later."
    )
    assert site.exists()


def test_lease_holders_dedupe_and_reset(quantum_env):
    _, _, _, _ = quantum_env
    import wpfy.file_manager as file_manager

    file_manager._write_state(DOMAIN, {"state": "ready", "domain": DOMAIN, "lease_holders": []})
    assert file_manager.create_lease(DOMAIN, "alice")["active_leases"] == 1
    assert file_manager.create_lease(DOMAIN, "alice")["active_leases"] == 1
    assert file_manager.create_lease(DOMAIN, "bob")["active_leases"] == 2
    assert file_manager.lease_holder_usernames(DOMAIN) == ["alice", "bob"]

    file_manager.disable_file_manager(DOMAIN, _StubProvider())
    state = file_manager.get_file_manager_state(DOMAIN)
    assert state.active_leases == 0
    assert state.lease_holders == []


def test_partial_failure_calls_stop(quantum_env):
    _, site, _, _ = quantum_env
    import wpfy.file_manager as file_manager

    provider = _StubProvider(start_error=RuntimeError("start exploded"))
    with pytest.raises(file_manager.FileManagerError) as raised:
        file_manager.enable_file_manager(DOMAIN, "alice", provider)

    assert raised.value.code == "start_failed"
    assert provider.stopped == [DOMAIN]
    stored = json.loads((site / ".wpfy" / "file-manager" / "state.json").read_text(encoding="utf-8"))
    assert stored["state"] == "failed"
    assert stored["code"] == "start_failed"


def test_health_failure_code(quantum_env):
    _, _, _, _ = quantum_env
    import wpfy.file_manager as file_manager

    provider = _StubProvider(healthy=False)
    with pytest.raises(file_manager.FileManagerError) as raised:
        file_manager.enable_file_manager(DOMAIN, "alice", provider)

    assert raised.value.code == "health_failed"
    assert provider.stopped == [DOMAIN]


def test_disable_transitions_ready_to_disabled_and_is_idempotent(quantum_env):
    _, _, _, _ = quantum_env
    import wpfy.file_manager as file_manager

    file_manager.mark_ready(DOMAIN)
    provider = _StubProvider()

    assert file_manager.disable_file_manager(DOMAIN, provider) == {"state": "disabled"}
    assert file_manager.get_file_manager_state(DOMAIN).state == "disabled"
    assert file_manager.disable_file_manager(DOMAIN, provider) == {"state": "disabled"}
    assert provider.stopped == [DOMAIN, DOMAIN]


def test_enable_starting_state_returns_without_calling_provider(quantum_env):
    _, site, _, _ = quantum_env
    import wpfy.file_manager as file_manager

    file_manager._write_state(DOMAIN, {"state": "starting", "domain": DOMAIN})
    provider = _StubProvider(start_error=AssertionError("starting state must not retry"))

    assert file_manager.enable_file_manager(DOMAIN, "alice", provider) == {"state": "starting"}
    assert provider.calls == []
    assert json.loads((site / ".wpfy" / "file-manager" / "state.json").read_text()) ["state"] == "starting"


def test_enable_failed_state_retries_to_ready(quantum_env):
    _, _, _, _ = quantum_env
    import wpfy.file_manager as file_manager

    file_manager._write_state(DOMAIN, {"state": "failed", "domain": DOMAIN})
    provider = _StubProvider(launch_path="/proxy/")

    assert file_manager.enable_file_manager(DOMAIN, "alice", provider) == {"state": "ready", "url": "/proxy/"}
    assert file_manager.get_file_manager_state(DOMAIN).state == "ready"
    assert [name for name, _ in provider.calls] == ["ensure_config", "start", "health", "create_launch_session"]


def test_launch_session_requires_ready_state_and_returns_provider_url(quantum_env):
    _, _, _, _ = quantum_env
    import wpfy.file_manager as file_manager

    provider = _StubProvider(launch_path=f"/api/sites/{DOMAIN}/file-manager/proxy/")
    with pytest.raises(RuntimeError, match="file manager is not ready"):
        file_manager.launch_session(DOMAIN, "alice", provider)

    file_manager.mark_ready(DOMAIN)
    assert file_manager.launch_session(DOMAIN, "alice", provider) == {
        "url": f"/api/sites/{DOMAIN}/file-manager/proxy/"
    }


def test_mark_ready_sets_idle_expiry_and_empty_leases(quantum_env):
    _, _, _, _ = quantum_env
    import wpfy.file_manager as file_manager

    before = datetime.now(timezone.utc).timestamp()
    assert file_manager.mark_ready(DOMAIN) == {"state": "ready"}
    state = file_manager.get_file_manager_state(DOMAIN)
    expires = datetime.fromisoformat(state.idle_expires_at).timestamp()

    assert 890 <= expires - before <= 910
    assert state.lease_holders == []
    assert state.active_leases == 0


def test_warning_window_boundaries_and_invalid_states(quantum_env):
    _, _, _, _ = quantum_env
    import wpfy.file_manager as file_manager

    now = datetime.now(timezone.utc).timestamp()
    file_manager._write_state(
        DOMAIN,
        {"state": "ready", "domain": DOMAIN, "idle_expires_at": datetime.fromtimestamp(now + 60, timezone.utc).isoformat()},
    )
    assert file_manager.is_in_warning_window(DOMAIN) is True

    file_manager._write_state(
        DOMAIN,
        {"state": "ready", "domain": DOMAIN, "idle_expires_at": datetime.fromtimestamp(now + 1800, timezone.utc).isoformat()},
    )
    assert file_manager.is_in_warning_window(DOMAIN) is False

    file_manager._write_state(DOMAIN, {"state": "disabled", "domain": DOMAIN})
    assert file_manager.is_in_warning_window(DOMAIN) is False
    file_manager._write_state(DOMAIN, {"state": "ready", "domain": DOMAIN, "idle_expires_at": "corrupt"})
    assert file_manager.is_in_warning_window(DOMAIN) is False


def test_lease_without_username_keeps_holders_and_extends_expiry(quantum_env):
    _, _, _, _ = quantum_env
    import wpfy.file_manager as file_manager

    file_manager._write_state(DOMAIN, {"state": "ready", "domain": DOMAIN, "lease_holders": ["alice"]})
    before = datetime.now(timezone.utc).timestamp()
    result = file_manager.create_lease(DOMAIN)
    state = file_manager.get_file_manager_state(DOMAIN)
    expires = datetime.fromisoformat(result["idle_expires_at"]).timestamp()

    assert state.lease_holders == ["alice"]
    assert result["active_leases"] == 1
    assert expires >= before + 110


def test_enable_rejects_nonexistent_site_with_error_code(quantum_env):
    _, _, _, _ = quantum_env
    import wpfy.file_manager as file_manager

    with pytest.raises(file_manager.FileManagerError) as raised:
        file_manager.enable_file_manager("missing.example.com", "alice", _StubProvider())

    assert raised.value.code == "site_not_found"


def test_enable_rejects_missing_app_directory_with_error_code(quantum_env):
    paths, site, _, _ = quantum_env
    import wpfy.file_manager as file_manager

    (site / "app").rmdir()
    with pytest.raises(file_manager.FileManagerError) as raised:
        file_manager.enable_file_manager(DOMAIN, "alice", _StubProvider())

    assert raised.value.code == "app_dir_missing"
    assert Path(paths.sites_dir, DOMAIN).exists()


def test_active_leases_are_derived_from_distinct_holders(quantum_env):
    _, _, _, _ = quantum_env
    import wpfy.file_manager as file_manager

    file_manager._write_state(DOMAIN, {"state": "ready", "domain": DOMAIN})
    file_manager.create_lease(DOMAIN, "alice")
    file_manager.create_lease(DOMAIN, "bob")

    state = file_manager.get_file_manager_state(DOMAIN)
    assert state.lease_holders == ["alice", "bob"]
    assert state.active_leases == 2


def test_quantum_launch_session_uses_proxy_path(quantum_env):
    _, _, _, quantum = quantum_env

    assert quantum.create_launch_session(DOMAIN, "alice") == f"/api/sites/{DOMAIN}/file-manager/proxy/"


def test_create_lease_concurrent_calls_preserve_all_holders(quantum_env):
    _, _, _, _ = quantum_env
    import wpfy.file_manager as file_manager

    file_manager._write_state(DOMAIN, {"state": "ready", "domain": DOMAIN, "lease_holders": []})

    usernames = [f"user-{i}" for i in range(20)]
    barrier = threading.Barrier(len(usernames))

    def lease(name: str) -> None:
        barrier.wait()
        file_manager.create_lease(DOMAIN, name)

    threads = [threading.Thread(target=lease, args=(name,)) for name in usernames]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    state = file_manager.get_file_manager_state(DOMAIN)
    assert sorted(state.lease_holders) == sorted(usernames)
    assert state.active_leases == len(usernames)


def test_mark_ready_preserves_prior_enabled_at(quantum_env):
    _, _, _, _ = quantum_env
    import wpfy.file_manager as file_manager

    original = "2026-01-01T00:00:00+00:00"
    file_manager._write_state(
        DOMAIN, {"state": "starting", "domain": DOMAIN, "enabled_at": original, "lease_holders": []},
    )

    file_manager.mark_ready(DOMAIN)

    state = file_manager.get_file_manager_state(DOMAIN)
    assert state.state == "ready"
    assert state.enabled_at == original

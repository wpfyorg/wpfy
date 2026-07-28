from __future__ import annotations

from pathlib import Path
import subprocess

import pytest

from wpfy import site_database


ROOT_PASSWORD = "root-secret-test"


def _seed(paths, domain="example.com"):
    site = Path(paths.sites_dir) / domain
    site.mkdir(parents=True)
    (site / ".env").write_text(
        f"DOMAIN={domain}\nSITE_FLAVOR=wp\nDB_ROOT_PASSWORD={ROOT_PASSWORD}\n",
        encoding="utf-8",
    )
    (site / "compose.yaml").write_text("services: {}\n", encoding="utf-8")
    return site


def test_identifiers_are_rejected_before_compose(tmp_wpfy_home, monkeypatch):
    _seed(tmp_wpfy_home)
    calls = []
    monkeypatch.setattr(site_database, "compose_command", lambda *args, **kwargs: calls.append(args))

    with pytest.raises(ValueError):
        site_database.create_database("example.com", "bad;drop")
    with pytest.raises(ValueError):
        site_database.create_user("example.com", "bad-user", password="secret")
    with pytest.raises(ValueError):
        site_database.grant("example.com", "good_user", "bad.database")
    assert calls == []


@pytest.mark.parametrize("name", ("information_schema", "performance_schema", "mysql", "sys"))
def test_system_databases_are_rejected_on_every_database_name_path(tmp_wpfy_home, monkeypatch, name):
    _seed(tmp_wpfy_home)
    calls = []
    monkeypatch.setattr(site_database, "compose_command", lambda *args, **kwargs: calls.append(args))

    with pytest.raises(ValueError):
        site_database.create_database("example.com", name)
    with pytest.raises(ValueError):
        site_database.drop_database("example.com", name)
    with pytest.raises(ValueError):
        site_database.create_user("example.com", "wp_user", password="secret", grants=[name])
    with pytest.raises(ValueError):
        site_database.grant("example.com", "wp_user", name)
    assert calls == []


def test_database_sql_uses_stdin_and_in_container_root_secret(tmp_wpfy_home, monkeypatch):
    _seed(tmp_wpfy_home)
    calls = []

    def fake_compose(domain, *args, input_text=None):
        calls.append((domain, args, input_text))
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(site_database, "compose_command", fake_compose)
    monkeypatch.setattr(site_database, "docker_available", lambda: True)

    result = site_database.create_database("example.com", "wp_extra")

    assert result.exit_code == 0
    assert calls[0][1][-1] == 'exec mariadb -N -B -uroot -p"$MARIADB_ROOT_PASSWORD"'
    assert "CREATE DATABASE IF NOT EXISTS `wp_extra`" in calls[0][2]
    assert ROOT_PASSWORD not in calls[0][2]
    assert ROOT_PASSWORD not in " ".join(str(item) for item in calls[0][1])


def test_user_creation_and_grant_are_idempotent_and_scoped(tmp_wpfy_home, monkeypatch):
    _seed(tmp_wpfy_home)
    sql = []

    def fake_compose(domain, *args, input_text=None):
        sql.append(input_text)
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(site_database, "compose_command", fake_compose)
    monkeypatch.setattr(site_database, "docker_available", lambda: True)

    assert site_database.create_user("example.com", "wp_user", password="user-pass", grants="wp_extra").exit_code == 0
    assert site_database.drop_user("example.com", "wp_user").exit_code == 0
    assert site_database.grant("example.com", "wp_user", "wp_extra").exit_code == 0

    assert "CREATE USER IF NOT EXISTS 'wp_user'@'%'" in sql[0]
    assert "GRANT ALL PRIVILEGES ON `wp_extra`.* TO 'wp_user'@'%'" in sql[0]
    assert "DROP USER IF EXISTS 'wp_user'@'%'" in sql[1]
    assert "GRANT ALL PRIVILEGES ON `wp_extra`.* TO 'wp_user'@'%'" in sql[2]


@pytest.mark.parametrize("operation", ("create", "set"))
def test_database_user_failure_redacts_every_password_occurrence(tmp_wpfy_home, monkeypatch, operation):
    _seed(tmp_wpfy_home)
    password = "Leak-Me-9f3c2a"

    def fake_compose(domain, *args, input_text=None):
        return subprocess.CompletedProcess(
            args,
            1,
            "",
            f"syntax error near {input_text.strip()!r}; repeated password: {password}",
        )

    monkeypatch.setattr(site_database, "compose_command", fake_compose)
    monkeypatch.setattr(site_database, "docker_available", lambda: True)

    if operation == "create":
        result = site_database.create_user("example.com", "wp_user", password=password)
    else:
        result = site_database.set_user_password("example.com", "wp_user", password=password)

    assert result.exit_code != 0
    assert password not in result.message
    assert result.message.count("***REDACTED***") >= 2


def test_generated_password_is_returned_only_as_one_time_value(tmp_wpfy_home, monkeypatch):
    _seed(tmp_wpfy_home)

    monkeypatch.setattr(
        site_database,
        "compose_command",
        lambda domain, *args, input_text=None: subprocess.CompletedProcess(args, 0, "", ""),
    )
    monkeypatch.setattr(site_database, "docker_available", lambda: True)

    result = site_database.create_user("example.com", "wp_user")

    assert result.exit_code == 0
    assert result.one_time_password
    assert result.one_time_password not in result.message

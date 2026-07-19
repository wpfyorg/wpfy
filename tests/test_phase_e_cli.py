from __future__ import annotations

import argparse
import io

from wpfy import cli


def test_required_secret_reads_one_crlf_line(monkeypatch):
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("secret\r\nsecond\n"))

    secret, error = cli._required_secret(
        True,
        prompt="unused",
        stdin_error="missing",
        tty_error="tty",
        empty_error="empty",
    )

    assert (secret, error) == ("secret", None)
    assert cli.sys.stdin.readline() == "second\n"


def test_required_secret_preserves_exact_empty_and_non_tty_errors(monkeypatch):
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("\n"))
    assert cli._secret_from_args(argparse.Namespace(secret_key_stdin=True))[1] == cli.CommandResult(
        "secret key required on stdin",
        exit_code=2,
    )

    stdin = io.StringIO()
    monkeypatch.setattr(stdin, "isatty", lambda: False)
    monkeypatch.setattr(cli.sys, "stdin", stdin)
    assert cli._smtp_password_from_args(argparse.Namespace(password_stdin=False))[1] == cli.CommandResult(
        "SMTP password prompt requires a TTY; use --password-stdin for scripts",
        exit_code=2,
    )


def test_config_password_remains_optional():
    assert cli._config_password(argparse.Namespace(password=False, password_stdin=False)) == (None, None)


def test_healthcheck_aggregate_uses_named_defaults(monkeypatch):
    calls = []
    monkeypatch.setattr(
        cli,
        "_healthcheck_disk",
        lambda *args: calls.append(("disk", args)) or cli.CommandResult("disk"),
    )
    monkeypatch.setattr(
        cli,
        "_healthcheck_load",
        lambda *args: calls.append(("load", args)) or cli.CommandResult("load"),
    )
    monkeypatch.setattr(cli, "_healthcheck_system", lambda: cli.CommandResult("system"))
    monkeypatch.setattr(cli, "_healthcheck_all_sites", lambda: cli.CommandResult("sites"))

    cli.handle_healthcheck(argparse.Namespace(health_target="all"))

    assert calls == [("disk", ("/", *cli.DISK_THRESHOLDS)), ("load", cli.LOAD_THRESHOLDS)]

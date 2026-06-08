from __future__ import annotations

import importlib
import json
import stat

import pytest
from wpfy.cli import build_parser, run


def test_build_parser_returns_parser():
    parser = build_parser()
    assert parser is not None


def test_parser_has_expected_subcommands():
    parser = build_parser()
    subparsers_actions = [action for action in parser._actions if hasattr(action, 'choices')]
    subcommand_names = []
    for action in subparsers_actions:
        if action.choices:
            subcommand_names.extend(action.choices.keys())
    assert "site" in subcommand_names
    assert "stack" in subcommand_names


def test_help_exits_zero():
    with pytest.raises(SystemExit) as exc_info:
        run(["--help"])
    assert exc_info.value.code == 0


def test_help_shows_examples_and_description(capsys):
    with pytest.raises(SystemExit) as exc_info:
        run(["--help"])
    output = capsys.readouterr().out

    assert exc_info.value.code == 0
    assert "Docker-first CLI for WordPress and server administration." in output
    assert "Examples:" in output
    assert "wpfy site create example.com --wp" in output


def test_site_subcommand_exists():
    with pytest.raises(SystemExit) as exc_info:
        run(["site", "--help"])
    assert exc_info.value.code == 0


def test_site_create_help_shows_examples(capsys):
    with pytest.raises(SystemExit) as exc_info:
        run(["site", "create", "--help"])
    output = capsys.readouterr().out

    assert exc_info.value.code == 0
    assert "Create a site, bootstrap its filesystem, and optionally provision WordPress." in output
    assert "WordPress administrator password" in output
    assert "Examples:" in output


def test_stack_subcommand_exists():
    with pytest.raises(SystemExit) as exc_info:
        run(["stack", "--help"])
    assert exc_info.value.code == 0


def test_stack_install_help_shows_examples(capsys):
    with pytest.raises(SystemExit) as exc_info:
        run(["stack", "install", "--help"])
    output = capsys.readouterr().out

    assert exc_info.value.code == 0
    assert "Pull the Docker images needed by wpfy and start the shared edge proxy." in output
    assert "Examples:" in output
    assert "wpfy stack install --all" in output


def test_secure_command_exists():
    with pytest.raises(SystemExit) as exc_info:
        run(["secure", "--help"])
    assert exc_info.value.code == 0


def test_maintenance_command_exists():
    with pytest.raises(SystemExit) as exc_info:
        run(["maintenance", "--help"])
    assert exc_info.value.code == 0


def test_update_command_exists():
    with pytest.raises(SystemExit) as exc_info:
        run(["update", "--help"])
    assert exc_info.value.code == 0


def test_site_wp_command_exists():
    with pytest.raises(SystemExit) as exc_info:
        run(["site", "wp", "--help"])
    assert exc_info.value.code == 0


def test_secure_parser_in_build():
    parser = build_parser()
    subparsers = [a for a in parser._actions if hasattr(a, 'choices')]
    commands = set()
    for sp in subparsers:
        if sp.choices:
            commands.update(sp.choices.keys())
    assert "secure" in commands
    assert "maintenance" in commands
    assert "update" in commands


def test_site_wp_parser_has_domain():
    parser = build_parser()
    for action in parser._actions:
        if hasattr(action, 'choices') and "site" in (action.choices or {}):
            site = action.choices["site"]
            for sa in site._actions:
                if hasattr(sa, 'choices') and "wp" in (sa.choices or {}):
                    wp_parser = sa.choices["wp"]
                    args = [a.dest for a in wp_parser._actions if a.dest != "help"]
                    assert "domain" in args
                    assert "wp_args" in args
                    return
    pytest.fail("site wp parser not found")


def test_site_update_parser_has_flags():
    parser = build_parser()
    for action in parser._actions:
        if hasattr(action, 'choices') and "site" in (action.choices or {}):
            site = action.choices["site"]
            for sa in site._actions:
                if hasattr(sa, 'choices') and "update" in (sa.choices or {}):
                    update_parser = sa.choices["update"]
                    args = [a.dest for a in update_parser._actions if a.dest != "help"]
                    assert "domain" in args
                    assert "wpredis" in args
                    assert "wpfc" in args
                    assert "letsencrypt" in args
                    return
    pytest.fail("site update parser not found")


def test_site_create_parser_has_wordpress_admin_flags():
    parser = build_parser()
    for action in parser._actions:
        if hasattr(action, 'choices') and "site" in (action.choices or {}):
            site = action.choices["site"]
            for sa in site._actions:
                if hasattr(sa, 'choices') and "create" in (sa.choices or {}):
                    create_parser = sa.choices["create"]
                    args = [a.dest for a in create_parser._actions if a.dest != "help"]
                    assert "wp_user" in args
                    assert "wp_email" in args
                    assert "wp_password" in args
                    return
    pytest.fail("site create parser not found")


def test_php_parsers_accept_84_and_default_to_84():
    parser = build_parser()

    create_args = parser.parse_args(["site", "create", "example.com", "--wp"])
    assert create_args.php == "8.4"

    assert parser.parse_args(["site", "create", "example.com", "--php", "8.4"]).php == "8.4"
    assert parser.parse_args(["site", "update", "example.com", "--php", "8.4"]).php == "8.4"
    assert parser.parse_args(["stack", "install", "--php"]).php == "8.4"
    assert parser.parse_args(["stack", "install", "--php", "8.4"]).php == "8.4"


def test_site_create_default_php_version_is_84(monkeypatch):
    import wpfy.cli as cli

    captured = {}
    def fake_create(request, **kwargs):
        captured["request"] = request
        return cli.site_lifecycle.CreateSiteResult(
            spec=cli.site_lifecycle.SiteSpec(
                request.domain, request.flavor, True, False, php_version=request.php_version
            ),
            touched=(),
            bootstrap=cli.site_lifecycle.RuntimeResult(0, "ok", ran=True),
            runtime=cli.site_lifecycle.RuntimeResult(0, "started", ran=True),
            wordpress_message="installed",
        )

    monkeypatch.setattr(cli.site_lifecycle, "create_site", fake_create)

    result = cli.run(["site", "create", "example.com", "--wp"])

    assert result == 0
    assert captured["request"].php_version == "8.4"


def test_stack_install_php_flag_pulls_default_84(monkeypatch, capsys):
    import wpfy.cli as cli

    calls = []

    class Proc:
        returncode = 0
        stdout = "ok"
        stderr = ""

    def fake_run(cmd, *args, **kwargs):
        calls.append(cmd)
        return Proc()

    monkeypatch.setattr(cli.subprocess, "run", fake_run)

    result = cli.run(["stack", "install", "--php"])
    output = capsys.readouterr().out

    assert result == 0
    assert ["docker", "pull", "ghcr.io/wpfyorg/php-fpm:8.4"] in calls
    assert not any(cmd[:2] == ["docker", "build"] for cmd in calls)
    assert "=== stack install ===" in output
    assert "PHP 8.4: OK pulled ghcr.io/wpfyorg/php-fpm:8.4" in output


def test_stack_install_explicit_php_pulls_only_requested_version(monkeypatch):
    import wpfy.cli as cli

    calls = []

    class Proc:
        returncode = 0
        stdout = "ok"
        stderr = ""

    def fake_run(cmd, *args, **kwargs):
        calls.append(cmd)
        return Proc()

    monkeypatch.setattr(cli.subprocess, "run", fake_run)

    result = cli.run(["stack", "install", "--php", "8.3"])

    assert result == 0
    assert calls == [["docker", "pull", "ghcr.io/wpfyorg/php-fpm:8.3"]]


def test_stack_install_all_pulls_only_default_php(monkeypatch):
    import wpfy.cli as cli
    from wpfy.site_layout import RuntimeResult

    calls = []

    class Proc:
        returncode = 0
        stdout = "ok"
        stderr = ""

    def fake_run(cmd, *args, **kwargs):
        calls.append(cmd)
        return Proc()

    monkeypatch.setattr(cli.traefik, "start_traefik", lambda: RuntimeResult(0, "started", ran=True))
    monkeypatch.setattr(cli.subprocess, "run", fake_run)

    result = cli.run(["stack", "install", "--all"])
    pulled = [cmd for cmd in calls if cmd[:2] == ["docker", "pull"]]

    assert result == 0
    assert ["docker", "pull", "ghcr.io/wpfyorg/php-fpm:8.4"] in pulled
    assert ["docker", "pull", "ghcr.io/wpfyorg/php-fpm:8.2"] not in pulled
    assert ["docker", "pull", "ghcr.io/wpfyorg/php-fpm:8.3"] not in pulled
    assert not any(cmd[:2] == ["docker", "build"] for cmd in calls)


def test_stack_install_shows_tty_progress(monkeypatch, capsys):
    import wpfy.cli as cli
    from wpfy.site_layout import RuntimeResult

    class Proc:
        returncode = 0
        stdout = "ok"
        stderr = ""

    monkeypatch.setattr(cli.sys.stderr, "isatty", lambda: True)
    monkeypatch.setattr(cli.traefik, "start_traefik", lambda: RuntimeResult(0, "started", ran=True))
    monkeypatch.setattr(cli.subprocess, "run", lambda *args, **kwargs: Proc())

    result = cli.run(["stack", "install", "--all"])
    progress = capsys.readouterr().err

    assert result == 0
    assert "Starting shared Traefik edge proxy..." in progress
    assert "Pulling PHP 8.4 runtime image..." in progress
    assert "Pulling MariaDB 11.4 image..." in progress
    assert "Pulling Redis 7 image..." in progress


def test_stack_install_php_pull_failure_exits_nonzero(monkeypatch, capsys):
    import wpfy.cli as cli

    class Proc:
        returncode = 1
        stdout = ""
        stderr = "manifest unknown"

    monkeypatch.setattr(cli.subprocess, "run", lambda *args, **kwargs: Proc())

    result = cli.run(["stack", "install", "--php"])
    output = capsys.readouterr().out

    assert result == 1
    assert "=== stack install ===" in output
    assert "PHP 8.4: FAIL error: manifest unknown" in output


def test_wordpress_credentials_use_git_defaults_non_interactive(monkeypatch):
    import argparse
    import wpfy.cli as cli

    class Proc:
        def __init__(self, returncode=0, stdout=""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = ""

    def fake_run(cmd, *args, **kwargs):
        if cmd == ["git", "config", "--get", "user.name"]:
            return Proc(stdout="Jane Developer\n")
        if cmd == ["git", "config", "--get", "user.email"]:
            return Proc(stdout="jane@example.com\n")
        return Proc(returncode=1)

    monkeypatch.setattr(cli.subprocess, "run", fake_run)
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: False)
    monkeypatch.setattr(cli, "generated_secret", lambda: "generated-password")

    creds = cli._resolve_wp_admin_credentials(
        argparse.Namespace(wp_user=None, wp_email=None, wp_password=None),
        "example.com",
    )

    assert creds.user == "jane-developer"
    assert creds.email == "jane@example.com"
    assert creds.password == "generated-password"
    assert creds.password_generated is True


def test_site_create_prints_generated_wordpress_password_only_for_new_install(tmp_wpfy_home, monkeypatch, capsys):
    import wpfy.cli as cli

    monkeypatch.setattr(
        cli.site_lifecycle,
        "create_site",
        lambda request, **kwargs: cli.site_lifecycle.CreateSiteResult(
            spec=cli.site_lifecycle.SiteSpec(request.domain, request.flavor, True, False),
            touched=("/tmp/compose.yaml",),
            bootstrap=cli.site_lifecycle.RuntimeResult(0, "wordpress files already bootstrapped", ran=True),
            runtime=cli.site_lifecycle.RuntimeResult(0, "started", ran=True),
            wordpress_message="wordpress installed",
            wordpress_admin_user="admin",
            generated_password="generated-password",
        ),
    )

    result = cli.run(["site", "create", "example.com", "--wp"])
    output = capsys.readouterr().out

    assert result == 0
    assert "=== Site created ===" in output
    assert "Site created" in output
    assert "domain: example.com" in output
    assert "site type: wordpress" in output
    assert "scaffold: updated 1 paths" in output
    assert "bootstrap: OK wordpress files already bootstrapped" in output
    assert "runtime: OK started" in output
    assert "wordpress: wordpress installed" in output
    assert "generated password: generated-password" in output
    assert "next: sign in at https://example.com/wp-admin" in output


def test_site_create_does_not_print_password_for_existing_wordpress_install(monkeypatch, capsys):
    import wpfy.cli as cli

    monkeypatch.setattr(
        cli.site_lifecycle,
        "create_site",
        lambda request, **kwargs: cli.site_lifecycle.CreateSiteResult(
            spec=cli.site_lifecycle.SiteSpec(request.domain, request.flavor, True, False),
            touched=(),
            bootstrap=cli.site_lifecycle.RuntimeResult(0, "wordpress files already bootstrapped", ran=True),
            runtime=cli.site_lifecycle.RuntimeResult(0, "started", ran=True),
            wordpress_message="wordpress already installed",
        ),
    )

    result = cli.run(["site", "create", "example.com", "--wp", "--pass", "do-not-print"])
    output = capsys.readouterr().out

    assert result == 0
    assert "do-not-print" not in output
    assert "Site already up to date" in output
    assert "scaffold: unchanged" in output
    assert "wordpress: wordpress already installed" in output
    assert "next: sign in at https://example.com/wp-admin" in output


def test_site_create_shows_progress_updates_on_tty(monkeypatch, capsys):
    import wpfy.cli as cli

    monkeypatch.setattr(cli.sys.stderr, "isatty", lambda: True)
    def fake_create(request, **kwargs):
        for step in ("scaffold", "bootstrap", "runtime", "wordpress-provision"):
            kwargs["progress"](step)
        return cli.site_lifecycle.CreateSiteResult(
            spec=cli.site_lifecycle.SiteSpec(request.domain, request.flavor, True, False),
            touched=("/tmp/compose.yaml",),
            bootstrap=cli.site_lifecycle.RuntimeResult(0, "bootstrapped", ran=True),
            runtime=cli.site_lifecycle.RuntimeResult(0, "started", ran=True),
            wordpress_message="wordpress installed",
        )

    monkeypatch.setattr(cli.site_lifecycle, "create_site", fake_create)

    result = cli.run(["site", "create", "example.com", "--wp"])
    captured = capsys.readouterr()

    assert result == 0
    assert "Writing site scaffold..." in captured.err
    assert "Bootstrapping site files..." in captured.err
    assert "Starting site runtime..." in captured.err
    assert "Provisioning WordPress core and admin user. This can take a few seconds..." in captured.err


def test_site_create_wpfc_includes_cache_next_step(monkeypatch, capsys):
    import wpfy.cli as cli

    monkeypatch.setattr(
        cli.site_lifecycle,
        "create_site",
        lambda request, **kwargs: cli.site_lifecycle.CreateSiteResult(
            spec=cli.site_lifecycle.SiteSpec(request.domain, request.flavor, True, False),
            touched=("/tmp/compose.yaml",),
            bootstrap=cli.site_lifecycle.RuntimeResult(0, "bootstrapped", ran=True),
            runtime=cli.site_lifecycle.RuntimeResult(0, "started", ran=True),
            wordpress_message="wordpress already installed",
        ),
    )

    result = cli.run(["site", "create", "cache.example.com", "--wpfc"])
    output = capsys.readouterr().out

    assert result == 0
    assert "site type: wordpress" in output
    assert "next: sign in at https://cache.example.com/wp-admin" in output
    assert "next: install and activate the matching cache plugin in WordPress" in output


def test_site_status_uses_human_friendly_summary(monkeypatch, capsys):
    import wpfy.cli as cli
    from wpfy.site_layout import HealthResult

    domain = "status.example.com"

    monkeypatch.setattr(cli, "site_exists", lambda value: True)
    monkeypatch.setattr(
        cli,
        "site_info",
        lambda value: {
            "domain": domain,
            "flavor": "wp",
            "path": f"/opt/wpfy/sites/{domain}",
            "compose": f"/opt/wpfy/sites/{domain}/compose.yaml",
        },
    )
    monkeypatch.setattr(
        cli,
        "site_health",
        lambda value: HealthResult(domain, True, True, True, True, "ready", "web=1 app=1 db=1 redis=0 http=ok"),
    )

    result = cli.run(["site", "status", domain])
    output = capsys.readouterr().out

    assert result == 0
    assert f"=== site status: {domain} ===" in output
    assert "status: ready" in output
    assert "scaffold: yes" in output
    assert "bootstrap: yes" in output
    assert "runtime: yes" in output
    assert "http: yes" in output
    assert "summary: web=1 app=1 db=1 redis=0 http=ok" in output


def test_parser_has_info_command():
    parser = build_parser()
    subparsers = [a for a in parser._actions if hasattr(a, 'choices')]
    commands = set()
    for sp in subparsers:
        if sp.choices:
            commands.update(sp.choices.keys())
    assert "info" in commands
    assert "clean" in commands


def test_site_delete_missing_returns_clean_error(tmp_wpfy_home, monkeypatch):
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")

    result = run(["site", "delete", "missing.example.com", "--force"])

    assert result == 2


def test_site_ssl_preflight_only_failure_exits_nonzero(monkeypatch):
    import wpfy.cli
    from wpfy.certificate_lifecycle import SSLPreflightResult

    monkeypatch.setattr(
        wpfy.cli,
        "preflight_ssl",
        lambda domain: SSLPreflightResult(domain, (), (), ("203.0.113.10",), (), False, "preflight failed"),
    )

    result = wpfy.cli.run(["site", "ssl", "bad.example.com", "--letsencrypt", "--preflight-only"])

    assert result == 2


def test_site_create_proxied_preflight_sets_spec_proxied(monkeypatch):
    import wpfy.cli as cli

    captured = {}
    def fake_create(request, **kwargs):
        captured["request"] = request
        return cli.site_lifecycle.CreateSiteResult(
            spec=cli.site_lifecycle.SiteSpec(request.domain, request.flavor, True, False, proxied=True),
            touched=(),
            bootstrap=cli.site_lifecycle.RuntimeResult(0, "ok", ran=True),
            runtime=cli.site_lifecycle.RuntimeResult(0, "started", ran=True),
        )

    monkeypatch.setattr(cli.site_lifecycle, "create_site", fake_create)

    result = cli.run(["site", "create", "example.com", "--wp", "--letsencrypt"])

    assert result == 0
    assert captured["request"].proxied_override is None


def test_site_create_no_proxied_override_forces_direct(monkeypatch):
    import wpfy.cli as cli

    captured = {}
    def fake_create(request, **kwargs):
        captured["request"] = request
        return cli.site_lifecycle.CreateSiteResult(
            spec=cli.site_lifecycle.SiteSpec(request.domain, request.flavor, True, False),
            touched=(),
            bootstrap=cli.site_lifecycle.RuntimeResult(0, "ok", ran=True),
            runtime=cli.site_lifecycle.RuntimeResult(0, "started", ran=True),
        )

    monkeypatch.setattr(cli.site_lifecycle, "create_site", fake_create)

    result = cli.run(["site", "create", "example.com", "--wp", "--letsencrypt", "--no-proxied"])

    assert result == 0
    assert captured["request"].proxied_override is False


def test_debug_reports_issued_cert_with_unknown_expiry(tmp_wpfy_home, monkeypatch):
    import subprocess
    from pathlib import Path

    import wpfy.cli as cli
    import wpfy.site_layout as site_layout
    from wpfy.site_layout import RuntimeResult

    domain = "example.com"
    monkeypatch.setattr(cli.operational_inspection, "PATHS", tmp_wpfy_home)
    site_root = Path(tmp_wpfy_home.sites_dir) / domain
    site_root.mkdir(parents=True)
    (site_root / "compose.yaml").write_text("services: {}\n", encoding="utf-8")

    class Proc:
        returncode = 0
        stdout = "{}"
        stderr = ""

    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: Proc())
    monkeypatch.setattr(site_layout, "_http_probe_site", lambda domain: RuntimeResult(0, "http probe passed", ran=True))
    monkeypatch.setattr(cli.operational_inspection, "get_cert_info", lambda domain: {"status": "issued"})
    monkeypatch.setattr(cli.operational_inspection, "cert_expiry_days", lambda domain: None)
    monkeypatch.setattr(cli.operational_inspection, "site_info", lambda domain: {"flavor": "html"})

    checks = cli.operational_inspection.site_diagnostics(domain)

    assert any(
        check.name == "ssl expiry"
        and check.ok is None
        and check.message == "certificate found; expiry unavailable"
        for check in checks
    )


def test_secure_fails_on_loose_env_permissions(tmp_wpfy_home, monkeypatch, capsys):
    import wpfy.cli
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    importlib.reload(wpfy.cli)

    class Proc:
        returncode = 1
        stdout = ""
        stderr = ""

    monkeypatch.setattr(wpfy.cli.operational_inspection.subprocess, "run", lambda *args, **kwargs: Proc())
    spec = wpfy.site_layout.SiteSpec(domain="loose.example.com", flavor="html", use_mysql=False, use_redis=False)
    wpfy.site_layout.ensure_site_scaffold(spec)
    wpfy.site_layout.env_path("loose.example.com").chmod(0o644)

    result = wpfy.cli.run(["secure", "loose.example.com"])
    output = capsys.readouterr().out

    assert result == 1
    assert "[FAIL] .env: perms 0o644 (expected 0o600)" in output


def test_secure_passes_on_private_env_permissions(tmp_wpfy_home, monkeypatch, capsys):
    import wpfy.cli
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    importlib.reload(wpfy.cli)

    class Proc:
        returncode = 1
        stdout = ""
        stderr = ""

    monkeypatch.setattr(wpfy.cli.operational_inspection.subprocess, "run", lambda *args, **kwargs: Proc())
    spec = wpfy.site_layout.SiteSpec(domain="private.example.com", flavor="html", use_mysql=False, use_redis=False)
    wpfy.site_layout.ensure_site_scaffold(spec)

    result = wpfy.cli.run(["secure", "private.example.com"])
    output = capsys.readouterr().out

    assert result == 0
    assert "[PASS] .env: perms 0o600" in output
    assert "result: PASS" in output
    assert stat.S_IMODE(wpfy.site_layout.env_path("private.example.com").stat().st_mode) == 0o600


def test_secure_warns_on_sftp_host_port_without_secret_output(tmp_wpfy_home, monkeypatch, capsys):
    import wpfy.cli
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    importlib.reload(wpfy.cli)

    domain = "sftp-secure.example.com"
    project = wpfy.site_layout.domain_to_project(domain)

    class Proc:
        def __init__(self, returncode=1, stdout="", stderr=""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    def fake_run(cmd, *args, **kwargs):
        if cmd[:2] == ["docker", "inspect"] and cmd[-1] == f"{project}-sftp":
            return Proc(0, json.dumps([{
                "HostConfig": {
                    "Privileged": False,
                    "PortBindings": {"22/tcp": [{"HostIp": "127.0.0.1", "HostPort": "2222"}]},
                },
                "Config": {"User": "1000"},
            }]))
        return Proc()

    monkeypatch.setattr(wpfy.cli.operational_inspection.subprocess, "run", fake_run)
    spec = wpfy.site_layout.SiteSpec(domain=domain, flavor="html", use_mysql=False, use_redis=False)
    wpfy.site_layout.ensure_site_scaffold(spec)

    result = wpfy.cli.run(["secure", domain])
    output = capsys.readouterr().out

    assert result == 0
    assert f"[WARN] {project}-sftp: host port bindings: 22/tcp" in output
    assert "SFTP_PASSWORD" not in output
    assert "secret" not in output


def test_secure_reports_container_hardening_baseline(tmp_wpfy_home, monkeypatch, capsys):
    import wpfy.cli
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    importlib.reload(wpfy.cli)

    domain = "hardened.example.com"
    project = wpfy.site_layout.domain_to_project(domain)

    class Proc:
        def __init__(self, returncode=1, stdout="", stderr=""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    def fake_run(cmd, *args, **kwargs):
        if cmd[:2] == ["docker", "inspect"] and cmd[-1] == f"{project}-web":
            return Proc(0, json.dumps([{
                "HostConfig": {
                    "Privileged": False,
                    "SecurityOpt": ["no-new-privileges:true"],
                    "CapDrop": ["NET_RAW"],
                    "PidsLimit": 256,
                    "Memory": 268435456,
                    "LogConfig": {
                        "Type": "json-file",
                        "Config": {"max-size": "10m", "max-file": "3"},
                    },
                    "PortBindings": {},
                },
                "Config": {"User": "101"},
            }]))
        return Proc()

    monkeypatch.setattr(wpfy.cli.operational_inspection.subprocess, "run", fake_run)
    spec = wpfy.site_layout.SiteSpec(domain=domain, flavor="html", use_mysql=False, use_redis=False)
    wpfy.site_layout.ensure_site_scaffold(spec)

    result = wpfy.cli.run(["secure", domain])
    output = capsys.readouterr().out

    assert result == 0
    assert f"[PASS] {project}-web: no-new-privileges enabled" in output
    assert f"[PASS] {project}-web: raw network capability dropped" in output
    assert f"[PASS] {project}-web: pids_limit=256" in output
    assert f"[PASS] {project}-web: memory limit configured" in output
    assert f"[PASS] {project}-web: log rotation configured" in output

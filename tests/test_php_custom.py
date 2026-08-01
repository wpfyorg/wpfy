from __future__ import annotations

from wpfy import cli
from wpfy import site_configuration as configuration
from wpfy import site_layout as layout
from wpfy import site_runtime as runtime


class Proc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _site(domain: str) -> None:
    layout.ensure_site_scaffold(layout.SiteSpec(domain=domain, flavor="wp", use_mysql=True, use_redis=False))


def test_php_validation_uses_php_output_and_removes_candidate(tmp_wpfy_home, monkeypatch):
    domain = "php-validation.example.com"
    _site(domain)
    php_root = layout.php_dir(domain)
    monkeypatch.setattr(layout, "runtime_skip_requested", lambda: False)
    monkeypatch.setattr(layout, "docker_available", lambda: True)
    monkeypatch.setattr(
        layout,
        "compose_command",
        lambda *args: Proc(stderr="PHP: syntax error, unexpected end of file in zzz-custom.ini on line 2"),
    )

    result = layout.validate_php_custom(domain, 'upload_max_filesize = "64M\n')

    assert result.exit_code == 1
    assert not list(php_root.glob("*.candidate"))


def test_php_restart_refuses_only_definite_php_syntax_errors(monkeypatch):
    calls = []
    monkeypatch.setattr(configuration, "runtime_skip_requested", lambda: False)
    monkeypatch.setattr(configuration, "docker_available", lambda: True)
    monkeypatch.setattr(configuration, "compose_command", lambda *args: calls.append(args) or Proc())

    monkeypatch.setattr(
        configuration,
        "validate_php_custom",
        lambda domain: runtime.RuntimeResult(1, "PHP: syntax error in zzz-custom.ini"),
    )
    refused = configuration._restart_php_services("example.com")

    assert refused.exit_code == 1
    assert refused.message == "PHP restart refused: PHP: syntax error in zzz-custom.ini"
    assert calls == []

    for exit_code in (2, 3):
        monkeypatch.setattr(
            configuration,
            "validate_php_custom",
            lambda domain, exit_code=exit_code: runtime.RuntimeResult(exit_code, "could not check"),
        )
        assert configuration._restart_php_services("example.com").exit_code == 0

    assert calls == [
        ("example.com", "up", "-d", "--force-recreate", "app", "web"),
        ("example.com", "up", "-d", "--force-recreate", "app", "web"),
    ]


def test_site_php_validate_cli(monkeypatch, capsys):
    monkeypatch.setattr(
        cli,
        "validate_php_custom",
        lambda domain: runtime.RuntimeResult(3, f"Docker unavailable for {domain}"),
    )

    exit_code = cli.run(["site", "php", "example.com", "validate"])

    assert exit_code == 3
    assert "Docker unavailable" in capsys.readouterr().out

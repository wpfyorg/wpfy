from __future__ import annotations

import importlib
from pathlib import Path

import pytest


@pytest.mark.parametrize(
    ("module_name", "filename", "loader_name", "error_name", "cli_args"),
    [
        ("wpfy.smtp", "smtp.env", "load_smtp_config", "SMTPConfigError", ["smtp", "status"]),
        (
            "wpfy.dns",
            "dns-cloudflare.env",
            "load_cloudflare_config",
            "DNSConfigError",
            ["dns", "cloudflare", "status"],
        ),
        (
            "wpfy.s3_backup",
            "backup-storage.env",
            "load_s3_config",
            "S3ConfigError",
            ["backup", "storage", "status"],
        ),
    ],
)
def test_secret_config_loaders_shape_symlink_errors(
    tmp_wpfy_home,
    module_name,
    filename,
    loader_name,
    error_name,
    cli_args,
    capsys,
):
    import wpfy.cli as cli

    module = importlib.import_module(module_name)
    importlib.reload(module)
    external = Path(tmp_wpfy_home.state_dir) / "external.env"
    external.parent.mkdir(parents=True, exist_ok=True)
    external.write_text("SECRET=outside\n", encoding="utf-8")
    path = Path(tmp_wpfy_home.config_dir) / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    path.symlink_to(external)

    with pytest.raises(getattr(module, error_name), match="cannot read"):
        getattr(module, loader_name)()

    assert cli.run(cli_args) == 2
    output = capsys.readouterr().out
    assert "cannot read" in output
    assert "Traceback" not in output
    assert external.read_text(encoding="utf-8") == "SECRET=outside\n"


def test_smtp_loader_trims_values_and_preserves_embedded_equals(tmp_wpfy_home):
    import wpfy.smtp as smtp

    importlib.reload(smtp)
    path = smtp.smtp_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "# comment\nWPFY_SMTP_HOST= smtp.example.test \nWPFY_SMTP_PORT= 587 \n"
        "WPFY_SMTP_SENDER= ops@example.test \nWPFY_SMTP_USERNAME= user=name \n"
        "WPFY_SMTP_PASSWORD= pass=word \nWPFY_SMTP_TLS= STARTTLS \n",
        encoding="utf-8",
    )

    config = smtp.load_smtp_config()

    assert config.host == "smtp.example.test"
    assert config.username == "user=name"
    assert config.password == "pass=word"
    assert config.tls == "starttls"

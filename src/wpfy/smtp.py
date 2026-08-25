from __future__ import annotations

from dataclasses import dataclass
from email.message import EmailMessage
import os
from pathlib import Path
import smtplib
import ssl
from typing import Final, Literal, get_args

from .redaction import redact_values
from .settings import current_paths
from .site_paths import read_env


TLSMode = Literal["starttls", "ssl", "none"]
TLS_MODES: Final = get_args(TLSMode)
CONFIG_FILENAME: Final = "smtp.env"


@dataclass(frozen=True, slots=True)
class SMTPConfig:
    host: str
    port: int
    sender: str
    username: str
    password: str
    tls: TLSMode = "starttls"


class SMTPConfigError(RuntimeError):
    pass


def smtp_config_path() -> Path:
    return Path(current_paths().config_dir) / CONFIG_FILENAME


def write_smtp_config(config: SMTPConfig) -> Path:
    path = smtp_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w", encoding="utf-8") as output:
        os.fchmod(output.fileno(), 0o600)
        output.write(
            "\n".join([
                f"WPFY_SMTP_HOST={config.host}",
                f"WPFY_SMTP_PORT={config.port}",
                f"WPFY_SMTP_SENDER={config.sender}",
                f"WPFY_SMTP_USERNAME={config.username}",
                f"WPFY_SMTP_PASSWORD={config.password}",
                f"WPFY_SMTP_TLS={config.tls}",
                "",
            ])
        )
    path.chmod(0o600)
    return path


def load_smtp_config() -> SMTPConfig:
    path = smtp_config_path()
    try:
        values = {key: value.strip() for key, value in read_env(path).items()}
    except OSError as exc:
        raise SMTPConfigError(f"cannot read SMTP config: {exc}") from exc
    if not values and not path.exists():
        raise SMTPConfigError("smtp is not configured; run `wpfy smtp set`")
    missing = [key for key in _required_keys() if not values.get(key)]
    if missing:
        raise SMTPConfigError(f"missing {', '.join(missing)}")
    tls = _parse_tls(values.get("WPFY_SMTP_TLS", "starttls"))
    return SMTPConfig(
        host=values["WPFY_SMTP_HOST"],
        port=_parse_port(values["WPFY_SMTP_PORT"]),
        sender=values["WPFY_SMTP_SENDER"],
        username=values["WPFY_SMTP_USERNAME"],
        password=values["WPFY_SMTP_PASSWORD"],
        tls=tls,
    )


def clear_smtp_config() -> None:
    path = smtp_config_path()
    if path.exists():
        path.unlink()


def smtp_status_lines(config: SMTPConfig) -> list[str]:
    return [
        f"host: {config.host}",
        f"port: {config.port}",
        f"sender: {config.sender}",
        "username: configured",
        "password: configured",
        f"tls: {config.tls}",
    ]


def send_test_message(config: SMTPConfig, recipient: str, *, dry_run: bool = False) -> str:
    if not recipient or "@" not in recipient:
        raise SMTPConfigError("valid --to address required")
    if dry_run:
        return f"dry-run: validated SMTP config for {recipient}"

    message = EmailMessage()
    message["From"] = config.sender
    message["To"] = recipient
    message["Subject"] = "wpfy SMTP test"
    message.set_content("wpfy SMTP test message\n")

    context = ssl.create_default_context()
    if config.tls == "ssl":
        with smtplib.SMTP_SSL(config.host, config.port, timeout=15, context=context) as client:
            _login(client, config)
            client.send_message(message)
    else:
        with smtplib.SMTP(config.host, config.port, timeout=15) as client:
            if config.tls == "starttls":
                client.starttls(context=context)
            _login(client, config)
            client.send_message(message)
    return f"sent: {recipient}"


def redact_smtp_secret(message: str, config: SMTPConfig) -> str:
    return redact_values(message, (config.username, config.password))


def _login(client: smtplib.SMTP, config: SMTPConfig) -> None:
    if config.username and config.password:
        client.login(config.username, config.password)


def _required_keys() -> tuple[str, ...]:
    return (
        "WPFY_SMTP_HOST",
        "WPFY_SMTP_PORT",
        "WPFY_SMTP_SENDER",
        "WPFY_SMTP_USERNAME",
        "WPFY_SMTP_PASSWORD",
    )


def _parse_tls(value: str) -> TLSMode:
    normalized = value.strip().lower()
    match normalized:
        case "starttls":
            return "starttls"
        case "ssl":
            return "ssl"
        case "none":
            return "none"
        case _:
            raise SMTPConfigError("invalid WPFY_SMTP_TLS")


def _parse_port(value: str) -> int:
    if not value.isdigit():
        raise SMTPConfigError("invalid WPFY_SMTP_PORT")
    port = int(value)
    if not 1 <= port <= 65535:
        raise SMTPConfigError("invalid WPFY_SMTP_PORT")
    return port

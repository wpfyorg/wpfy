"""Database and user management for site-level MariaDB containers."""
from __future__ import annotations

from dataclasses import dataclass
import re
import secrets
import subprocess

from .events import record_event
from .redaction import redact_values
from .site_paths import env_path, read_env, site_exists, validate_domain
from .site_runtime import compose_command, docker_available, runtime_skip_requested


_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
_DB_SHELL = 'exec mariadb -N -B -uroot -p"$MARIADB_ROOT_PASSWORD"'
_SYSTEM_DATABASES = ("information_schema", "performance_schema", "mysql", "sys")
_RESERVED_USERS = frozenset({"root", "mysql", "mariadb_sys", "mariadb.sys"})


@dataclass(frozen=True, slots=True)
class DatabaseResult:
    """Database operation result."""
    exit_code: int
    message: str
    items: tuple[str, ...] = ()
    one_time_password: str | None = None
    ran: bool = False
    skipped: bool = False


def _identifier(value: str, label: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"invalid {label}: use ^[a-z][a-z0-9_]{{0,31}}$")
    return value


def _database_name(value: str) -> str:
    value = _identifier(value, "database name")
    if value in _SYSTEM_DATABASES:
        raise ValueError(f"reserved database name: {value}")
    return value


def _user_name(value: str) -> str:
    value = _identifier(value, "database user")
    if value in _RESERVED_USERS:
        raise ValueError(f"reserved database user: {value}")
    return value


def _sql_string(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "''").replace("\x00", "\\0").replace(
        "\r", "\\r",
    ).replace("\n", "\\n") + "'"


def _database_site(domain: str) -> DatabaseResult | None:
    validate_domain(domain)
    if not site_exists(domain):
        return DatabaseResult(2, f"site not found: {domain}")
    flavor = read_env(env_path(domain)).get("SITE_FLAVOR", "site")
    if flavor in {"html", "php", "site"}:
        return DatabaseResult(2, f"site has no database service: {domain}")
    if runtime_skip_requested() or not docker_available():
        return DatabaseResult(3, "database operation refused: Docker runtime unavailable", skipped=True)
    return None


def _db_sql(domain: str, sql: str, *, sensitive_values: tuple[str, ...] = ()) -> DatabaseResult:
    problem = _database_site(domain)
    if problem is not None:
        return problem
    try:
        proc = compose_command(domain, "exec", "-T", "db", "sh", "-lc", _DB_SHELL, input_text=sql)
    except (OSError, subprocess.SubprocessError) as exc:
        message = redact_values(str(exc), sensitive_values)
        return DatabaseResult(3, f"database command failed: {message}")
    if proc.returncode != 0:
        message = proc.stderr.strip() or proc.stdout.strip() or "database command failed"
        return DatabaseResult(proc.returncode or 1, redact_values(message, sensitive_values), ran=True)
    rows = tuple(line.strip() for line in proc.stdout.splitlines() if line.strip())
    return DatabaseResult(0, proc.stdout.strip(), rows, ran=True)


def list_databases(domain: str) -> DatabaseResult:
    """List databases."""
    excluded = ",".join(_sql_string(name) for name in _SYSTEM_DATABASES)
    result = _db_sql(
        domain,
        "SELECT SCHEMA_NAME FROM information_schema.SCHEMATA "
        f"WHERE SCHEMA_NAME NOT IN ({excluded}) ORDER BY SCHEMA_NAME;\n",
    )
    if result.exit_code != 0:
        return result
    return DatabaseResult(0, "\n".join(result.items), result.items, ran=True)


def list_users(domain: str) -> DatabaseResult:
    """List users."""
    result = _db_sql(
        domain,
        "SELECT DISTINCT User FROM mysql.user "
        "WHERE Host='%' AND User NOT IN ('root','mariadb.sys','mysql') ORDER BY User;\n",
    )
    if result.exit_code != 0:
        return result
    return DatabaseResult(0, "\n".join(result.items), result.items, ran=True)


def create_database(domain: str, name: str) -> DatabaseResult:
    """Create database."""
    name = _database_name(name)
    result = _db_sql(domain, f"CREATE DATABASE IF NOT EXISTS `{name}`;\n")
    if result.exit_code == 0:
        record_event("site.database.create", domain=domain, detail=f"database {name} ensured")
        return DatabaseResult(0, f"database ready: {name}", ran=True)
    return result


def drop_database(domain: str, name: str) -> DatabaseResult:
    """Drop database."""
    name = _database_name(name)
    result = _db_sql(domain, f"DROP DATABASE IF EXISTS `{name}`;\n")
    if result.exit_code == 0:
        record_event("site.database.drop", domain=domain, detail=f"database {name} dropped")
        return DatabaseResult(0, f"database absent: {name}", ran=True)
    return result


def _grant_sql(user: str, database: str) -> str:
    return f"GRANT ALL PRIVILEGES ON `{database}`.* TO '{user}'@'%';"


def create_user(
    domain: str,
    user: str,
    password: str | None = None,
    grants=None,
) -> DatabaseResult:
    """Create user."""
    user = _user_name(user)
    grant_names: tuple[str, ...]
    if grants is None:
        grant_names = ()
    elif isinstance(grants, str):
        grant_names = (_database_name(grants),)
    else:
        try:
            grant_names = tuple(_database_name(name) for name in grants)
        except TypeError as exc:
            raise ValueError("grants must be database names") from exc

    generated = password is None
    password = password if password is not None else secrets.token_urlsafe(18)
    if not isinstance(password, str) or not password:
        raise ValueError("database user password must be a non-empty string")
    statements = [
        f"CREATE USER IF NOT EXISTS '{user}'@'%' IDENTIFIED BY {_sql_string(password)};",
        f"ALTER USER IF EXISTS '{user}'@'%' IDENTIFIED BY {_sql_string(password)};",
    ]
    statements.extend(_grant_sql(user, database) for database in grant_names)
    result = _db_sql(domain, "\n".join(statements) + "\n", sensitive_values=(password,))
    if result.exit_code == 0:
        record_event("site.database.user-create", domain=domain, detail=f"database user {user} ensured")
        return DatabaseResult(
            0,
            f"database user ready: {user}",
            one_time_password=password if generated else None,
            ran=True,
        )
    return result


def drop_user(domain: str, user: str) -> DatabaseResult:
    """Drop user."""
    user = _user_name(user)
    result = _db_sql(domain, f"DROP USER IF EXISTS '{user}'@'%';\n")
    if result.exit_code == 0:
        record_event("site.database.user-drop", domain=domain, detail=f"database user {user} dropped")
        return DatabaseResult(0, f"database user absent: {user}", ran=True)
    return result


def set_user_password(domain: str, user: str, password: str | None = None) -> DatabaseResult:
    """Set user password."""
    user = _user_name(user)
    generated = password is None
    password = password if password is not None else secrets.token_urlsafe(18)
    if not isinstance(password, str) or not password:
        raise ValueError("database user password must be a non-empty string")
    result = _db_sql(
        domain,
        f"ALTER USER IF EXISTS '{user}'@'%' IDENTIFIED BY {_sql_string(password)};\n",
        sensitive_values=(password,),
    )
    if result.exit_code == 0:
        record_event("site.database.user-password", domain=domain, detail=f"database user {user} password updated")
        return DatabaseResult(
            0,
            f"database user password updated: {user}",
            one_time_password=password if generated else None,
            ran=True,
        )
    return result


def grant(domain: str, user: str, database: str) -> DatabaseResult:
    """Grant."""
    user = _user_name(user)
    database = _database_name(database)
    result = _db_sql(domain, _grant_sql(user, database) + "\n")
    if result.exit_code == 0:
        record_event(
            "site.database.grant",
            domain=domain,
            detail=f"database user {user} granted access to {database}",
        )
        return DatabaseResult(0, f"granted {user} access to {database}", ran=True)
    return result

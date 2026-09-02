"""WPFY Login Shield: container-to-host WordPress authentication event pipeline.

Task t10. Carries official wp-fail2ban plugin events (and WordPress core
application-password failures, which the plugin does not cover) from the site's
PHP container into a host-visible structured per-site log.

Components:

- Host log path: ``<site>/security/wp-auth.log`` (outside the WordPress
  document root, inside the per-site ``security/`` staging directory).
- Container mount: the site's ``app`` (php-fpm) service bind-mounts the log at
  ``/var/log/wpfy/wp-auth.log`` and the generated MU-plugin bridge at
  ``/var/www/html/wp-content/mu-plugins/wpfy-login-shield-bridge.php``
  (read-only). Both mounts are rendered from the compose scaffold, so they
  survive container recreation and ``wpfy refresh``.
- Bridge: a small WPFY-owned MU-plugin that hooks the plugin's
  ``...\\wp_fail2ban\\Syslog::write`` filter and WP core
  ``application_password_failed_authentication`` action, and appends one JSONL
  line per authentication failure. It returns ``true`` from the plugin filter
  so native syslog is skipped (PHP syslog cannot reach the host in this
  architecture; see t03 evidence).
- Rotation: a per-site logrotate stanza mirroring the ADR 0023 access-log
  pattern (weekly, maxsize 100M, rotate 12, copytruncate) so the bind-mounted
  single file keeps its inode.

No fail2ban jail activation happens here; this module only moves events from
WordPress to a host-visible log.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from .site_paths import site_dir, validate_domain
from .site_security import (
    _current_paths,
    _install_global_text,
    _install_text_in_place,
    _remove_global_file,
    _safe_write_in_place,
    load_security,
)

# Host-side file names inside the per-site security/ directory (the same
# directory the wp-cli service mounts read-only as /security; see t06).
AUTH_LOG_FILE = "wp-auth.log"
AUTH_LOG_CONTAINER_PATH = "/var/log/wpfy/wp-auth.log"
AUTH_LOG_MODE = 0o640

BRIDGE_MU_FILE = "wpfy-login-shield-bridge.php"
BRIDGE_CONTAINER_PATH = "/var/www/html/wp-content/mu-plugins/wpfy-login-shield-bridge.php"
BRIDGE_MODE = 0o644

# Structured record contract (t10 + plan Phase 5). Event value is stable so
# host-side filters can match one literal.
RECORD_EVENT = "wordpress_auth_failure"
RECORD_FIELDS = (
    "timestamp",
    "event",
    "site",
    "surface",
    "client_ip",
    "account_hash",
    "reason_class",
)

# Hard = immediate-ban classes upstream (unknown/blocked user, enumeration);
# soft = known-user wrong password and other gentle classes; extra = password
# reset requests (optional jail upstream). See t03 research section 10.
HARD_EVENT_NEEDLES = (
    "unknown user",
    "blocked authentication",
    "blocked user",
    "user enumeration",
)
EXTRA_EVENT_NEEDLES = ("password reset",)


def security_dir(domain: str) -> Path:
    """Return security directory."""
    validate_domain(domain)
    return site_dir(domain) / "security"


def auth_log_path(domain: str) -> Path:
    """Return auth log path."""
    validate_domain(domain)
    return security_dir(domain) / AUTH_LOG_FILE


def bridge_path(domain: str) -> Path:
    """Return bridge path."""
    validate_domain(domain)
    return security_dir(domain) / BRIDGE_MU_FILE


def _php_single_quote(value: str) -> str:
    """Render a PHP single-quoted string literal (escape backslash + quote)."""
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


# ---------------------------------------------------------------------------
# Bridge MU-plugin content
# ---------------------------------------------------------------------------

_BRIDGE_TEMPLATE = """<?php
/**
 * Plugin Name: WPFY Login Shield Bridge
 * Description: WPFY-owned bridge: mirrors official wp-fail2ban Syslog events
 * and WordPress core application-password failures into a host-visible
 * structured log. WPFY-owned generated file; do not edit.
 */

defined( 'ABSPATH' ) || exit;

if ( ! function_exists( 'add_action' ) ) {
    return;
}

if ( ! defined( 'WPFY_SHIELD_SITE' ) ) {
    define( 'WPFY_SHIELD_SITE', %(site)s );
}
if ( ! defined( 'WPFY_SHIELD_AUTH_LOG' ) ) {
    define( 'WPFY_SHIELD_AUTH_LOG', %(log)s );
}
if ( ! defined( 'WPFY_SHIELD_ENABLED' ) ) {
    // State-driven guard (t13): generated from per-site security.json. When
    // Login Shield is disabled the bridge writes no records, so a disabled
    // site never generates auth-failure events.
    define( 'WPFY_SHIELD_ENABLED', %(enabled)s );
}

/**
 * Never-ban redaction (t16 W2): an identity that must never become a
 * bannable client is redacted to the 0.0.0.0 sentinel before the record is
 * written, mirroring the panel_auth guard for what a container can observe:
 *   0.0.0.0 sentinel, loopback (127.0.0.0/8, ::1), and 172.16.0.0/12
 *   (Docker bridge 172.17/16 and WPFY/edge container networks).
 * Cloudflare's 172.64.0.0/13 is NOT inside 172.16.0.0/12 (it is a public
 * range, 172.64.0.0-172.71.255.255), so it is not redacted here; a resolved
 * Cloudflare edge never appears in-container because nginx real-ip resolves
 * the client before fastcgi, and Cloudflare edges are handled by the panel
 * auth never-ban discovery, not this static container-visible set.
 * In-container REMOTE_ADDR cannot be a Traefik edge /32-/128 or the panel
 * backend: nginx real-ip resolves the client before fastcgi, so those
 * identities surface only as the internal peer after a trust regression and
 * are covered by the private-range redaction. A legitimate public attacker
 * never originates from these ranges and still emits.
 */
function wpfy_shield_is_never_ban( $ip ) {
    if ( ! is_string( $ip ) || '' === $ip ) {
        return true;
    }
    $parsed = filter_var( $ip, FILTER_VALIDATE_IP );
    if ( false === $parsed ) {
        return true;
    }
    $v4 = filter_var( $parsed, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 );
    if ( false !== $v4 ) {
        $octets = array_map( 'intval', explode( '.', $v4 ) );
        $addr = ( $octets[0] << 24 ) | ( $octets[1] << 16 ) | ( $octets[2] << 8 ) | $octets[3];
        // 0.0.0.0 sentinel: banning it is a no-op in iptables.
        if ( 0 === $addr ) {
            return true;
        }
        // 127.0.0.0/8 loopback.
        if ( ( $addr & 0xff000000 ) === 0x7f000000 ) {
            return true;
        }
        // 172.16.0.0/12 (Docker bridge + WPFY/edge container networks).
        // Cloudflare 172.64/13 is public (172.64.0.0-172.71.255.255) and not
        // inside 172.16/12; it never appears in-container under real-ip trust.
        if ( ( $addr & 0xfff00000 ) === 0xac100000 ) {
            return true;
        }
        return false;
    }
    // IPv6. Mirrors the v4 arm above: sentinel, loopback, and the container
     // ranges wpfy itself owns. Only WPFY's assigned fd4a:3b1c::/48 prefix is
     // static infrastructure; another routed/operator ULA remains bannable.
    $packed = @inet_pton( $parsed );
    if ( false === $packed || 16 !== strlen( $packed ) ) {
        return true;
    }
    // '::' unspecified sentinel and '::1' loopback.
    if ( "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0" === $packed
        || "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1" === $packed ) {
        return true;
    }
    // WPFY's fd4a:3b1c::/48 unique-local infrastructure prefix.
    if ( "\\xfd\\x4a\\x3b\\x1c\\x00\\x00" === substr( $packed, 0, 6 ) ) {
        return true;
    }
    return false;
}

/**
 * Append one JSONL auth-failure record to the bind-mounted host log.
 * Injection-safe: every value goes through wp_json_encode (fallback
 * json_encode). Never fatal: a write failure is ignored so the log path can
 * never take WordPress authentication offline.
 */
function wpfy_shield_write_record( $site, $surface, $client_ip, $identity, $reason_class ) {
    if ( ! WPFY_SHIELD_ENABLED ) {
        return;
    }
    if ( ! is_string( $client_ip ) || '' === $client_ip ) {
        $client_ip = isset( $_SERVER['REMOTE_ADDR'] ) ? (string) $_SERVER['REMOTE_ADDR'] : '0.0.0.0';
    }
    // t16 W2: never-ban identities are redacted to the 0.0.0.0 sentinel
    // before the record is written; the strict filter rejects the sentinel,
    // so edge/container infrastructure can never be banned by an auth
    // failure even if nginx real-ip trust regresses out-of-band.
    if ( wpfy_shield_is_never_ban( $client_ip ) ) {
        $client_ip = '0.0.0.0';
    }
    $account_hash = ( is_string( $identity ) && '' !== $identity )
        ? hash( 'sha256', strtolower( $identity ) )
        : '';
    $record = array(
        'timestamp'    => gmdate( 'Y-m-d\\TH:i:s\\Z' ),
        'event'        => 'wordpress_auth_failure',
        'site'         => $site,
        'surface'      => $surface,
        'client_ip'    => $client_ip,
        'account_hash' => $account_hash,
        'reason_class' => $reason_class,
    );
    $line = function_exists( 'wp_json_encode' ) ? wp_json_encode( $record ) : json_encode( $record );
    if ( ! is_string( $line ) ) {
        return;
    }
    @file_put_contents( WPFY_SHIELD_AUTH_LOG, $line . "\\n", FILE_APPEND | LOCK_EX );
}

/**
 * Classify plugin messages into hard / soft / extra without re-implementing
 * detection (t03 research section 10). Hard = immediate-ban classes; soft =
 * known-user wrong password and other gentle classes; extra = password reset.
 */
function wpfy_shield_classify( $msg ) {
    $text = is_string( $msg ) ? $msg : '';
    foreach ( array(
        'unknown user',
        'blocked authentication',
        'blocked user',
        'user enumeration',
    ) as $needle ) {
        if ( false !== stripos( $text, $needle ) ) {
            return 'hard';
        }
    }
    if ( false !== stripos( $text, 'password reset' ) ) {
        return 'extra';
    }
    return 'soft';
}

function wpfy_shield_surface( $msg ) {
    $text = is_string( $msg ) ? $msg : '';
    if ( false !== stripos( $text, 'xmlrpc' ) ) {
        return 'xmlrpc';
    }
    if ( false !== stripos( $text, 'rest' ) ) {
        return 'rest';
    }
    if ( false !== stripos( $text, 'password reset' ) ) {
        return 'password_reset';
    }
    if ( false !== stripos( $text, 'enumeration' ) ) {
        return 'user_enum';
    }
    return 'wp_login';
}

/**
 * Bridge the official wp-fail2ban Syslog::write extension point. WordPress
 * apply_filters passes FOUR arguments: the leading filter $value (null for
 * this filter) plus ($level, $msg, $remote_addr); add_filter must declare 4
 * accepted args or the real $remote_addr is dropped (t21 Blocker 3). Returns
 * true (non-null) so the plugin skips native syslog, which cannot reach the
 * host in this architecture (t03 research section 8). For wp_login_failed the
 * plugin passes a null $remote_addr; fall back to $_SERVER['REMOTE_ADDR']
 * (nginx real-ip resolves the true client via set_real_ip_from exact Traefik
 * /32-/128 peers) before the record is built. Never parse forwarded headers
 * here. The filter name is a plain string and is inert when the plugin is
 * absent or deactivated.
 */
function wpfy_shield_bridge_syslog_write( $value, $level, $msg, $remote_addr ) {
    if ( ! is_string( $remote_addr ) || '' === $remote_addr ) {
        $remote_addr = isset( $_SERVER['REMOTE_ADDR'] )
            ? (string) $_SERVER['REMOTE_ADDR']
            : '';
    }
    wpfy_shield_write_record(
        WPFY_SHIELD_SITE,
        wpfy_shield_surface( $msg ),
        $remote_addr,
        is_string( $msg ) ? $msg : '',
        wpfy_shield_classify( $msg )
    );
    return true;
}
add_filter(
    'org\\lecklider\\charles\\wordpress\\wp_fail2ban\\Syslog::write',
    'wpfy_shield_bridge_syslog_write',
    10,
    4
);

/**
 * Cover WordPress application passwords, which wp-fail2ban does not log.
 * WP core fires this action with the failing username (WP >= 5.6).
 */
function wpfy_shield_app_password_failed( $username ) {
    wpfy_shield_write_record(
        WPFY_SHIELD_SITE,
        'app_password',
        isset( $_SERVER['REMOTE_ADDR'] ) ? (string) $_SERVER['REMOTE_ADDR'] : '',
        is_string( $username ) ? $username : '',
        'soft'
    );
}
add_action( 'application_password_failed_authentication', 'wpfy_shield_app_password_failed' );
"""


def bridge_content(domain: str, *, enabled: bool = True) -> str:
    """Render the WPFY-owned bridge MU-plugin for one site (injection-safe).

    ``enabled`` controls the ``WPFY_SHIELD_ENABLED`` guard: when False the
    bridge loads but writes no auth-failure records (disable path, t13).
    """
    validate_domain(domain)
    return _BRIDGE_TEMPLATE % {
        "site": _php_single_quote(domain),
        "log": _php_single_quote(AUTH_LOG_CONTAINER_PATH),
        "enabled": "true" if enabled else "false",
    }


# ---------------------------------------------------------------------------
# Rotation (mirrors site_security._configure_access_log_rotation)
# ---------------------------------------------------------------------------


def _auth_logrotate_path(domain: str) -> Path:
    validate_domain(domain)
    digest = hashlib.sha256(domain.encode("utf-8")).hexdigest()[:16]
    return Path(_current_paths().config_dir).parent / "logrotate.d" / f"wpfy-auth-{digest}"


def _auth_log_rotation_content(domain: str) -> str:
    log = auth_log_path(domain)
    return "\n".join((
        "# Generated by wpfy. Keep host-visible WordPress auth logs bounded.",
        f"{log} {{",
        "    weekly",
        "    maxsize 100M",
        "    rotate 12",
        "    missingok",
        "    notifempty",
        "    compress",
        "    delaycompress",
        "    copytruncate",
        "}",
        "",
    ))


def _configure_auth_log_rotation(domain: str) -> bool:
    return _install_global_text(_auth_logrotate_path(domain), _auth_log_rotation_content(domain))


def _remove_auth_log_rotation(domain: str) -> bool:
    return _remove_global_file(_auth_logrotate_path(domain))


# ---------------------------------------------------------------------------
# File placement
# ---------------------------------------------------------------------------


def ensure_event_pipeline_files(domain: str, *, enabled: bool | None = None) -> list[str]:
    """Create/refresh the security dir, auth log, and bridge MU-plugin.

    Idempotent: returns the list of paths that changed. Called from the site
    scaffold so the files exist before any container starts and survive
    container recreation.

    ``enabled`` drives the bridge write guard (t13). When None it is derived
    from the per-site ``security.json`` ``fail2ban`` flag (default disabled),
    so container recreation and ``wpfy refresh`` preserve the state-driven
    integration without an explicit call.
    """
    validate_domain(domain)
    root = security_dir(domain)
    root.mkdir(parents=True, exist_ok=True)
    touched: list[str] = []

    log = root / AUTH_LOG_FILE
    if not log.exists():
        _safe_write_in_place(root, AUTH_LOG_FILE, "", AUTH_LOG_MODE)
        touched.append(str(log))
    else:
        os.chmod(log, AUTH_LOG_MODE, follow_symlinks=False)

    if enabled is None:
        try:
            enabled = bool(load_security(domain).get("fail2ban", False))
        except (OSError, TypeError, ValueError):
            enabled = False
    content = bridge_content(domain, enabled=enabled)
    # The bridge is individually bind-mounted into the app container, so a
    # content change must preserve its inode (gate H5 pattern, t10 evidence):
    # os.replace would leave the container mount pointing at the old inode.
    if _install_text_in_place(root, BRIDGE_MU_FILE, content, BRIDGE_MODE):
        touched.append(str(root / BRIDGE_MU_FILE))

    _configure_auth_log_rotation(domain)
    return touched

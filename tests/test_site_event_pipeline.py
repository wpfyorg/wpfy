from __future__ import annotations

import importlib
import os
from pathlib import Path
import stat

import pytest

from wpfy.site_layout import compose_content, SiteSpec


def _spec(**kwargs) -> SiteSpec:
    kwargs.setdefault("site_uid", 100000)
    return SiteSpec(**kwargs)


# ---------------------------------------------------------------------------
# Paths and constants
# ---------------------------------------------------------------------------


def test_auth_log_lives_outside_wordpress_docroot():
    import wpfy.site_event_pipeline as pipeline

    log = pipeline.auth_log_path("example.com")
    assert log == pipeline.security_dir("example.com") / pipeline.AUTH_LOG_FILE
    assert "app" not in log.parts
    assert "wp-content" not in log.parts
    assert log.name == "wp-auth.log"


def test_auth_log_container_path_is_not_web_accessible():
    import wpfy.site_event_pipeline as pipeline

    assert pipeline.AUTH_LOG_CONTAINER_PATH.startswith("/var/log/")
    assert "/var/www/html" not in pipeline.AUTH_LOG_CONTAINER_PATH


def test_auth_log_rotation_path_is_distinct_from_access_log_rotation():
    import wpfy.site_event_pipeline as pipeline
    import wpfy.site_security as security

    assert pipeline._auth_logrotate_path("example.com") != security._logrotate_path("example.com")


# ---------------------------------------------------------------------------
# Bridge MU-plugin content
# ---------------------------------------------------------------------------


def test_bridge_content_embeds_site_and_log_path():
    import wpfy.site_event_pipeline as pipeline

    content = pipeline.bridge_content("example.com")
    assert "'example.com'" in content
    assert pipeline.AUTH_LOG_CONTAINER_PATH in content


def test_bridge_content_rejects_unsafe_domain():
    import wpfy.site_event_pipeline as pipeline

    with pytest.raises(ValueError, match="invalid domain"):
        pipeline.bridge_content("example.com')); evil(); //")


def test_bridge_content_hooks_plugin_syslog_write_filter():
    import wpfy.site_event_pipeline as pipeline

    content = pipeline.bridge_content("example.com")
    assert "Syslog::write" in content
    assert "add_filter(" in content
    # Suppress native syslog so events are not duplicated into container stderr.
    assert "return true;" in content


def test_bridge_content_hooks_core_app_password_failure():
    import wpfy.site_event_pipeline as pipeline

    content = pipeline.bridge_content("example.com")
    assert "application_password_failed_authentication" in content
    assert "add_action(" in content


def test_bridge_content_has_structured_record_fields():
    import wpfy.site_event_pipeline as pipeline

    content = pipeline.bridge_content("example.com")
    for field in ("timestamp", "event", "site", "surface", "client_ip", "account_hash", "reason_class"):
        assert f"'{field}'" in content
    assert "'wordpress_auth_failure'" in content


def test_bridge_content_is_injection_safe_json():
    import wpfy.site_event_pipeline as pipeline

    content = pipeline.bridge_content("example.com")
    assert "wp_json_encode" in content or "json_encode" in content
    assert "FILE_APPEND" in content


def test_bridge_content_uses_remote_addr_not_forwarded_headers():
    import wpfy.site_event_pipeline as pipeline

    content = pipeline.bridge_content("example.com")
    assert "REMOTE_ADDR" in content
    assert "HTTP_X_FORWARDED_FOR" not in content
    assert "HTTP_CF_CONNECTING_IP" not in content
    assert "X-Forwarded-For" not in content


def test_bridge_content_has_never_ban_redaction():
    """t16 W2 pin: the bridge redacts never-ban identities (loopback, Docker
    bridge / WPFY edge ranges, 0.0.0.0 sentinel) before writing a record, so
    an edge/container hop can never become a bannable client."""
    import wpfy.site_event_pipeline as pipeline

    content = pipeline.bridge_content("example.com")
    assert "wpfy_shield_is_never_ban" in content
    # Redacted identities become the 0.0.0.0 sentinel (a ban no-op).
    assert "0.0.0.0" in content
    # The static never-ban ranges mirror the panel_auth guard for what a
    # container can observe: loopback, sentinel, and 172.16/12 (Docker bridge
    # + WPFY/edge container networks). Cloudflare 172.64/13 is public range,
    # not inside 172.16/12, and is handled by the panel discovery, not here.
    assert "127.0.0.0/8" in content
    assert "172.16.0.0/12" in content
    assert "::1" in content


def test_bridge_redacts_never_ban_before_record_write():
    """t16 W2 pin: redaction happens before the record is built/written — the
    client_ip stored in the record is already sentinel-redacted."""
    import wpfy.site_event_pipeline as pipeline

    content = pipeline.bridge_content("example.com")
    write_fn = content[content.index("function wpfy_shield_write_record"):]
    redact_fn = content[content.index("function wpfy_shield_is_never_ban"):content.index("function wpfy_shield_write_record")]
    assert "wpfy_shield_is_never_ban" in redact_fn
    # The write path consults the never-ban guard before building $record.
    assert "wpfy_shield_is_never_ban( $client_ip )" in write_fn
    assert "file_put_contents" in write_fn


def test_bridge_content_never_fatals_when_plugin_absent():
    import wpfy.site_event_pipeline as pipeline

    content = pipeline.bridge_content("example.com")
    assert "defined( 'ABSPATH' )" in content
    assert "function_exists( 'add_action' )" in content


def test_bridge_content_preserves_hard_soft_extra_classes():
    import wpfy.site_event_pipeline as pipeline

    content = pipeline.bridge_content("example.com")
    for needle in ("unknown user", "blocked authentication", "blocked user", "user enumeration"):
        assert needle in content
    assert "'hard'" in content
    assert "'soft'" in content
    assert "'extra'" in content
    assert "password reset" in content


def test_bridge_content_classifies_surfaces():
    import wpfy.site_event_pipeline as pipeline

    content = pipeline.bridge_content("example.com")
    for surface in ("wp_login", "xmlrpc", "rest", "app_password", "password_reset", "user_enum"):
        assert f"'{surface}'" in content


def test_bridge_content_never_hooks_normal_frontend():
    import wpfy.site_event_pipeline as pipeline

    content = pipeline.bridge_content("example.com")
    for hook in ("wp_footer", "template_redirect", "wp_head", "init", "shutdown"):
        assert hook not in content


# ---------------------------------------------------------------------------
# t21 Blocker 3: Syslog::write filter arity + REMOTE_ADDR fallback
# ---------------------------------------------------------------------------


def test_bridge_syslog_write_filter_declares_four_accepted_args():
    """t21 Blocker 3 pin: WordPress apply_filters('...Syslog::write', null,
    $level, $msg, $remote_addr) passes FOUR args (leading filter $value + the
    three plugin args). The callback must declare the leading $value param AND
    add_filter must declare 4 accepted args, or the real $remote_addr is
    dropped and every event records client_ip=0.0.0.0."""
    import wpfy.site_event_pipeline as pipeline

    content = pipeline.bridge_content("example.com")
    assert "function wpfy_shield_bridge_syslog_write( $value, $level, $msg, $remote_addr )" in content
    # add_filter registers accepted-args=4 so apply_filters passes the real
    # $remote_addr through; accepted-args=3 silently truncates it.
    assert "    'wpfy_shield_bridge_syslog_write',\n    10,\n    4\n);" in content


def test_bridge_syslog_write_falls_back_to_remote_addr_for_null():
    """t21 Blocker 3 pin: wp_login_failed passes a null $remote_addr to the
    plugin. The bridge must fall back to $_SERVER['REMOTE_ADDR'] (nginx real-ip
    resolves the true client via set_real_ip_from exact Traefik peers) before
    the never-ban redaction, so real events carry the attacker IP."""
    import wpfy.site_event_pipeline as pipeline

    content = pipeline.bridge_content("example.com")
    bridge_fn = content[content.index("function wpfy_shield_bridge_syslog_write"):content.index("add_filter(")]
    assert "! is_string( $remote_addr ) || '' === $remote_addr" in bridge_fn
    assert "REMOTE_ADDR" in bridge_fn
    # The fallback resolves the client BEFORE the record is built, so the
    # resolved value flows through never-ban redaction inside write_record.
    assert bridge_fn.index("REMOTE_ADDR") < bridge_fn.index("wpfy_shield_write_record")


def test_bridge_hook_audit_all_registered_args_match_wp_signatures():
    """t21 Blocker 3 audit pin: every add_filter/add_action registration in the
    bridge matches the WordPress-side signature. Syslog::write = 4 filter args
    (value + level + msg + remote_addr) -> 4 accepted; app-password action =
    1 arg ($username) -> default accepted args. No other hooks registered."""
    import re
    import wpfy.site_event_pipeline as pipeline

    content = pipeline.bridge_content("example.com")
    # Exactly two hook registrations exist (filter + action).
    assert len(re.findall(r"add_(?:filter|action)\(", content)) == 2
    # Syslog::write filter: 4-param callback + accepted-args 4.
    assert "function wpfy_shield_bridge_syslog_write( $value, $level, $msg, $remote_addr )" in content
    assert "    'wpfy_shield_bridge_syslog_write',\n    10,\n    4\n);" in content
    # application_password_failed_authentication action: 1-param callback,
    # add_action uses the default accepted-args (1).
    app_fn = content[
        content.index("function wpfy_shield_app_password_failed"):content.index("add_action(")
    ]
    assert "( $username )" in app_fn
    assert "add_action( 'application_password_failed_authentication', 'wpfy_shield_app_password_failed' );" in content


_PHP_BRIDGE_HARNESS = r"""<?php
/**
 * WPFY bridge integration harness (t21 Blocker 3 pin). Mimics the WordPress
 * hook contract for the two hooks the generated bridge registers:
 *   - apply_filters( $tag, $value, ...$args ) passes $value plus up to
 *     accepted_args extras to each filter callback (WP core semantics).
 *   - do_action( $tag, ...$args ) passes up to accepted_args extras.
 * Then fires real plugin/core events and lets the generated bridge write
 * records to a tmp auth log. Exit code 0 only if every call completes.
 * Args: <auth-log path> <bridge path>
 */

define( 'ABSPATH', '/var/www/html/' );
define( 'WPFY_SHIELD_SITE', 'pin.example.com' );
define( 'WPFY_SHIELD_AUTH_LOG', $argv[1] );
define( 'WPFY_SHIELD_ENABLED', true );
$_SERVER['REMOTE_ADDR'] = '203.0.113.10';

$GLOBALS['wpfy_filters'] = array();
$GLOBALS['wpfy_actions'] = array();

function add_filter( $tag, $callback, $priority = 10, $accepted_args = 1 ) {
    $GLOBALS['wpfy_filters'][ $tag ][] = array(
        'callback' => $callback,
        'accepted' => (int) $accepted_args,
    );
}

function add_action( $tag, $callback, $priority = 10, $accepted_args = 1 ) {
    $GLOBALS['wpfy_actions'][ $tag ][] = array(
        'callback' => $callback,
        'accepted' => (int) $accepted_args,
    );
}

function wpfy_apply_filters( $tag, $value, ...$args ) {
    $result = $value;
    if ( isset( $GLOBALS['wpfy_filters'][ $tag ] ) ) {
        foreach ( $GLOBALS['wpfy_filters'][ $tag ] as $entry ) {
            $pass = array_merge( array( $result ), array_slice( $args, 0, $entry['accepted'] ) );
            $result = call_user_func_array( $entry['callback'], $pass );
        }
    }
    return $result;
}

function wpfy_do_action( $tag, ...$args ) {
    if ( isset( $GLOBALS['wpfy_actions'][ $tag ] ) ) {
        foreach ( $GLOBALS['wpfy_actions'][ $tag ] as $entry ) {
            $pass = array_slice( $args, 0, $entry['accepted'] );
            call_user_func_array( $entry['callback'], $pass );
        }
    }
}

require $argv[2];

$tag = 'org\\lecklider\\charles\\wordpress\\wp_fail2ban\\Syslog::write';

// 1. Plugin event with a real (nginx real-ip resolved) remote_addr. The
//    plugin applies the filter as (null, $level, $msg, $remote_addr); the
//    leading null is the filter value.
$ret = wpfy_apply_filters( $tag, null, 5, 'Authentication failure for admin', '203.0.113.10' );
echo 'RETURN=' . ( $ret === true ? 'true' : var_export( $ret, true ) ) . "\n";

// 2. wp_login_failed path: plugin passes a null remote_addr; the bridge must
//    fall back to $_SERVER['REMOTE_ADDR'] (nginx real-ip resolved client).
wpfy_apply_filters( $tag, null, 5, 'Authentication failure for bob', null );

// 3. Never-ban identity (loopback): must redact to the 0.0.0.0 sentinel.
wpfy_apply_filters( $tag, null, 5, 'Authentication failure for carol', '127.0.0.1' );

// 4. Hard class: unknown user, real remote addr.
wpfy_apply_filters( $tag, null, 5, 'Authentication attempt for unknown user', '198.51.100.9' );

// 5. WP core app-password failure action (the plugin does not cover it).
wpfy_do_action( 'application_password_failed_authentication', 'alice' );

echo 'DONE' . "\n";
"""


def test_bridge_real_php_integration_syslog_write_arity(tmp_path):
    """t21 Blocker 3 integration pin: execute the GENERATED bridge under real
    PHP with WP-style apply_filters semantics (4 args, leading filter $value).
    Asserts the bridge receives $level/$msg/$remote_addr correctly, writes a
    record with the REMOTE_ADDR-resolved client IP (not 0.0.0.0) when the
    plugin passes a null remote_addr (wp_login_failed), redacts never-ban IPs,
    classifies hard/soft, covers the app-password action, and returns true to
    skip native syslog. This is the exact failure the live host saw (Blocker 3).
    """
    import hashlib
    import json
    import shutil
    import subprocess

    import wpfy.site_event_pipeline as pipeline

    php = shutil.which("php")
    if php is None:
        pytest.skip("php binary not available")

    bridge = tmp_path / "wpfy-login-shield-bridge.php"
    bridge.write_text(pipeline.bridge_content("bridge-pin.example.com"), encoding="utf-8")
    log = tmp_path / "wp-auth.log"
    harness = tmp_path / "harness.php"
    harness.write_text(_PHP_BRIDGE_HARNESS, encoding="utf-8")

    proc = subprocess.run(
        [php, "-d", "error_reporting=E_ALL", "-d", "display_errors=1", str(harness), str(log), str(bridge)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, f"php harness failed:\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    assert "DONE" in proc.stdout
    # The filter must return true (non-null) so the plugin skips native syslog.
    assert "RETURN=true" in proc.stdout, f"filter must return true to skip native syslog:\n{proc.stdout}"

    records = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(records) == 5, f"expected 5 records, got {len(records)}"

    def _hash(identity: str) -> str:
        return hashlib.sha256(identity.lower().encode("utf-8")).hexdigest()

    # 1. Real remote_addr plugin event: correct arg mapping.
    assert records[0]["surface"] == "wp_login"
    assert records[0]["client_ip"] == "203.0.113.10"
    assert records[0]["reason_class"] == "soft"
    assert records[0]["account_hash"] == _hash("Authentication failure for admin")
    assert len(records[0]["account_hash"]) == 64

    # 2. wp_login_failed null remote_addr -> REMOTE_ADDR fallback (attacker IP).
    assert records[1]["client_ip"] == "203.0.113.10", (
        "null remote_addr must fall back to $_SERVER['REMOTE_ADDR'], not 0.0.0.0"
    )
    assert records[1]["account_hash"] == _hash("Authentication failure for bob")

    # 3. Never-ban identity (loopback) redacted to the 0.0.0.0 sentinel.
    assert records[2]["client_ip"] == "0.0.0.0"

    # 4. Hard class preserved from the message.
    assert records[3]["reason_class"] == "hard"
    assert records[3]["client_ip"] == "198.51.100.9"

    # 5. App-password action still covered with REMOTE_ADDR client.
    assert records[4]["surface"] == "app_password"
    assert records[4]["client_ip"] == "203.0.113.10"
    assert records[4]["account_hash"] == _hash("alice")
    assert records[4]["reason_class"] == "soft"


# ---------------------------------------------------------------------------
# Scaffold + compose integration
# ---------------------------------------------------------------------------


def test_compose_content_app_mounts_auth_log_and_bridge(tmp_wpfy_home):
    import wpfy.site_event_pipeline as pipeline

    content = compose_content(_spec(domain="example.com", flavor="wp", use_mysql=True, use_redis=False))
    log_mount = f"./security/{pipeline.AUTH_LOG_FILE}:{pipeline.AUTH_LOG_CONTAINER_PATH}"
    bridge_mount = (
        f"./security/{pipeline.BRIDGE_MU_FILE}:{pipeline.BRIDGE_CONTAINER_PATH}:ro"
    )
    assert log_mount in content
    assert bridge_mount in content
    # The auth log is writable and never under the docroot; the bridge is read-only.
    assert "/var/www/html" not in log_mount
    app_block = content[content.index("  app:"):]
    assert app_block.index(log_mount) < app_block.index(bridge_mount)


def test_ensure_site_scaffold_creates_pipeline_files(tmp_wpfy_home):
    import wpfy.site_layout
    import wpfy.site_event_pipeline as pipeline

    importlib.reload(wpfy.site_layout)
    domain = "pipeline.example.com"
    spec = wpfy.site_layout.SiteSpec(domain=domain, flavor="wp", use_mysql=True, use_redis=False)
    wpfy.site_layout.ensure_site_scaffold(spec)

    log = pipeline.auth_log_path(domain)
    bridge = pipeline.bridge_path(domain)
    assert log.is_file()
    assert stat.S_IMODE(log.stat().st_mode) == pipeline.AUTH_LOG_MODE
    assert bridge.is_file()
    assert stat.S_IMODE(bridge.stat().st_mode) == pipeline.BRIDGE_MODE
    assert domain in bridge.read_text(encoding="utf-8")

    rotation = pipeline._auth_logrotate_path(domain)
    rotation_text = rotation.read_text(encoding="utf-8")
    assert str(log) in rotation_text
    assert "copytruncate" in rotation_text
    assert "maxsize 100M" in rotation_text

    compose = wpfy.site_layout.compose_path(domain).read_text(encoding="utf-8")
    assert f"./security/{pipeline.AUTH_LOG_FILE}:{pipeline.AUTH_LOG_CONTAINER_PATH}" in compose
    assert (
        f"./security/{pipeline.BRIDGE_MU_FILE}:{pipeline.BRIDGE_CONTAINER_PATH}:ro" in compose
    )


def test_ensure_site_scaffold_pipeline_files_are_idempotent(tmp_wpfy_home):
    import wpfy.site_layout
    import wpfy.site_event_pipeline as pipeline

    importlib.reload(wpfy.site_layout)
    domain = "pipeline-idempotent.example.com"
    spec = wpfy.site_layout.SiteSpec(domain=domain, flavor="wp", use_mysql=True, use_redis=False)
    wpfy.site_layout.ensure_site_scaffold(spec)

    first_inode = pipeline.auth_log_path(domain).stat().st_ino
    touched = pipeline.ensure_event_pipeline_files(domain)

    assert touched == []
    assert pipeline.auth_log_path(domain).stat().st_ino == first_inode
    assert wpfy.site_layout.ensure_site_scaffold(spec) == []


def test_ensure_event_pipeline_files_rejects_log_symlink(tmp_wpfy_home, tmp_path):
    import wpfy.site_layout
    import wpfy.site_event_pipeline as pipeline

    importlib.reload(wpfy.site_layout)
    domain = "pipeline-symlink.example.com"
    spec = wpfy.site_layout.SiteSpec(domain=domain, flavor="wp", use_mysql=True, use_redis=False)
    wpfy.site_layout.ensure_site_scaffold(spec)
    external = tmp_path / "external-auth-log"
    external.write_bytes(b"sentinel")
    pipeline.auth_log_path(domain).unlink()
    pipeline.auth_log_path(domain).symlink_to(external)

    with pytest.raises(ValueError, match="unsafe scaffold destination"):
        wpfy.site_layout.ensure_site_scaffold(spec)

    assert external.read_bytes() == b"sentinel"


def test_auth_log_rotation_install_and_remove(tmp_wpfy_home):
    import wpfy.site_event_pipeline as pipeline

    changed = pipeline._configure_auth_log_rotation("example.com")
    assert changed is True
    assert pipeline._configure_auth_log_rotation("example.com") is False
    text = pipeline._auth_logrotate_path("example.com").read_text(encoding="utf-8")
    assert "copytruncate" in text
    assert "rotate 12" in text
    assert "weekly" in text

    assert pipeline._remove_auth_log_rotation("example.com") is True
    assert not pipeline._auth_logrotate_path("example.com").exists()
    assert pipeline._remove_auth_log_rotation("example.com") is False


def test_auth_log_path_requires_valid_domain():
    import wpfy.site_event_pipeline as pipeline

    with pytest.raises(ValueError, match="invalid domain"):
        pipeline.auth_log_path("../escape")


def test_bridge_content_enabled_guard_defaults_to_enabled():
    import wpfy.site_event_pipeline as pipeline

    content = pipeline.bridge_content("example.com")
    assert "WPFY_SHIELD_ENABLED" in content
    assert "define( 'WPFY_SHIELD_ENABLED', true );" in content
    assert "if ( ! WPFY_SHIELD_ENABLED )" in content


def test_bridge_content_disabled_guard_blocks_writes():
    import wpfy.site_event_pipeline as pipeline

    content = pipeline.bridge_content("example.com", enabled=False)
    assert "define( 'WPFY_SHIELD_ENABLED', false );" in content
    assert "if ( ! WPFY_SHIELD_ENABLED ) {\n        return;" in content


def test_ensure_event_pipeline_files_is_state_driven_by_security_json(tmp_wpfy_home, tmp_path):
    """t13: the bridge guard follows security.json fail2ban flag by default
    (default disabled on fresh sites) and can be forced for enable/disable."""
    import wpfy.site_layout as layout
    import wpfy.site_security as security
    import wpfy.site_event_pipeline as pipeline

    domain = "shield-a.example.com"
    layout.ensure_site_scaffold(
        layout.SiteSpec(domain=domain, flavor="wp", use_mysql=True, use_redis=False),
    )
    state = security.load_security(domain)
    assert state["fail2ban"] is False

    pipeline.ensure_event_pipeline_files(domain)
    disabled_text = pipeline.bridge_path(domain).read_text(encoding="utf-8")
    assert "WPFY_SHIELD_ENABLED', false" in disabled_text

    bridge_inode = pipeline.bridge_path(domain).stat().st_ino
    pipeline.ensure_event_pipeline_files(domain, enabled=True)
    enabled_text = pipeline.bridge_path(domain).read_text(encoding="utf-8")
    assert "WPFY_SHIELD_ENABLED', true" in enabled_text
    # The bridge is individually bind-mounted; a content change must preserve
    # the inode (gate H5 pattern) or the app container keeps the stale file.
    assert pipeline.bridge_path(domain).stat().st_ino == bridge_inode

    pipeline.ensure_event_pipeline_files(domain, enabled=False)
    assert "WPFY_SHIELD_ENABLED', false" in pipeline.bridge_path(domain).read_text(encoding="utf-8")
    assert pipeline.bridge_path(domain).stat().st_ino == bridge_inode

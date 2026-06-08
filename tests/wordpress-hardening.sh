#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

failures=0
tmp_dir="$(mktemp -d)"
cleanup() {
    rm -rf "$tmp_dir"
}
trap cleanup EXIT

pass() { printf '[PASS] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*"; }
fail() { printf '[FAIL] %s\n' "$*"; failures=$((failures + 1)); }

export PYTHONPATH=src
export WPFY_INSTALL_ROOT="$tmp_dir/install"
export WPFY_CONFIG_DIR="$tmp_dir/config"
export WPFY_STATE_DIR="$tmp_dir/state"
export WPFY_LOG_DIR="$tmp_dir/log"
export WPFY_SKIP_RUNTIME=1
export WPFY_SKIP_WORDPRESS_DOWNLOAD=1

python3 - <<'PY'
from wpfy.site_layout import SiteSpec, ensure_site_scaffold, bootstrap_site_files
spec = SiteSpec(domain="wp-hardening.example.com", flavor="wp", use_mysql=True, use_redis=False)
ensure_site_scaffold(spec)
bootstrap_site_files("wp-hardening.example.com")
PY

site_root="$WPFY_INSTALL_ROOT/sites/wp-hardening.example.com"
conf="$site_root/nginx/default.conf"
app="$site_root/app"

[[ -f "$app/wp-config.php" ]] && pass "wp-config.php is generated" || fail "wp-config.php is missing"
grep -q "WP_DEBUG.*true" "$app/wp-config.php" && fail "WP_DEBUG is enabled" || pass "WP_DEBUG is not explicitly enabled"
grep -Eq "AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY" "$app/wp-config.php" && pass "WordPress salts are present or fallback config is minimal" || warn "WordPress salts not present in fallback config"

grep -Eq 'wp-content/uploads/.+\\.php|uploads/.+\\.php' "$conf" && pass "uploads PHP execution blocked" || fail "uploads PHP execution not blocked"
grep -Eq 'wp-config|\\.env|debug\\.log|readme\\.html|license\\.txt|xmlrpc\\.php' "$conf" && pass "common WordPress sensitive paths are handled" || fail "common WordPress sensitive paths are not handled"
grep -Eq 'autoindex[[:space:]]+off' "$conf" && pass "directory listing disabled explicitly" || warn "directory listing is not explicitly disabled"

compose="$site_root/compose.yaml"
grep -q 'db:' "$compose" && pass "database is generated as an internal service" || fail "database service missing for wp flavor"
grep -Eq '^[[:space:]]+ports:' "$compose" && fail "site compose has direct host ports" || pass "site compose has no direct host ports"

exit "$failures"

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
fail() { printf '[FAIL] %s\n' "$*"; failures=$((failures + 1)); }

export PYTHONPATH=src
export WPFY_INSTALL_ROOT="$tmp_dir/install"
export WPFY_CONFIG_DIR="$tmp_dir/config"
export WPFY_STATE_DIR="$tmp_dir/state"
export WPFY_LOG_DIR="$tmp_dir/log"
export WPFY_SKIP_RUNTIME=1

python3 - <<'PY'
from wpfy.site_layout import SiteSpec, ensure_site_scaffold
ensure_site_scaffold(SiteSpec(domain="nginx-audit.example.com", flavor="wp", use_mysql=True, use_redis=False))
PY

conf="$WPFY_INSTALL_ROOT/sites/nginx-audit.example.com/nginx/default.conf"
printf 'checking generated nginx config: %s\n' "$conf"

grep -Eq 'wp-content/uploads/.+\\.php|uploads/.+\\.php' "$conf" && pass "uploads PHP execution is blocked" || fail "uploads PHP execution is not explicitly blocked"
grep -Eq 'wp-config\\.php|wp-config' "$conf" && pass "wp-config.php is blocked" || fail "wp-config.php is not explicitly blocked"
grep -Eq '\\.env|dotfile|/\\\.' "$conf" && pass "dotfiles and .env are blocked" || fail "dotfiles/.env are not explicitly blocked"
grep -Eq 'debug\\.log|\\.sql|\\.bak|\\.zip|backup' "$conf" && pass "debug logs/backups/dumps are blocked" || fail "debug logs/backups/dumps are not explicitly blocked"
grep -Eq 'deny[[:space:]]+all|return[[:space:]]+403|return[[:space:]]+404' "$conf" && pass "sensitive locations return deny status" || fail "no deny/403/404 sensitive-location policy found"

exit "$failures"

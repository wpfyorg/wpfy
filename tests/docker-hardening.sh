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

python3 - <<'PY'
from pathlib import Path
from wpfy.site_layout import SiteSpec, ensure_site_scaffold, compose_path
from wpfy.traefik import traefik_compose_content

ensure_site_scaffold(SiteSpec(domain="docker-audit.example.com", flavor="wpredis", use_mysql=True, use_redis=True))
Path("docker-audit-traefik.compose.yaml").write_text(traefik_compose_content(), encoding="utf-8")
print(compose_path("docker-audit.example.com"))
PY

site_compose="$WPFY_INSTALL_ROOT/sites/docker-audit.example.com/compose.yaml"
traefik_compose="docker-audit-traefik.compose.yaml"
trap 'rm -rf "$tmp_dir" "$traefik_compose"' EXIT

check_file() {
    local file="$1"
    local label="$2"
    printf '\n== %s ==\n' "$label"

    grep -q 'restart: unless-stopped' "$file" && pass "$label has restart policies" || fail "$label missing restart policies"
    grep -q 'healthcheck:' "$file" && pass "$label has healthchecks" || warn "$label has no healthchecks"
    grep -q 'privileged: true' "$file" && fail "$label enables privileged mode" || pass "$label does not enable privileged mode"
    grep -q 'network_mode: host' "$file" && fail "$label uses host networking" || pass "$label does not use host networking"
    grep -q 'pid: host' "$file" && fail "$label uses host PID namespace" || pass "$label does not use host PID namespace"
    grep -q 'ipc: host' "$file" && fail "$label uses host IPC namespace" || pass "$label does not use host IPC namespace"
    grep -Eq 'security_opt:|no-new-privileges' "$file" && pass "$label sets no-new-privileges/security_opt" || fail "$label missing no-new-privileges/security_opt"
    grep -Eq 'cap_drop:|cap_drop:\s*\\[ALL\\]' "$file" && pass "$label drops Linux capabilities" || fail "$label missing cap_drop"
    grep -Eq 'mem_limit:|cpus:|pids_limit:' "$file" && pass "$label defines resource limits" || fail "$label missing resource limits"
    grep -q 'logging:' "$file" && pass "$label defines log rotation/options" || fail "$label missing logging limits"
}

check_file "$site_compose" "site compose"
check_file "$traefik_compose" "traefik compose"

grep -q '/var/run/docker.sock:/var/run/docker.sock:ro' "$traefik_compose" && warn "Traefik Docker socket mount is read-only but remains sensitive" || fail "Traefik Docker socket mount missing or changed"

if command -v docker >/dev/null 2>&1; then
    warn "live docker inspect hardening checks skipped by default; use wpfy secure on a disposable running stack"
else
    warn "live docker inspect skipped: docker not installed"
fi

exit "$failures"

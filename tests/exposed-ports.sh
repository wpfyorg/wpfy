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
from wpfy.site_definition import SiteDefinition, sftp_service_lines
from wpfy.site_layout import SiteSpec, ensure_site_scaffold, compose_path
from wpfy.traefik import traefik_compose_content

def sftp_service_yaml(domain, host_port="2222"):
    definition = SiteDefinition(
        domain=domain,
        flavor="site",
        use_mysql=False,
        use_redis=False,
        sftp_password="configured",
        sftp_port=host_port,
    )
    return "\n" + "\n".join(sftp_service_lines(definition))

ensure_site_scaffold(SiteSpec(domain="audit.example.com", flavor="wpredis", use_mysql=True, use_redis=True))
print(f"SITE_COMPOSE={compose_path('audit.example.com')}")
print("---TRAEFIK---")
print(traefik_compose_content())
print("---SFTP---")
print(sftp_service_yaml("audit.example.com", "2222"))
PY

site_compose="$WPFY_INSTALL_ROOT/sites/audit.example.com/compose.yaml"

if grep -Eq '^[[:space:]]+ports:' "$site_compose"; then
    fail "site compose exposes host ports; per-site web/app/db/redis should stay behind Traefik/internal networks"
else
    pass "site compose has no direct host port bindings"
fi

traefik_content="$(PYTHONPATH=src python3 - <<'PY'
from wpfy.traefik import traefik_compose_content
print(traefik_compose_content())
PY
)"

grep -q '"80:80"' <<<"$traefik_content" && pass "Traefik publishes HTTP 80" || fail "Traefik HTTP 80 binding missing"
grep -q '"443:443"' <<<"$traefik_content" && pass "Traefik publishes HTTPS 443" || fail "Traefik HTTPS 443 binding missing"
grep -q '/var/run/docker.sock:/var/run/docker.sock:ro' <<<"$traefik_content" && warn "Traefik mounts Docker socket read-only; still high-impact if Traefik is compromised" || fail "Traefik Docker provider socket mount not found"

sftp_content="$(PYTHONPATH=src python3 - <<'PY'
from wpfy.site_definition import SiteDefinition, sftp_service_lines

definition = SiteDefinition(
    domain="audit.example.com",
    flavor="site",
    use_mysql=False,
    use_redis=False,
    sftp_password="configured",
    sftp_port="2222",
)
print("\n" + "\n".join(sftp_service_lines(definition)))
PY
)"
grep -q '"127.0.0.1:2222:22"' <<<"$sftp_content" && pass "SFTP sidecar binds loopback only" || fail "SFTP sidecar is not loopback-bound"

if command -v docker >/dev/null 2>&1; then
    warn "runtime port inspection skipped by default; run on a disposable active stack for live bindings"
else
    warn "runtime port inspection skipped: docker not installed"
fi

exit "$failures"

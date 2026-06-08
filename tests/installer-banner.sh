#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

pass() { printf '[PASS] %s\n' "$*"; }
fail() { printf '[FAIL] %s\n' "$*" >&2; exit 1; }

output="$(
    env \
        WPFY_INSTALLER_SOURCE_ONLY=1 \
        WPFY_BUILD=JUN2026 \
        WPFY_TEST_HOST_OS="Ubuntu 24.04 LTS" \
        WPFY_TEST_HOSTNAME="wpfy.example.com" \
        WPFY_TEST_VIRTUALIZATION="kvm" \
        WPFY_TEST_DISK="39G free of 43G total (7% used)" \
        WPFY_TEST_RAM="2.4G" \
        WPFY_TEST_SWAP="1.2G" \
        WPFY_TEST_CPU="2" \
        WPFY_TEST_IPV4="192.0.2.10" \
        WPFY_TEST_IPV6="N/A" \
        bash -c 'source ./wpfy; show_welcome'
)"

grep -q '______' <<<"$output" || fail "wpfy logo missing"
grep -q 'Build:.*JUN2026' <<<"$output" || fail "build row missing"
grep -q 'Operating System:.*Ubuntu 24.04 LTS' <<<"$output" || fail "OS row missing"
grep -q 'Hostname:.*wpfy.example.com' <<<"$output" || fail "hostname row missing"
grep -q 'Virtualization:.*kvm' <<<"$output" || fail "virtualization row missing"
grep -q 'Disk Space:.*39G free of 43G total (7% used)' <<<"$output" || fail "disk row missing"
grep -q 'RAM Memory:.*2.4G total' <<<"$output" || fail "RAM row missing"
grep -q 'Swap:.*1.2G total' <<<"$output" || fail "swap row missing"
grep -q 'vCPU Cores:.*2' <<<"$output" || fail "CPU row missing"
grep -q 'IPv4 Address:.*192.0.2.10' <<<"$output" || fail "IPv4 row missing"
grep -q 'IPv6 Address:.*N/A' <<<"$output" || fail "IPv6 row missing"

while IFS= read -r line; do
    [[ ${#line} -le 80 ]] || fail "banner line exceeds 80 columns: $line"
done <<<"$output"

pass "installer banner renders a bounded host summary"

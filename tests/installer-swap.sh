#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

pass() { printf '[PASS] %s\n' "$*"; }
fail() { printf '[FAIL] %s\n' "$*" >&2; exit 1; }

TMP_DIR="$(mktemp -d)"
cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

run_ensure_swap() {
    env \
        WPFY_INSTALLER_SOURCE_ONLY=1 \
        WPFY_DRY_RUN=1 \
        WPFY_TEST_ACTIVE_SWAP="${WPFY_TEST_ACTIVE_SWAP:-0}" \
        WPFY_TEST_ROOT_FREE_GB="${WPFY_TEST_ROOT_FREE_GB:-20}" \
        WPFY_SWAP="${WPFY_SWAP:-1}" \
        WPFY_SWAP_SIZE_MB="${WPFY_SWAP_SIZE_MB:-}" \
        WPFY_SWAP_FILE="${WPFY_SWAP_FILE:-$TMP_DIR/swapfile}" \
        bash -c 'source ./wpfy; ensure_swap'
}

WPFY_TEST_ACTIVE_SWAP=1 output="$(run_ensure_swap)"
grep -q 'active swap already present' <<<"$output" || fail "active swap skip missing"
pass "existing active swap skips swap creation"

WPFY_TEST_ACTIVE_SWAP=0 WPFY_TEST_ROOT_FREE_GB=7 output="$(run_ensure_swap)"
grep -q 'need at least 8GB' <<<"$output" || fail "low disk skip missing"
pass "low free disk skips swap creation"

WPFY_TEST_ACTIVE_SWAP=0 WPFY_TEST_ROOT_FREE_GB=20 output="$(run_ensure_swap)"
grep -q 'create 2048MB swap' <<<"$output" || fail "20GB-class disk did not choose 2GB swap"
pass "20GB-class disk chooses 2GB swap"

WPFY_TEST_ACTIVE_SWAP=0 WPFY_TEST_ROOT_FREE_GB=30 output="$(run_ensure_swap)"
grep -q 'create 4096MB swap' <<<"$output" || fail "30GB+ disk did not choose 4GB swap"
pass "30GB+ disk chooses 4GB swap"

WPFY_SWAP=0 output="$(run_ensure_swap)"
grep -q 'WPFY_SWAP=0' <<<"$output" || fail "WPFY_SWAP=0 skip missing"
pass "WPFY_SWAP=0 disables swap creation"

WPFY_SWAP=1 WPFY_TEST_ACTIVE_SWAP=0 WPFY_TEST_ROOT_FREE_GB=20 WPFY_SWAP_SIZE_MB=3072 output="$(run_ensure_swap)"
grep -q 'create 3072MB swap' <<<"$output" || fail "WPFY_SWAP_SIZE_MB override missing"
pass "WPFY_SWAP_SIZE_MB overrides adaptive sizing"

swap_path="$TMP_DIR/dry-run-swapfile"
WPFY_SWAP_FILE="$swap_path" WPFY_TEST_ACTIVE_SWAP=0 WPFY_TEST_ROOT_FREE_GB=20 output="$(run_ensure_swap)"
[[ ! -e "$swap_path" ]] || fail "dry-run created swap file"
pass "dry-run does not create swap file"

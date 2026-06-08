#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

pass() { printf '[PASS] %s\n' "$*"; }
fail() { printf '[FAIL] %s\n' "$*" >&2; exit 1; }
warn() { printf '[WARN] %s\n' "$*"; }

TMP_DIR="$(mktemp -d)"
cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

archive="$TMP_DIR/wpfy-local.tar.gz"
bundle="$TMP_DIR/wpfy-local"
mkdir -p "$bundle"
tar --exclude='.git' --exclude='.context' --exclude='__pycache__' -cf - . | tar -xf - -C "$bundle"
tar -czf "$archive" -C "$TMP_DIR" wpfy-local
if command -v sha256sum >/dev/null 2>&1; then
    checksum="$(sha256sum "$archive" | awk '{print $1}')"
else
    checksum="$(shasum -a 256 "$archive" | awk '{print $1}')"
fi

bad_status=0
bad_output="$(WPFY_SOURCE_ARCHIVE="$archive" WPFY_SOURCE_SHA256="0000000000000000000000000000000000000000000000000000000000000000" bash install.sh --dry-run 2>&1)" || bad_status=$?
[[ "$bad_status" -ne 0 ]] || fail "install.sh accepted a mismatched source checksum"
grep -q 'source archive checksum mismatch' <<<"$bad_output" || fail "install.sh checksum mismatch message missing"
pass "install.sh rejects mismatched source archive checksum"

status=0
output="$(WPFY_SOURCE_ARCHIVE="$archive" WPFY_SOURCE_SHA256="$checksum" bash install.sh --dry-run 2>&1)" || status=$?
printf '%s\n' "$output"

grep -q 'Source archive checksum verified' <<<"$output" || fail "install.sh did not verify matching checksum"
grep -q '\[DRY-RUN\] \[4/16\] Validating installer bundle' <<<"$output" || fail "bootstrap progress did not reach step 4"
grep -q '\[DRY-RUN\] \[5/16\] Checking Ubuntu support' <<<"$output" || fail "bundled installer progress did not continue at step 5"
if [[ "$status" -ne 0 ]]; then
    if [[ "$(uname -s)" != "Linux" ]]; then
        pass "install.sh local archive handoff works; bundled Ubuntu installer dry-run skipped on non-Linux host"
        exit 0
    fi
    fail "bundled installer dry-run exited $status"
fi

grep -q 'wpfy pip install skipped (--skip-wpfy-install)' <<<"$output" || fail "bundled installer did not skip PyPI install"
grep -q '\[dry-run\]' <<<"$output" || fail "dry-run output did not include dry-run operations"

if grep -E 'apt-get install|systemctl enable|rm -rf /opt/wpfy' <<<"$output" >/dev/null; then
    warn "dry-run text mentions host-mutating operations; confirm they are printed only, not executed"
fi

pass "installer dry-run local archive path is safe and repeatable"

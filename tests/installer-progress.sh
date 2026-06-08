#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

pass() { printf '[PASS] %s\n' "$*"; }
fail() { printf '[FAIL] %s\n' "$*" >&2; exit 1; }

TMP_DIR="$(mktemp -d)"
cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT

tty_output="$(
    env -u NO_COLOR WPFY_INSTALLER_SOURCE_ONLY=1 WPFY_TEST_TTY=1 bash -c '
        source ./wpfy
        setup_ui
        CURRENT_STEP=8
        CURRENT_STEP_LABEL="Installing Docker"
        render_active_step
        render_completed_step OK
    '
)"
[[ "$tty_output" == *$'\033[36m'* ]] || fail "TTY active step is not cyan"
[[ "$tty_output" == *$'\033[32m'* ]] || fail "TTY completed step is not green"
[[ "$tty_output" == *$'\r'* ]] || fail "TTY progress does not rewrite one line"
grep -q '50%.*8/16.*Installing Docker' <<<"$tty_output" || fail "TTY progress values are incorrect"
pass "TTY progress is color-coded and updates in place"

bar_states="$(
    env -u NO_COLOR WPFY_INSTALLER_SOURCE_ONLY=1 WPFY_TEST_TTY=1 bash -c '
        source ./wpfy
        setup_ui
        progress_line 0 "Starting"
        printf "\n"
        progress_line 8 "Halfway"
        printf "\n"
        progress_line 16 "Complete" OK
    '
)"
grep -q '0%.*0/16.*Starting' <<<"$bar_states" || fail "0% progress state missing"
grep -q '50%.*8/16.*Halfway' <<<"$bar_states" || fail "50% progress state missing"
grep -q '100%.*16/16.*Complete' <<<"$bar_states" || fail "100% progress state missing"
pass "progress bar renders exact boundary states"

plain_output="$(
    WPFY_INSTALLER_SOURCE_ONLY=1 WPFY_TEST_TTY=1 WPFY_NO_COLOR=1 bash -c '
        source ./wpfy
        setup_ui
        CURRENT_STEP=8
        CURRENT_STEP_LABEL="Installing Docker"
        render_completed_step OK
    '
)"
[[ "$plain_output" != *$'\033['* ]] || fail "--no-color emitted ANSI escapes"
grep -q '^\[OK\] \[8/16\] Installing Docker$' <<<"$plain_output" || fail "plain progress output is unstable"
pass "no-color output is plain and stable"

standard_no_color="$(
    NO_COLOR=1 WPFY_INSTALLER_SOURCE_ONLY=1 WPFY_TEST_TTY=1 bash -c '
        source ./wpfy
        setup_ui
        CURRENT_STEP=8
        CURRENT_STEP_LABEL="Installing Docker"
        render_completed_step OK
    '
)"
[[ "$standard_no_color" != *$'\033['* ]] || fail "NO_COLOR emitted ANSI escapes"
pass "standard NO_COLOR is respected"

hidden_log="$TMP_DIR/hidden.log"
hidden_output="$(
    WPFY_INSTALLER_SOURCE_ONLY=1 WPFY_INSTALL_LOG="$hidden_log" bash -c '
        source ./wpfy
        setup_ui
        setup_logging
        noisy_step() { echo "raw command detail"; }
        run_step 1 "Quiet operation" noisy_step
        cleanup_session
    '
)"
grep -q '^\[OK\] \[5/16\] Quiet operation$' <<<"$hidden_output" || fail "quiet step status missing"
! grep -q 'raw command detail' <<<"$hidden_output" || fail "quiet mode leaked command output"
grep -q 'raw command detail' "$hidden_log" || fail "quiet mode did not retain command output in log"
pass "default mode hides command output and retains it in the log"

skip_log="$TMP_DIR/skip.log"
skip_output="$(
    WPFY_INSTALLER_SOURCE_ONLY=1 WPFY_INSTALL_LOG="$skip_log" bash -c '
        source ./wpfy
        setup_ui
        setup_logging
        skipped_step() { mark_step_skipped "already installed"; }
        run_step 1 "Existing component" skipped_step
        cleanup_session
    '
)"
grep -q '^\[SKIP\] \[5/16\] Existing component$' <<<"$skip_output" || fail "SKIP state missing"
grep -q 'STEP 5/16 SKIP' "$skip_log" || fail "SKIP state missing from log"
pass "idempotent work is reported as SKIP"

verbose_log="$TMP_DIR/verbose.log"
verbose_output="$(
    WPFY_INSTALLER_SOURCE_ONLY=1 WPFY_VERBOSE=1 WPFY_INSTALL_LOG="$verbose_log" bash -c '
        source ./wpfy
        setup_ui
        setup_logging
        noisy_step() { echo "visible command detail"; }
        run_step 1 "Verbose operation" noisy_step
        cleanup_session
    '
)"
grep -q 'visible command detail' <<<"$verbose_output" || fail "verbose mode hid command output"
grep -q 'visible command detail' "$verbose_log" || fail "verbose mode did not retain command output"
pass "verbose mode mirrors command output"

failure_log="$TMP_DIR/failure.log"
set +e
failure_output="$(
    WPFY_INSTALLER_SOURCE_ONLY=1 WPFY_INSTALL_LOG="$failure_log" bash -c '
        source ./wpfy
        setup_ui
        setup_logging
        failing_step() {
            for n in $(seq 1 20); do echo "failure line $n"; done
            return 7
        }
        run_step 1 "Deliberate failure" failing_step
    ' 2>&1
)"
failure_status=$?
set -e
[[ "$failure_status" -eq 7 ]] || fail "failed step returned $failure_status instead of 7"
grep -q 'Installation failed' <<<"$failure_output" || fail "failure heading missing"
grep -q 'Step: Deliberate failure (5/16)' <<<"$failure_output" || fail "failure step context missing"
grep -q 'Exit status: 7' <<<"$failure_output" || fail "failure exit status missing"
grep -q 'Last 15 log lines:' <<<"$failure_output" || fail "failure log tail heading missing"
grep -q 'failure line 20' <<<"$failure_output" || fail "failure log tail omitted recent output"
grep -q 'STEP 5/16 FAIL' "$failure_log" || fail "failure was not recorded in durable log"
pass "failed steps show context and a bounded log tail"

summary_output="$(
    WPFY_INSTALLER_SOURCE_ONLY=1 bash -c '
        source ./wpfy
        USE_TTY=0
        LOG_FILE="/var/log/wpfy/install.log"
        INSTALL_STARTED_AT=$(( $(date +%s) - 65 ))
        wpfy() { echo "wpfy 0.1.0"; }
        docker() { echo "29.1.3"; }
        show_success
    '
)"
grep -q 'Installation complete' <<<"$summary_output" || fail "success heading missing"
grep -q 'Version: wpfy 0.1.0' <<<"$summary_output" || fail "installed version missing"
grep -q 'Docker: 29.1.3' <<<"$summary_output" || fail "Docker version missing"
grep -q 'Elapsed: 1m 05s' <<<"$summary_output" || fail "elapsed time missing"
grep -q 'Next: wpfy stack install --nginx' <<<"$summary_output" || fail "next command missing"
pass "success summary includes versions, timing, log, and next command"

set +e
interrupt_output="$(
    WPFY_INSTALLER_SOURCE_ONLY=1 bash -c '
        source ./wpfy
        USE_TTY=0
        LOG_FILE="/tmp/wpfy-interrupt.log"
        on_interrupt
    ' 2>&1
)"
interrupt_status=$?
set -e
[[ "$interrupt_status" -eq 130 ]] || fail "interrupt returned $interrupt_status instead of 130"
grep -q 'Installation interrupted' <<<"$interrupt_output" || fail "interrupt message missing"
grep -q 'Log: /tmp/wpfy-interrupt.log' <<<"$interrupt_output" || fail "interrupt log path missing"
pass "interrupt cleanup reports status and log path"

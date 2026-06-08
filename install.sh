#!/usr/bin/env bash
set -euo pipefail

REPO_OWNER="${WPFY_REPO_OWNER:-wpfyorg}"
REPO_NAME="${WPFY_REPO_NAME:-wpfy}"
REF="${WPFY_REF:-main}"
SOURCE_ARCHIVE="${WPFY_SOURCE_ARCHIVE:-https://github.com/${REPO_OWNER}/${REPO_NAME}/archive/${REF}.tar.gz}"
SOURCE_SHA256="${WPFY_SOURCE_SHA256:-}"
LOG_FILE="${WPFY_INSTALL_LOG:-/var/log/wpfy/install.log}"
DRY_RUN="${WPFY_DRY_RUN:-0}"
VERBOSE="${WPFY_VERBOSE:-0}"
NO_COLOR_REQUESTED="${WPFY_NO_COLOR:-0}"
PROGRESS_TOTAL=16
INSTALL_STARTED_AT="${WPFY_INSTALL_STARTED_AT:-$(date +%s)}"
TMP_ROOT=""
CURRENT_STEP=0
CURRENT_STEP_LABEL=""
CURRENT_STEP_COMMAND=""
CURRENT_STEP_LOG=""
STEP_STATUS="OK"
USE_TTY=0

COLOR_RESET=""
COLOR_CYAN=""
COLOR_GREEN=""
COLOR_YELLOW=""
COLOR_RED=""

usage() {
    cat <<EOF
Usage: bash install.sh [--dry-run] [--verbose] [--no-color] [--help]

Downloads the wpfy source archive and runs the bundled installer.

Examples:
  curl -fsSL https://raw.githubusercontent.com/wpfyorg/wpfy/main/install.sh | sudo bash
  WPFY_SOURCE_SHA256=<sha256> bash install.sh --dry-run

Environment:
  WPFY_REF             Git ref to install from (default: main)
  WPFY_SOURCE_ARCHIVE  Source tarball URL or local file path
  WPFY_SOURCE_SHA256   Optional SHA-256 checksum for the source tarball
  WPFY_REPO_OWNER      GitHub owner for default archive URL (default: wpfyorg)
  WPFY_REPO_NAME       GitHub repo for default archive URL (default: wpfy)
  WPFY_VERBOSE         Show command output when set to 1
  WPFY_NO_COLOR        Disable ANSI colors when set to 1
EOF
}

log() {
    printf '%s\n' "$*"
}

host_value() {
    local override_name="$1"
    shift
    local override_value="${!override_name:-}"
    if [[ -n "$override_value" ]]; then
        printf '%s\n' "$override_value"
        return 0
    fi
    "$@"
}

host_os() {
    if [[ -r /etc/os-release ]]; then
        (
            . /etc/os-release
            printf '%s\n' "${PRETTY_NAME:-${NAME:-Linux}}"
        )
    else
        uname -srm
    fi
}

host_hostname() {
    local value
    value="$(hostname -f 2>/dev/null || hostname 2>/dev/null || true)"
    printf '%s\n' "${value:-unknown}"
}

host_virtualization() {
    local value="unknown"
    if command -v systemd-detect-virt >/dev/null 2>&1; then
        value="$(systemd-detect-virt 2>/dev/null || true)"
        [[ "$value" == "none" ]] && value="physical"
    fi
    printf '%s\n' "$value"
}

host_disk() {
    local value
    value="$(df -hP / 2>/dev/null | awk 'NR == 2 { printf "%s free of %s total (%s used)", $4, $2, $5 }' || true)"
    printf '%s\n' "${value:-unknown}"
}

host_memory_value() {
    local row="$1"
    if command -v free >/dev/null 2>&1; then
        free -h | awk -v row="$row" '$1 == row":" { print $2 }'
    else
        printf 'unknown\n'
    fi
}

host_cpu_count() {
    if command -v nproc >/dev/null 2>&1; then
        nproc
    else
        getconf _NPROCESSORS_ONLN 2>/dev/null || printf 'unknown\n'
    fi
}

host_ip() {
    local family="$1"
    local destination="$2"
    local address=""
    if command -v ip >/dev/null 2>&1; then
        address="$(ip "-$family" route get "$destination" 2>/dev/null | awk '{ for (i=1; i<=NF; i++) if ($i == "src") { print $(i+1); exit } }' || true)"
    fi
    printf '%s\n' "${address:-N/A}"
}

banner_row() {
    printf '# %-20s %-55.55s #\n' "$1:" "$2"
}

show_welcome() {
    local build os hostname virtualization disk ram swap cpu ipv4 ipv6
    build="${WPFY_BUILD:-$(date -u +%b%Y | tr '[:lower:]' '[:upper:]')}"
    os="$(host_value WPFY_TEST_HOST_OS host_os)"
    hostname="$(host_value WPFY_TEST_HOSTNAME host_hostname)"
    virtualization="$(host_value WPFY_TEST_VIRTUALIZATION host_virtualization)"
    disk="$(host_value WPFY_TEST_DISK host_disk)"
    ram="$(host_value WPFY_TEST_RAM host_memory_value Mem)"
    swap="$(host_value WPFY_TEST_SWAP host_memory_value Swap)"
    cpu="$(host_value WPFY_TEST_CPU host_cpu_count)"
    ipv4="$(host_value WPFY_TEST_IPV4 host_ip 4 1.1.1.1)"
    ipv6="$(host_value WPFY_TEST_IPV6 host_ip 6 2606:4700:4700::1111)"

    cat <<'EOF'
 __        ______  ______ __   __
 \ \      / /  _ \|  ____|\ \ / /
  \ \ /\ / /| |_) | |__    \ V /
   \ V  V / |  __/|  __|    | |
    \_/\_/  |_|   |_|       |_|
EOF
    printf '%80s\n' '' | tr ' ' '#'
    banner_row "Build" "$build"
    banner_row "Operating System" "$os"
    banner_row "Hostname" "$hostname"
    banner_row "Virtualization" "$virtualization"
    banner_row "Disk Space" "$disk"
    banner_row "RAM Memory" "$ram total"
    banner_row "Swap" "$swap total"
    banner_row "vCPU Cores" "$cpu"
    banner_row "IPv4 Address" "$ipv4"
    banner_row "IPv6 Address" "$ipv6"
    printf '%80s\n' '' | tr ' ' '#'
}

die() {
    printf 'wpfy install: %s\n' "$*" >&2
    exit 1
}

setup_ui() {
    if [[ "$VERBOSE" != "1" && "$NO_COLOR_REQUESTED" != "1" && -z "${NO_COLOR+x}" ]] \
        && [[ "${WPFY_TEST_TTY:-0}" == "1" || ( -t 1 && -z "${CI:-}" ) ]]; then
        USE_TTY=1
        COLOR_RESET=$'\033[0m'
        COLOR_CYAN=$'\033[36m'
        COLOR_GREEN=$'\033[32m'
        COLOR_YELLOW=$'\033[33m'
        COLOR_RED=$'\033[31m'
    fi
}

setup_logging() {
    [[ "$DRY_RUN" == "1" ]] && return 0
    if mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null && touch "$LOG_FILE" 2>/dev/null; then
        chmod 640 "$LOG_FILE" 2>/dev/null || true
        return
    fi
    LOG_FILE="$(mktemp "${TMPDIR:-/tmp}/wpfy-install.XXXXXX.log")"
    chmod 600 "$LOG_FILE"
}

progress_bar() {
    local completed="$1"
    local width=16
    local filled=$(( completed * width / PROGRESS_TOTAL ))
    local empty=$(( width - filled ))
    printf '%*s' "$filled" '' | tr ' ' '#'
    printf '%*s' "$empty" '' | tr ' ' '-'
}

progress_line() {
    local completed="$1"
    local label="$2"
    local status="${3:-ACTIVE}"
    local percent=$(( completed * 100 / PROGRESS_TOTAL ))
    local color="$COLOR_CYAN"
    case "$status" in
        OK) color="$COLOR_GREEN" ;;
        SKIP) color="$COLOR_YELLOW" ;;
        FAIL) color="$COLOR_RED" ;;
    esac
    printf '%s[%s] %3d%%  %2d/%d  %-42.42s%s' \
        "$color" "$(progress_bar "$completed")" "$percent" "$completed" "$PROGRESS_TOTAL" "$label" "$COLOR_RESET"
}

restore_terminal() {
    if [[ "$USE_TTY" == "1" ]]; then
        printf '\033[?25h'
    fi
    return 0
}

render_active_step() {
    [[ "$DRY_RUN" == "1" ]] && return 0
    if [[ "$USE_TTY" == "1" ]]; then
        printf '\r\033[2K'
        progress_line "$(( CURRENT_STEP - 1 ))" "$CURRENT_STEP_LABEL"
    fi
}

render_completed_step() {
    local status="$1"
    [[ "$DRY_RUN" == "1" ]] && return 0
    if [[ "$USE_TTY" == "1" ]]; then
        printf '\r\033[2K'
        progress_line "$CURRENT_STEP" "$CURRENT_STEP_LABEL" "$status"
    else
        printf '[%s] [%d/%d] %s\n' "$status" "$CURRENT_STEP" "$PROGRESS_TOTAL" "$CURRENT_STEP_LABEL"
    fi
}

mark_step_skipped() {
    printf 'SKIP\n%s\n' "$1" >"$TMP_ROOT/step-status"
}

append_step_log() {
    local label="$1"
    local status="$2"
    local duration="$3"
    {
        printf '\n[%s] STEP %d/%d START %s\n' "$(date -u +%FT%TZ)" "$CURRENT_STEP" "$PROGRESS_TOTAL" "$label"
        [[ -s "$CURRENT_STEP_LOG" ]] && cat "$CURRENT_STEP_LOG"
        printf '[%s] STEP %d/%d %s duration=%ss\n' \
            "$(date -u +%FT%TZ)" "$CURRENT_STEP" "$PROGRESS_TOTAL" "$status" "$duration"
    } >>"$LOG_FILE"
}

show_failure() {
    local status="$1"
    restore_terminal
    if [[ "$USE_TTY" == "1" ]]; then
        printf '\r\033[2K'
        progress_line "$(( CURRENT_STEP > 0 ? CURRENT_STEP - 1 : 0 ))" "${CURRENT_STEP_LABEL:-Bootstrap}" "FAIL"
        printf '\n'
    fi
    printf '%sInstallation failed%s\n' "$COLOR_RED" "$COLOR_RESET" >&2
    printf 'Step: %s (%d/%d)\n' "${CURRENT_STEP_LABEL:-bootstrap}" "$CURRENT_STEP" "$PROGRESS_TOTAL" >&2
    printf 'Exit status: %s\n' "$status" >&2
    [[ -n "$CURRENT_STEP_COMMAND" ]] && printf 'Command: %s\n' "$CURRENT_STEP_COMMAND" >&2
    printf 'Log: %s\n' "$LOG_FILE" >&2
    if [[ -n "$CURRENT_STEP_LOG" && -s "$CURRENT_STEP_LOG" ]]; then
        printf '\nLast 15 log lines:\n' >&2
        tail -n 15 "$CURRENT_STEP_LOG" >&2
    fi
    printf '\nFix the reported issue, then run the installer again.\n' >&2
}

run_step() {
    local step="$1"
    local label="$2"
    shift 2
    local started status duration
    CURRENT_STEP="$step"
    CURRENT_STEP_LABEL="$label"
    CURRENT_STEP_COMMAND="$1"

    if [[ "$DRY_RUN" == "1" ]]; then
        printf '\n[DRY-RUN] [%d/%d] %s\n' "$CURRENT_STEP" "$PROGRESS_TOTAL" "$label"
        "$@"
        return
    fi

    CURRENT_STEP_LOG="$TMP_ROOT/step-${CURRENT_STEP}.log"
    : >"$CURRENT_STEP_LOG"
    rm -f "$TMP_ROOT/step-status"
    started="$(date +%s)"
    render_active_step

    set +e
    if [[ "$VERBOSE" == "1" ]]; then
        ( set -e; "$@" ) > >(tee "$CURRENT_STEP_LOG") 2>&1
        status=$?
    else
        ( set -e; "$@" ) >"$CURRENT_STEP_LOG" 2>&1
        status=$?
    fi
    set -e

    duration=$(( $(date +%s) - started ))
    STEP_STATUS="OK"
    [[ -f "$TMP_ROOT/step-status" ]] && STEP_STATUS="$(sed -n '1p' "$TMP_ROOT/step-status")"
    if [[ "$status" -ne 0 ]]; then
        append_step_log "$label" "FAIL" "$duration"
        show_failure "$status"
        exit "$status"
    fi
    append_step_log "$label" "$STEP_STATUS" "$duration"
    render_completed_step "$STEP_STATUS"
}

on_interrupt() {
    restore_terminal
    printf '\n%sInstallation interrupted%s\n' "$COLOR_RED" "$COLOR_RESET" >&2
    printf 'Log: %s\n' "$LOG_FILE" >&2
    exit 130
}

cleanup() {
    restore_terminal
    [[ -n "$TMP_ROOT" ]] && rm -rf "$TMP_ROOT"
}

download_archive() {
    local destination="$1"
    case "$SOURCE_ARCHIVE" in
        http://*|https://*)
            command -v curl >/dev/null 2>&1 || die "curl is required"
            curl -fsSL "$SOURCE_ARCHIVE" -o "$destination" || die "failed to download source archive: $SOURCE_ARCHIVE"
            ;;
        file://*)
            cp "${SOURCE_ARCHIVE#file://}" "$destination" || die "failed to copy source archive: $SOURCE_ARCHIVE"
            ;;
        *)
            cp "$SOURCE_ARCHIVE" "$destination" || die "failed to copy source archive: $SOURCE_ARCHIVE"
            ;;
    esac
}

archive_sha256() {
    local archive="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$archive" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$archive" | awk '{print $1}'
    else
        die "sha256sum or shasum is required when WPFY_SOURCE_SHA256 is set"
    fi
}

verify_archive_checksum() {
    local archive="$1"
    if [[ -z "$SOURCE_SHA256" ]]; then
        log "Source archive checksum verification skipped (WPFY_SOURCE_SHA256 not set)"
        [[ "$DRY_RUN" == "1" ]] || mark_step_skipped "checksum not provided"
        return 0
    fi
    local actual
    actual="$(archive_sha256 "$archive")"
    [[ "$actual" == "$SOURCE_SHA256" ]] || die "source archive checksum mismatch"
    log "Source archive checksum verified"
}

extract_archive() {
    tar -xzf "$1" -C "$TMP_ROOT" || die "source archive could not be extracted"
}

validate_source_bundle() {
    local source_dir
    source_dir="$(find "$TMP_ROOT" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
    [[ -n "$source_dir" && -f "$source_dir/wpfy" ]] || die "source archive does not contain the wpfy installer"
    printf '%s\n' "$source_dir" >"$TMP_ROOT/source-dir"
}

main() {
    local installer_args=()
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --help) usage; exit 0 ;;
            --dry-run) DRY_RUN="1"; installer_args+=("--dry-run") ;;
            --verbose) VERBOSE="1"; installer_args+=("--verbose") ;;
            --no-color) NO_COLOR_REQUESTED="1"; installer_args+=("--no-color") ;;
            *) die "unknown argument: $1" ;;
        esac
        shift
    done

    TMP_ROOT="$(mktemp -d)"
    trap cleanup EXIT
    trap on_interrupt INT TERM
    setup_ui
    setup_logging
    if [[ "$DRY_RUN" == "1" ]]; then
        show_welcome
    else
        show_welcome | tee -a "$LOG_FILE"
    fi
    [[ "$USE_TTY" == "1" && "$DRY_RUN" != "1" ]] && printf '\033[?25l'

    local archive="$TMP_ROOT/wpfy.tar.gz"
    run_step 1 "Downloading source archive" download_archive "$archive"
    run_step 2 "Verifying source checksum" verify_archive_checksum "$archive"
    run_step 3 "Extracting source archive" extract_archive "$archive"
    run_step 4 "Validating installer bundle" validate_source_bundle

    local source_dir
    source_dir="$(cat "$TMP_ROOT/source-dir")"
    restore_terminal
    WPFY_INSTALL_LOG="$LOG_FILE" \
    WPFY_BOOTSTRAP_LOG="$LOG_FILE" \
    WPFY_PROGRESS_OFFSET=4 \
    WPFY_PROGRESS_TOTAL="$PROGRESS_TOTAL" \
    WPFY_INSTALL_STARTED_AT="$INSTALL_STARTED_AT" \
    WPFY_VERBOSE="$VERBOSE" \
    WPFY_NO_COLOR="$NO_COLOR_REQUESTED" \
    WPFY_SKIP_WELCOME=1 \
        bash "$source_dir/wpfy" --skip-wpfy-install "${installer_args[@]}"
}

main "$@"

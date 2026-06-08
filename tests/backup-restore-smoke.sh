#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

export PYTHONPATH=src
export WPFY_SKIP_RUNTIME=1

python3 - <<'PY'
import importlib
import io
import os
import stat
import tarfile
import tempfile
from pathlib import Path

with tempfile.TemporaryDirectory(prefix="wpfy-backup-restore-") as td:
    root = Path(td)
    os.environ["WPFY_INSTALL_ROOT"] = str(root / "install")
    os.environ["WPFY_CONFIG_DIR"] = str(root / "config")
    os.environ["WPFY_STATE_DIR"] = str(root / "state")
    os.environ["WPFY_LOG_DIR"] = str(root / "log")

    import wpfy.settings
    import wpfy.registry
    import wpfy.site_layout

    importlib.reload(wpfy.settings)
    importlib.reload(wpfy.registry)
    importlib.reload(wpfy.site_layout)

    spec = wpfy.site_layout.SiteSpec(domain="backup-smoke.example.com", flavor="site", use_mysql=False, use_redis=False)
    wpfy.site_layout.ensure_site_scaffold(spec)
    result = wpfy.site_layout.backup_site("backup-smoke.example.com")
    if result.exit_code != 0:
        raise SystemExit(f"[FAIL] backup failed: {result.message}")

    archive = Path(result.message.removeprefix("backup created: "))
    mode = stat.S_IMODE(archive.stat().st_mode)
    if mode != 0o600:
        raise SystemExit(f"[FAIL] backup archive mode is {oct(mode)}, expected 0o600")
    print("[PASS] backup archive is 0600")

    unsafe = root / "unsafe.tar.gz"
    with tarfile.open(unsafe, "w:gz") as tf:
        info = tarfile.TarInfo("../escape")
        payload = b"bad"
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))

    restore = wpfy.site_layout.restore_site("backup-smoke.example.com", str(unsafe))
    if restore.exit_code == 0:
        raise SystemExit("[FAIL] restore accepted parent-path archive member")
    print("[PASS] restore rejects parent-path archive members")

    valid = wpfy.site_layout.restore_site("backup-smoke.example.com", str(archive))
    if valid.exit_code != 0:
        raise SystemExit(f"[FAIL] restore rejected valid backup: {valid.message}")
    env_mode = stat.S_IMODE(wpfy.site_layout.env_path("backup-smoke.example.com").stat().st_mode)
    if env_mode != 0o600:
        raise SystemExit(f"[FAIL] restored .env mode is {oct(env_mode)}, expected 0o600")
    print("[PASS] valid restore preserves private .env mode")
PY

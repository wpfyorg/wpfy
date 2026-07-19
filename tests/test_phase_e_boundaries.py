from pathlib import Path


ROOT = Path(__file__).parents[1] / "src" / "wpfy"


def source(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8")


def test_phase_e_primitive_ownership_boundaries():
    for name in ("smtp.py", "dns.py", "s3_backup.py"):
        text = source(name)
        assert "read_env(path)" in text
        assert ".read_text(encoding=\"utf-8\").splitlines()" not in text

    assert "def _read_env_safely" in source("site_layout.py")
    assert "WPFY_SYSTEMD_DIR" in source("systemd.py")
    assert "WPFY_SYSTEMD_DIR" not in source("cron.py")
    assert "WPFY_SYSTEMD_DIR" not in source("backup_schedule.py")
    assert ".replace(\".\", \"-\").replace(\"_\", \"-\").lower()" not in source("site_definition.py")

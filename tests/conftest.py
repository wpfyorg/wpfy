from __future__ import annotations

import pytest
from unittest.mock import patch
import importlib


@pytest.fixture
def tmp_wpfy_home(tmp_path, monkeypatch):
    """Monkeypatch PATHS env vars to use tmp_path, then reimport wpfy.settings."""
    install_root = str(tmp_path / "install")
    config_dir = str(tmp_path / "config")
    state_dir = str(tmp_path / "state")
    log_dir = str(tmp_path / "log")

    monkeypatch.setenv("WPFY_INSTALL_ROOT", install_root)
    monkeypatch.setenv("WPFY_CONFIG_DIR", config_dir)
    monkeypatch.setenv("WPFY_STATE_DIR", state_dir)
    monkeypatch.setenv("WPFY_LOG_DIR", log_dir)

    # Reimport settings module to pick up patched env vars
    import wpfy.settings
    importlib.reload(wpfy.settings)
    import wpfy.registry
    importlib.reload(wpfy.registry)

    return wpfy.settings.PATHS


@pytest.fixture
def clean_registry(tmp_wpfy_home):
    """Provide a fresh Registry instance backed by tmp_path state dir."""
    from pathlib import Path
    from wpfy.registry import Registry

    registry_path = Path(tmp_wpfy_home.state_dir) / "sites.json"
    return Registry(path=registry_path)
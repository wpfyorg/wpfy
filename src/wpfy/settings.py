from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class WpfyPaths:
    install_root: str = os.environ.get("WPFY_INSTALL_ROOT", "/opt/wpfy")
    config_dir: str = os.environ.get("WPFY_CONFIG_DIR", "/etc/wpfy")
    state_dir: str = os.environ.get("WPFY_STATE_DIR", "/var/lib/wpfy")
    log_dir: str = os.environ.get("WPFY_LOG_DIR", "/var/log/wpfy")

    @property
    def app_dir(self) -> str:
        return os.path.join(self.install_root, "app")

    @property
    def sites_dir(self) -> str:
        return os.path.join(self.install_root, "sites")

    @property
    def tmp_dir(self) -> str:
        return os.path.join(self.state_dir, "tmp")

    @property
    def updater_dir(self) -> str:
        """Private, durable updater state (downloads, lock, and state file)."""
        return os.environ.get("WPFY_UPDATER_DIR", os.path.join(self.state_dir, "updates"))

    @property
    def update_dir(self) -> str:
        return self.updater_dir

    @property
    def releases_dir(self) -> str:
        return os.path.join(self.install_root, "releases")

    @property
    def release_dir(self) -> str:
        return self.releases_dir

    @property
    def current_link(self) -> str:
        return os.path.join(self.install_root, "current")

    @property
    def update_lock_path(self) -> str:
        return os.path.join(self.updater_dir, "update.lock")

    @property
    def update_state_path(self) -> str:
        return os.path.join(self.updater_dir, "state.json")

    @property
    def update_keyring_path(self) -> str:
        return os.environ.get("WPFY_UPDATE_KEYRING", os.path.join(self.config_dir, "update_trust.gpg"))

    @property
    def traefik_dir(self) -> str:
        return os.environ.get("WPFY_TRAEFIK_DIR", os.path.join(self.install_root, "traefik"))

    def site_dir(self, domain: str) -> str:
        return os.path.join(self.sites_dir, domain)


PATHS = WpfyPaths()


def current_paths() -> WpfyPaths:
    """Late-bound accessor for PATHS.

    Reads the module global at call time (not import time), so it stays
    correct across `importlib.reload(wpfy.settings)` after env root changes:
    reload mutates this module's dict in place, and this function's
    `__globals__` is that same dict, so callers who imported the function
    itself (not `PATHS` directly) still see the reloaded value.
    """
    return PATHS

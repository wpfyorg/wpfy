# wpfy

Docker-first VPS installer and WordPress/server management CLI.

## Status
- Implemented: Docker-first CLI, Ubuntu installer, per-site Compose stacks, Traefik edge proxy, SSL DNS/IP preflight, full WordPress provisioning, backups, restore, diagnostics, and SFTP lifecycle.
- Planned: hosted image/release hardening, disposable-VPS validation, and broader production polish.

## Target Install UX
```bash
curl -fsSL https://raw.githubusercontent.com/wpfyorg/wpfy/main/install.sh | sudo bash
```

The repository must be public, or the source archive URL must be reachable without credentials.

## License
wpfy is licensed under the GNU Affero General Public License v3.0. See [LICENSE](LICENSE).

## Current Local Usage
```bash
PYTHONPATH=src python3 -m wpfy --help
PYTHONPATH=src python3 -m wpfy site create example.com --wp
PYTHONPATH=src python3 -m wpfy stack install --nginx
```

## Core Direction
- Ubuntu-first for v1.
- Docker/Compose instead of host-level Nginx/PHP/MariaDB/Redis.
- Familiar command structure for common WordPress server operations.
- Strong per-site container isolation: one Compose project, network, volumes, database, and optional Redis per site.
- SSL is opt-in via `-le` or `--letsencrypt`; DNS/IP preflight must pass before certificate issuance.

## Documentation
- Public usage documentation and release notes are being prepared for the wpfy knowledge base.

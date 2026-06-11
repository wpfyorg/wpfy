# Changelog

All notable changes to wpfy will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project aims to follow [Semantic Versioning](https://semver.org/) once it leaves beta.

## [Unreleased]

### Added
- Public beta documentation set: rewritten `README.md`, `SECURITY.md`, `CONTRIBUTING.md`, `ROADMAP.md`, issue templates, and a public repository audit report (`docs/public-beta-audit.md`).
- CI workflow running the pytest suite on pushes and pull requests.

## Beta (current, unversioned)

Initial public beta feature set:

### Added
- Docker-first CLI (`wpfy`) for WordPress and server administration on Ubuntu VPS hosts.
- Guided installer (`install.sh`) with system detection, dry-run mode, and install logging to `/var/log/wpfy/install.log`.
- Per-site Docker Compose stacks: unprivileged Nginx, PHP-FPM (7.4–8.4), MariaDB 11.4, optional Redis — each site with its own Compose project, private network, volumes, and unique unprivileged UID.
- Shared Traefik edge proxy with Let's Encrypt ACME certificate issuance and renewal.
- SSL DNS/IP preflight checks with automatic Cloudflare detection and proxied (HTTP-01) mode.
- Full WordPress provisioning via wp-cli, including admin user/email/password options.
- Site lifecycle commands: `create`, `ssl`, `backup`, `restore`, `wp`, `delete`, `list`, `info`, `show`, `status`, `update`.
- Stack lifecycle commands: `install`, `status`, `remove`, `upgrade`, `purge`.
- Backups (files + verified SQL dump) to `/var/lib/wpfy/backups/` and validated restore that preserves live database credentials.
- Diagnostics (`wpfy debug`) across Docker, Traefik, registry consistency, and per-site health.
- Per-site SFTP lifecycle (`wpfy sftp`) with isolated containers and auto-allocated ports.
- Cache cleaning (`wpfy clean`), log access (`wpfy log`), hardening audit (`wpfy secure`), maintenance helpers (`wpfy maintenance`), and self-update checks (`wpfy update`).

### Known limitations
- Wildcard SSL certificates are not supported.
- `wpfy stack migrate` (migration from host-level stacks) is not implemented in v1.
- phpMyAdmin, Adminer, Composer, and MySQLTuner stack helpers are deferred to v2.
- No automatic backup retention/rotation.

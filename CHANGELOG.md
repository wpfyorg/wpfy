# Changelog

All notable changes to wpfy will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project aims to follow [Semantic Versioning](https://semver.org/) once it leaves beta.

## [Unreleased]

### Release
- Prepared `1.0.0rc2`: package and CLI version identity now matches planned
  `v1.0.0-rc2` tag. Public source retains Python tests and public CI; package
  artifacts and installed production source exclude tests.

### Added
- Local browser control panel: `wpfy panel` serves a loopback-only, token-protected dashboard (stdlib HTTP server + static UI, no new dependencies). It reuses the same Python operation layer as the CLI for overview, site list/detail, health, diagnostics, logs, backups/restore, runtime start/stop/restart, SFTP enable/disable/status, a WP-CLI runner, and PHP version changes. Remote access is documented via SSH tunnel only; secrets are never returned by the API.
- Feature parity build: backup retention/prune, explicit `restore --latest`, named S3-compatible storage profiles, remote backup list/restore/delete/prune, Traefik/ACME edge backup/restore, Cloudflare-only wildcard SSL, `wpfy dns cloudflare`, and pull-only phpMyAdmin/Adminer/Composer helper images.
- Page 8 release validation coverage: documentation sync for the completed flat CLI surface and disposable-VPS runner probes for flat site creation, runtime commands, config/refresh, backup/restore, cron, SMTP dry-run/status, operator utilities, log cron, and flat deletion.
- Cron and SMTP operator surface: `wpfy cron minute|five-minute|hourly|six-hour|daily|weekly`, systemd-backed `wpfy cron install|status|disable`, `wpfy log cron`, safe custom cron hooks, and `wpfy smtp set|status|test|clear`.
- Permanent backup storage and schedule CLI: stored S3-compatible backup config, storage status/test/clear, and one systemd timer for daily or weekly all-site backups.
- Backup and restore ergonomics: `wpfy backup <domain> --list`, `wpfy restore <domain> --list`, `wpfy backup <domain> --path <directory>`, upload-only `wpfy backup <domain> --s3`, and sorted `wpfy backup all`.
- Canonical flat operator commands: `wpfy healthcheck`, `wpfy motd`, and `wpfy utility`.
- Safe flat config commands: `wpfy config`, `wpfy edit`, and `wpfy refresh`.
- Canonical flat runtime commands: `wpfy compose`, `wpfy up`, `wpfy down`, `wpfy exec`, `wpfy cp`, and `wpfy pull`.
- Flat convenience aliases for existing grouped site behavior: `wpfy run`, `wpfy backup`, `wpfy restore`, `wpfy rm`, `wpfy wp`, plus `wpfy version`.
- Public beta documentation set: rewritten `README.md`, `SECURITY.md`, `CONTRIBUTING.md`, `ROADMAP.md`, issue templates, and a public repository audit report (`docs/public-beta-audit.md`).
- CI workflow running the pytest suite on pushes and pull requests.

### Changed
- Phase F bounds four runtime hot paths without changing CLI behavior: Cloudflare CIDRs parse once per effective range set, public-IP fallback stops after the first IPv4, container health uses one batched `docker inspect`, and unchanged scaffolds leave registry bytes and timestamps untouched.
- Phase E consolidates SMTP, Cloudflare DNS, and stored S3 config reads through the no-follow env reader; exact-value error redaction now handles empty, duplicate, and overlapping secrets; cron and backup schedules share tested systemd mechanics; matching CLI secret input and health/project defaults have one source. Symlink-backed secret configs now fail with controlled domain errors.
- Phase D moved shared-stack operations into `stack.py`, cache selection/execution into `cache_operations.py`, and log/reset/WP execution behind public `site_runtime.py` APIs used by both CLI and panel. `stack purge` now requires `--force` and propagates stop/teardown failures; requested cache-operation failures now return non-zero.
- Phase C repair aligns file-backed SigV4 `SignedHeaders` with the canonical header block; uses descriptor-relative no-follow reads/writes for managed site environments and scaffold files; rejects WordPress core, restore, and ownership traversal through destination symlinks; gates scaffold-driven runtime starts on ownership success; rejects non-directory roots, special members, and `db-data/` payloads before runtime stop; reports post-stop replacement failures cleanly; and blocks partial bootstrap retries before app mutation while runtime is active.
- Phase C keeps verified site/edge S3-compatible archive uploads file-backed, fixed-length, and fully payload-signed; remote restore objects stream to private cleanup-safe temporary files and validate before live mutation.
- Fresh WordPress bootstrap now resolves the latest stable en_US release and verifies the versioned official tarball against WordPress.org's published SHA-1 before extraction, failing closed on missing, malformed, or mismatched metadata.
- Phase B CLI correctness: service inspection now uses authoritative structured facts, `site list` safely reconciles canonical filesystem state without no-op rewrites, ignored list filters are removed, update mismatches are reported neutrally, and runtime/type-handler contracts are truthful.
- Phase A safety gates now publish backups only after archive verification, remove SQL staging on every exit, require a complete database backup and confirmed runtime stop before deletion, commit maintenance state only after Compose success, require a confirmed ACME backup/write before renewal reload, and stop site creation after unexpected WordPress bootstrap failures.
- Reduced per-site health and security audit subprocess fan-out, cached Docker Compose capability checks per CLI process, streamed WordPress/SQL payloads instead of buffering them in memory, and split path/runtime ownership out of `site_layout.py`.
- Replaced the root `DESIGN.md` reference from HashiCorp-inspired styling to a Cohere-inspired website design direction.
- Fixed wildcard SSL Compose labels so `HostRegexp` backslashes render as valid YAML for Docker Compose/Traefik.
- Clarified the Page 9 CLI policy: grouped `site` and `stack` namespaces are retained for this release, while flat `run`, `backup`, `restore`, `wp`, `rm`, and `config` remain primary where exact equivalents exist.
- Page 8 VM validation now records unexpected non-zero exits into `validation-failures.txt`, forces non-interactive SMTP clear during ops validation, waits for restored WordPress readiness before restore/pre-reboot evidence, and labels skipped optional scanners explicitly.
- VM release readiness now explicitly requires disposable-VPS evidence; Page 9 keeps grouped stack and grouped site status/SSL/list/show surfaces because they have no exact flat replacements.
- Flat CLI is now the canonical VM/operator direction where exact equivalents exist; grouped `wpfy site ...` and `wpfy stack ...` parser surfaces remain supported for retained and compatibility operations this release.
- Split the marketing website and documentation/knowledge-base source into separate local repositories. The application repository now keeps the CLI, installer, runtime Docker assets, tests, and release automation.
- Consolidated flavor ownership and removed stale internal compatibility/test helpers without changing runtime behavior.

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

# wpfy Roadmap

This roadmap reflects current intent and will evolve with beta feedback. Nothing here is a committed delivery date.

## 1. Beta hardening (now)

- Validate the full lifecycle (install → create → SSL → backup → restore → delete) on fresh VPS instances across major providers.
- Broaden real-world coverage of the SSL preflight: varied DNS setups, IPv6-only hosts, Cloudflare configurations.
- Tighten error messages and recovery guidance for the most common failure modes (DNS not ready, Docker not running, low disk).
- Resolve the version-string inconsistency between package metadata and the CLI, and establish tagged releases.

## 2. Installer hardening

- Publish tagged release archives with published SHA-256 checksums, and make checksum-pinned installs (`WPFY_REF` + `WPFY_SOURCE_SHA256`) the documented default instead of installing from `main`.
- Expand pre-install environment checks (Docker availability, kernel/cgroup features, disk space) with actionable messages.
- Idempotent re-runs and a clearly documented uninstall path.

## 3. Documentation

- Per-command reference documentation beyond `--help`.
- Operational guides: moving a site between servers using backup/restore, running behind Cloudflare, troubleshooting SSL issuance.
- A compatibility matrix (Ubuntu releases, Docker Engine versions, architectures) backed by actual test runs.

## 4. Production readiness

- Independent review of the per-site isolation model (UIDs, networks, volumes).
- Backup retention/rotation policies and documented off-host backup workflows.
- Update/upgrade story for running sites (image refresh cadence, MariaDB major upgrades).
- Monitoring/health hooks suitable for external alerting.

## 5. Future features (v2 candidates)

- Wildcard SSL certificate support.
- Database/system helper tools: phpMyAdmin, Adminer, Composer, MySQLTuner.
- `wpfy stack migrate`: assisted migration from host-level (non-Docker) WordPress stacks.
- Additional cache flavors and tuning profiles.
- Multi-server awareness (longer-term exploration).

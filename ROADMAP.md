# wpfy Roadmap

This roadmap reflects current intent and will evolve with beta feedback. Nothing here is a committed delivery date.

## 1. Beta hardening (now)

- Validate the full lifecycle (install → create → SSL → backup → restore → delete) on fresh VPS instances across major providers.
- Broaden real-world coverage of the SSL preflight: varied DNS setups, IPv6-only hosts, Cloudflare configurations.
- Tighten error messages and recovery guidance for the most common failure modes (DNS not ready, Docker not running, low disk).
- Validate RC2 from its tagged public artifact, including anonymous image pulls,
  installer checksum verification, and the destructive lifecycle matrix.

## 2. Installer hardening

- Keep tagged archive checksums and checksum-pinned installs (`WPFY_REF` +
  `WPFY_SOURCE_SHA256`) as release requirements.
- Expand pre-install environment checks (Docker availability, kernel/cgroup features, disk space) with actionable messages.
- Idempotent re-runs and a clearly documented uninstall path.

## 3. Documentation

- A compatibility matrix (Ubuntu releases, Docker Engine versions, architectures) backed by actual test runs.

## 4. Production readiness

- Independent review of the per-site isolation model (UIDs, networks, volumes).
- Update/upgrade story for running sites (image refresh cadence, MariaDB major upgrades).
- Monitoring/health hooks suitable for external alerting.

## 5. Future features (v2 candidates)

- `wpfy stack migrate`: assisted migration from host-level (non-Docker) WordPress stacks.
- Additional cache flavors and tuning profiles.
- Multi-server awareness (longer-term exploration).

# wpfy Roadmap

This roadmap reflects current intent and will evolve with feedback. Nothing here is a committed delivery date. For what already shipped, see [CHANGELOG.md](CHANGELOG.md); for architectural decisions, see the ADR log linked from `wpfy-docs`.

The panel now runs on the rebuilt Tabler client (ADR 0032) with a host firewall page (ufw + fail2ban), and exposure has two opt-in paths — domainless self-signed exposure (ADR 0033) alongside domain-based Traefik exposure behind the new Docker socket proxy (ADR 0034). The items below build on that baseline.

## Near-term (v1 gates)

- Move validation from "proven as written config" to "proven live": the Traefik Docker socket-proxy allowlist (ADR 0034), fail2ban banning on a real host, ufw and IPv6 beyond one box, a diagnostics-redaction re-probe against a live panel, real-provider S3, real systemd timers, destructive shared-stack mutations, and an external scanner run.

## Later

- Event-driven alerting on top of SMTP (v1.1). SMTP is transport-only in v1: the panel stores transport settings and sends a test message, and nothing sends mail when an event or failure occurs. Building it means global SMTP with per-site propagation and event-driven alert rules. ADR 0037 (2026-09-01) defers this to v1.1 and pins its constraints: production SMTP credentials must not be shared directly across site containers, and the secrets storage/isolation design is deferred to an implementation ADR that must be written before any alerting code ships.
- Give the panel limiter a global ceiling. It is per-client-IP, so a distributed flood is throttled per source and not in aggregate, and the bucket table is bounded by TTL pruning rather than a hard cap.
- Revisit the domainless first-run setup secret being consumed on a validation failure (deliberate and tested today, worth reconsidering).
- A compatibility matrix (Ubuntu releases, Docker Engine versions, architectures) backed by real test runs.
- Independent review of the per-site isolation model (UIDs, networks, volumes).
- An update/upgrade story for running sites: image refresh cadence, MariaDB major upgrades.
- `wpfy stack migrate`: assisted migration from host-level (non-Docker) WordPress stacks.
- Additional cache flavors and tuning profiles; multi-server awareness (longer-term exploration).

## Explicitly not doing

- Host-level Nginx/PHP/MariaDB/Redis management — Docker Compose only, by design.
- Hosting mutually untrusted tenants on a shared host.
- Shipping a test suite in the public mirror — deliberate; the mirror carries source only.

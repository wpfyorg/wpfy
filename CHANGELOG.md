# Changelog

All notable changes to wpfy will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project aims to follow [Semantic Versioning](https://semver.org/) once it leaves beta.

## [Unreleased]

## [1.0.0-rc4] - 2026-08-02

### Added

- Serve WP Rocket's page cache directly from nginx on sites using the `wp-rocket` integration, via an adapted [Rocket-Nginx](https://github.com/satellitewp/rocket-nginx) 3.1.2 block (MIT). An anonymous hit is answered from WP Rocket's cache file with no PHP, WordPress or MySQL in the request path, and reports `X-Wpfy-Cache: HIT`. wpfy's existing `$wpfy_skip_cache` rules remain the sole authority on whether a request may be served from cache, so a logged-in, POST, query-string or `/wp-admin` request still reaches PHP; upstream's own cookie and method conditions are deliberately not carried, to keep one authority for the invariant. wpfy's server-side configuration for `wp-rocket` was previously inert — it emitted `fastcgi_cache_bypass` directives that mean nothing without a FastCGI cache zone — so every request traversed PHP. See ADR 0029.
- Delete WP Rocket's cached files during `wpfy cache <domain> purge` as a separate `rocket` layer, whether or not `wp rocket clean` succeeded. nginx answers from those files without consulting PHP, so a failed plugin command would otherwise leave purged pages still being served.

### Fixed

- Re-emit the vhost's security headers inside any generated nginx location that adds a header of its own. nginx's `add_header` inheritance is all-or-nothing, so the new cached-page location would otherwise have served WP Rocket's cached HTML without `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy` or HSTS. The header set now has a single definition that the vhost and the cache snippet both read.

## [1.0.0-rc3] - 2026-08-01

### Added

- Add the isolated `wpfy-agent` development workflow CLI.
- Validate `php/custom.ini` with the site's own PHP image before recreating the PHP container, and add `wpfy site php <domain> validate` so an operator can check a file before it costs an outage. Only a syntax error PHP itself reports refuses the recreate; an unverifiable file proceeds, so a Docker hiccup never keeps a site down.
- Record `cache.page.set`, `cache.object.set` and `cache.purge` events so cache configuration changes are auditable.
- Expose the nginx page-cache status as the `X-Wpfy-Cache` response header on sites using the `wpfc` integration.

### Fixed

- Purge the FlyingPress plugin cache with `wp flying-press purge-everything` instead of `wp flying-press purge`, which FlyingPress does not register. Purging a FlyingPress site previously cleared only the nginx layer while the plugin layer failed with `Error: Invalid command: purge`; the failure was invisible to the offline suite because it stubs `subprocess.run`.
- Accept the panel access token from `--token-file` or `WPFY_PANEL_TOKEN`, so it need never appear in the process command line where any local user can read it. `--token` still works and now warns.
- Remove containers a site no longer declares when starting its runtime. Disabling the Redis object cache dropped the service from `compose.yaml` but left the container running outside wpfy's lifecycle.
- Key panel failed-login throttling on the real client rather than the socket peer. Published through Traefik every request's peer is the proxy, so ten failed sign-ins from any one caller cooled down every remote operator for 60 seconds. A forwarded client address is honoured only when the connection itself arrives from the discovered edge network, and the chain is walked right-to-left past known hops; when no edge can be discovered the behaviour falls back to the peer rather than trusting an unverifiable header.
- Treat the rendered `traefik.yml` as authoritative when deciding whether the Traefik static configuration needs applying, instead of trusting a recorded hash alone. A recorded state that disagreed with the file made `wpfy stack acme-email` report "Traefik already has desired config" while the running proxy still used the old ACME contact, and the same stale comparison skipped the force-recreate, so a corrected address was written to disk but never loaded.
- Report per-layer status in the `cache.purge` audit event. It previously listed the layers attempted (`layers=plugin,nginx,redis`) with `outcome: ok` even when only nginx cleared; it now records `layers=plugin:ok,nginx:ok,redis:skipped` and a new `partial` outcome for a purge where some layer did not clear.

### First-run panel setup and telemetry (2026-07-28)
- Added a run-token-authorized two-step browser setup wizard that creates the first administrator, records separate licence and telemetry choices, retires both setup routes with HTTP 410 after first use, refuses edge-bound account creation, and applies the existing client throttle plus a 12-character password minimum.
- Extended panel users with forward-compatible first-name, last-name, and email fields; added mode-0600 install-scoped state with a stable UUID; and added verified-before-persisted TOTP enrollment or an explicit consequence-confirmed skip.
- Vendored pinned MIT QRCode.js with source revision, licence, URL, and SHA-256 while preserving the existing CSP.
- Added opt-out anonymous telemetry with an exhaustive seven-field payload, at-most-daily background stdlib delivery, inert unset endpoint, `WPFY_TELEMETRY=0`, and `wpfy telemetry status|enable|disable`.

### Security hardening corrections (2026-07-28)
- Remove the tracked internal backup artifact and exclude evidence, agent, graph, audit, log, test, and editor-tool trees from the staged production application payload.
- Separate requested SSL routing from observed certificate issuance in site list/info/status, reserving `ssl=enabled` for a matching certificate in Traefik's local ACME state and reporting unissued intent as `ssl=requested`.
- Recreate a running Traefik container only when its static configuration changes, so updated ACME contact settings take effect without restarting the edge on unchanged installs.
- Derive PHP's HTTPS state from `X-Forwarded-Proto` only when the original connection belongs to the discovered Traefik edge CIDR, fixing WordPress admin redirect loops without trusting client-spoofed headers or forcing plain-HTTP sites secure.
- Preserve nginx's embedded access-log timestamp during fail2ban matching, so the existing failed-login status rule reaches live combined-format lines instead of being applied after fail2ban strips the middle of the regex target.
- Make `panel expose` report router configuration rather than public readiness until the required service is installed, and add `panel expose --status` for router/domain/service inspection.
- Normalize run-token authentication to the same principal mapping shape used by named sessions, so identity and TOTP routes return defined responses instead of indexing a string.
- Return a generic JSON 500 for unexpected panel route exceptions while logging the traceback server-side and preserving unread-body connection closure.
- Close panel connections before responding when a declared request body remains unread, preventing keep-alive request desynchronization behind pooled Traefik connections.
- Late-bind settings paths in modules that previously captured `PATHS` during import, so redirected test roots consistently apply across the package.

### Phase 7e fail2ban and WordPress hardening (2026-07-28)
- Added opt-in per-site `wpfy site security <domain> fail2ban on|off` jails with a compiled-testable WordPress filter, per-site host-visible combined access logs, logrotate retention, and `DOCKER-USER` Docker ban actions.
- Made Nginx resolve every access-log client through the discovered Traefik edge CIDRs before logging, so a fail2ban jail never bans the shared proxy address.
- Blocked WordPress installer and upgrader endpoints plus narrow UpdraftPlus and Sucuri archive locations, and explicitly disabled the legacy `X-XSS-Protection` browser filter without blocking ordinary WordPress paths.

### Phase 7b Optional Traefik Panel Exposure (2026-07-28)
- Added opt-in `wpfy panel expose` routing through Traefik with mandatory named-user authentication, at least one enrolled TOTP factor, DNS/IP preflight, and exact-domain typed confirmation.
- Added a dedicated `wpfy-panel-edge` bridge and edge-gateway-only panel service bind; wildcard, public, hostname, and off-network binds remain refused while ad-hoc `wpfy panel` stays loopback-only.
- Added a read-only Traefik file-provider mount, TLS-only `websecure` router with ACME and edge rate limiting, truthful filesystem-derived exposure status, and idempotent disable/reversal even without bookkeeping state.
- Added token-free systemd service installation/removal plus hostile-domain, secret-leakage, privilege, mount, idempotency, and reversal coverage.

### Phase 7a Panel Authentication, Roles, and 2FA (2026-07-27)
- Added a mode-0600 disk-backed panel user store with per-user scrypt salts, password verification that masks unknown users, administrator and site-manager roles, and CLI user/site-assignment management without argv secrets.
- Added in-memory bearer sessions with idle and absolute expiry, logout invalidation, per-user login lockouts with event records, RFC 6238 TOTP enrollment and replay prevention, and immediate run-token retirement once any user exists.
- Added login, identity, TOTP, and administrator user APIs; centralized default-deny authorization now covers every panel route, while site, job, and event responses are filtered to a site-manager's assigned domains.
- Hardened login and account lifecycle edges: TOTP accepts ASCII digits only, locked and unknown refusals perform equal dummy-scrypt work, and every non-empty user store retains an administrator while final-user removal restores run-token bootstrap.

### Phase 5a Metrics sampler (2026-07-27)
- Added a stdlib SQLite time-series store in the state directory with WAL-mode concurrent appends, indexed scope/range reads, and 14-day retention.
- Added host CPU, memory, disk, and load sampling plus one-shot whole-machine Docker stats attribution to exact managed domain scopes.
- Added `wpfy metrics sample|show|prune`, minute-tick sampling, daily pruning, and explicit cron-log failures without interrupting the other minute tenants.
- Fixed the daily all-site health summary to use `HealthResult` readiness semantics instead of the nonexistent `exit_code` field.

### Phase 4a.2 Per-site security lockout controls (2026-07-27)
- Added per-site basic auth with one-time generated passwords, redacted events, an out-of-document-root `nginx/htpasswd` hash, and in-place rotation for the individually mounted credential file.
- Added Traefik edge Cloudflare-only allow lists sourced from effective Cloudflare ranges, plus DNS lockout preflight warnings and CLI `--force` handling.
- Replaced hostname real-IP trust with the discovered wpfy edge CIDR and added Cloudflare hop trust for proxied sites; discovery failures return non-zero after installing fail-closed rules.
- Exempted the managed health endpoint from server-level basic auth so Docker healthchecks remain healthy.
- Verified 33 Phase 4 security gates, real-image `nginx -t`, Compose config validation, and live old-password rejection/new-password acceptance after rotation. Cron gates remain on their separate branch.

### Release
- Prepared `1.0.0rc2`: package and CLI version identity now matches planned
  `v1.0.0-rc2` tag. Public source retains Python tests and public CI; package
  artifacts and installed production source exclude tests.

### Added
- Phase 4a.3 per-site cron foundations: atomic `<site>/cron.json` job storage, write-time schedule and service validation, a pure five-field matcher with traditional day-of-month/day-of-week OR semantics, and backup/regeneration coverage. Job execution, locking, the minute tick, and CLI remain Phase 4a.4.
- Phase 3a native cache integration: orthogonal page/object cache state with legacy migration, free-plugin installation, paid/BYO staging, wpfy's FastCGI cache rules, Redis Object Cache wiring, layered purge, and `wpfy cache show|set|object|purge` CLI operations. Panel adoption remains Phase 3b.
- Per-site `cache-data/` bind mounts for `wpfc` FastCGI cache files, owned by each site's uid and kept outside the backup archive so unprivileged Nginx can start without the image's default cache directory.
- Phase 2b panel UI: per-site Databases, PHP Settings, and Vhost tabs with typed destructive confirmations, one-time database credentials, Adminer loopback guidance, PHP dry-run previews, and verbatim Nginx validation output.
- Phase 2a operation and control surfaces: isolated per-site databases and scoped users, loopback-only Adminer, validated per-site PHP overrides with operator-owned custom ini files, and fail-closed validated Nginx custom includes exposed through CLI and panel APIs.
- Panel Phase 1a backend and UI: declarative permission-aware API routes, asynchronous site lifecycle jobs with live progress and one-time credential delivery, append-only redacted operation events, panel site create/delete/config/SFTP rotation endpoints, dry-run change previews, events and per-site activity views, client-side site search, and `wpfy log events`.
- Local browser control panel: `wpfy panel` serves a loopback-only, token-protected dashboard (stdlib HTTP server + static UI, no new dependencies). It reuses the same Python operation layer as the CLI for overview, site list/detail, health, diagnostics, logs, backups/restore, runtime start/stop/restart, SFTP enable/disable/status, a WP-CLI runner, and PHP version changes. Remote access is documented via SSH tunnel only; generated credentials are delivered only through one-time payloads and are not returned again after consumption.
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
- Phase 4a.5 cron correction enforces job timeouts inside the selected site container with a process-group supervisor and longer host-side backstop, probes Compose runtime state instead of classifying job output text, and removes the profile-only `wpcli` service from new cron targets while migrating prior entries to the running `app` service.
- Phase 3a correction updates individually bind-mounted generated files in place so running containers keep the same inode, and site health/diagnostics now run `nginx -t` to expose rejected generated configuration. Cache reload failures retry briefly for delayed shared-folder propagation, then return non-zero with a `wpfy debug` next step.
- Phase 3a correction writes trusted deterministic cache snippets without scaffold-time container validation, avoiding read-only include mount failures and the unavailable `app` upstream while retaining fail-closed validation for operator-owned `custom.conf`.
- Phase 2a correction hardens database grants against system schemas, redacts database-user passwords from SQL failures, creates bind-mount source files before publishing `compose.yaml`, clarifies stopped-runtime Nginx validation failures, and covers multi-database dump/restore shape.
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

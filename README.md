# wpfy

**Docker-first WordPress VPS installer and server management CLI.**

wpfy turns a fresh Ubuntu VPS into a managed WordPress host. Every site runs in its own isolated Docker Compose stack — Nginx, PHP-FPM, MariaDB, and optional Redis — behind a shared Traefik edge proxy that handles routing and Let's Encrypt TLS. One CLI manages the full lifecycle: create, secure, back up, restore, diagnose, and remove sites.

> ## ⚠️ Beta status
>
> wpfy is **beta / early-access software**. The core feature set is implemented and covered by an extensive automated test suite, but it has not yet been hardened by broad real-world use.
>
> - **Test on a fresh or disposable VPS first.** Do not point wpfy at a server hosting anything you can't afford to lose.
> - **Review before production use.** Read the [Safety model](#safety-model--isolation) and [Known limitations](#known-limitations) sections before hosting real traffic.
> - Expect rough edges, and please [report them](#contributing) — beta feedback directly shapes the roadmap.

## What wpfy does

- Installs and manages a complete WordPress hosting environment on an Ubuntu VPS using Docker and Docker Compose — no host-level Nginx, PHP, or MariaDB packages.
- Gives **each site its own Compose project**: dedicated containers, network, volumes, database, credentials, and Unix UID. Sites cannot read each other's files or databases.
- Runs a shared **Traefik edge proxy** that routes traffic per domain and obtains Let's Encrypt certificates automatically.
- Performs **DNS/IP preflight checks** before requesting certificates, with automatic Cloudflare detection.
- Provides **backups, restore, diagnostics, log access, security auditing, and per-site SFTP** from a single CLI.
- Provides WordPress cron interval runners, optional systemd timers, and SMTP config/test helpers without automatic backup or update side effects.

### Why Docker-first?

Traditional WordPress stack managers install Nginx, PHP, and MySQL directly on the host, so every site shares one PHP version, one database server, and one blast radius. wpfy instead composes each site from containers:

- **Isolation** — a compromised or misbehaving site is confined to its own containers, network, and unprivileged UID.
- **Per-site PHP versions** — run PHP 7.4 on a legacy site and 8.4 on a new one, side by side.
- **Clean removal** — deleting a site removes its containers, volumes, and files without leaving host packages behind.
- **Reproducibility** — a site is fully described by its `compose.yaml` and `.env`, which is also what makes backup and restore reliable.

## Current capabilities

| Area | Status |
|---|---|
| Ubuntu installer (`install.sh`) | ✅ Implemented |
| Per-site Docker Compose WordPress stacks | ✅ Implemented |
| Traefik edge proxy with Let's Encrypt | ✅ Implemented |
| SSL DNS/IP preflight + Cloudflare detection | ✅ Implemented |
| WordPress provisioning via wp-cli | ✅ Implemented |
| Backups and restore (files + database) | ✅ Implemented |
| WordPress cron runners and systemd timers | ✅ Implemented |
| SMTP config and explicit test sends | ✅ Implemented |
| Diagnostics (`wpfy debug`) | ✅ Implemented |
| Per-site SFTP lifecycle | ✅ Implemented |
| Security audit (`wpfy secure`) | ✅ Implemented |
| Wildcard SSL certificates | ✅ Implemented for Cloudflare DNS |
| phpMyAdmin / Adminer / Composer helpers | ✅ Pull-only helper images |
| MySQLTuner helper | ⏳ Skipped until a vetted pinned image exists |
| Migration from host-level stacks (`stack migrate`) | ❌ Not implemented in v1 |
| Backup retention/remote ops/edge backup | ✅ Implemented |

## Installation

On a fresh Ubuntu VPS, as a user with sudo access:

```bash
curl -fsSL https://raw.githubusercontent.com/wpfyorg/wpfy/main/install.sh | sudo bash
```

The installer detects your system, downloads the wpfy source archive from GitHub, and runs a step-by-step guided install. It logs to `/var/log/wpfy/install.log` and supports `--dry-run`, `--verbose`, and `--no-color`.

> **Note on piping to bash:** the command above fetches the installer from the mutable `main` branch. For a reviewable, reproducible install, download the script first and inspect it, and pin the source:
>
> ```bash
> curl -fsSLO https://raw.githubusercontent.com/wpfyorg/wpfy/main/install.sh
> less install.sh   # review before running
> sudo WPFY_REF=<tag-or-commit> WPFY_SOURCE_SHA256=<checksum> bash install.sh
> ```
>
> Supported environment overrides: `WPFY_REF` (branch/tag/commit, default `main`), `WPFY_SOURCE_SHA256` (verify the downloaded archive), `WPFY_SOURCE_ARCHIVE`, `WPFY_REPO_OWNER`, `WPFY_REPO_NAME`.

### Running from source (development)

```bash
git clone https://github.com/wpfyorg/wpfy.git
cd wpfy
PYTHONPATH=src python3 -m wpfy --help
```

## Repository split

This repository is the application and installer repository. The marketing
website and documentation are maintained separately from this public runtime
surface.

## Prerequisites

- **Ubuntu VPS** (Ubuntu-first for v1; other Linux distributions are untested).
- **Docker Engine with the Docker Compose plugin** (`docker compose`).
- **Python 3.10+**.
- **Root/sudo access** for installation and site management.
- **A domain with an A/AAAA record pointing at the server's public IP** before enabling SSL (or a Cloudflare-proxied DNS record — wpfy detects this automatically).
- Outbound internet access (GitHub, Docker Hub / ghcr.io, Let's Encrypt, and public-IP detection services).

## Quick start

```bash
# 1. Install the shared stack (pull images, start the Traefik edge proxy)
wpfy stack install --nginx --php --mysql

# 2. Create a WordPress site
wpfy site create example.com --wp

# 3. Add SSL once DNS points at this server
wpfy site ssl example.com --letsencrypt

# 4. Check that everything is healthy
wpfy site status example.com
wpfy debug
```

Or create the site with SSL in one step:

```bash
wpfy site create example.com --wp -le
```

## Common commands

Flat commands are the canonical VM/operator target surface. During migration, grouped `wpfy site ...` and `wpfy stack ...` commands remain temporary compatibility surfaces; the current flat commands reuse the proven grouped implementations until the cleanup page removes grouped parsers.

| Command | Description |
|---|---|
| `wpfy site create <domain> --wp` | Create a WordPress site (add `-le` for SSL, `--php 8.3` to pick a PHP version) |
| `wpfy run <domain> --wp` | Create a WordPress site through the flat CLI (currently delegates to `wpfy site create`) |
| `wpfy site create <domain> --html` | Create a static HTML site |
| `wpfy site list` | List managed sites |
| `wpfy site info <domain>` | Show site metadata and file paths |
| `wpfy site status <domain>` | Show site readiness and runtime health |
| `wpfy site ssl <domain> --letsencrypt` | Enable Let's Encrypt SSL (runs DNS preflight first) |
| `wpfy site ssl <domain> --status` | Show certificate status and expiry |
| `wpfy site ssl <domain> --renew` | Force certificate renewal |
| `wpfy site wp <domain> <wp-cli args>` | Run wp-cli inside the site's container (e.g. `wpfy site wp example.com plugin list`) |
| `wpfy site update <domain> --php 8.4` | Change a site's PHP version |
| `wpfy config <domain>` | Show sanitized config status without printing raw `.env` contents |
| `wpfy config <domain> --php 8.4` | Apply controlled config mutations through the site lifecycle path |
| `wpfy edit <domain> [--print-path]` | Print or safely open the authoritative `.env` path with a backup |
| `wpfy refresh <domain\|all> [--restart]` | Regenerate scaffold files from authoritative state; restart only when requested |
| `wpfy up <domain>` | Start a site's Compose runtime |
| `wpfy down <domain> [--volumes]` | Stop a site's Compose runtime without removing volumes unless requested |
| `wpfy compose <domain> -- <args>` | Run Docker Compose for one managed site |
| `wpfy exec <domain> [service] -- <command>` | Run a command in a site service (`app`, `web`, `db`, `redis`, `wpcli`, or `sftp`) |
| `wpfy cp <domain> <source> <destination>` | Copy one file into or out of a site service |
| `wpfy pull <domain> [--all\|--service <service>]` | Pull images for one managed site |
| `wpfy healthcheck [all\|system\|disk\|load\|app]` | Run script-safe operator health checks |
| `wpfy motd [--compact]` | Print a safe login-style operator summary |
| `wpfy utility password\|username\|uid\|token\|htpasswd` | Generate offline utility values without Docker |
| `wpfy cron minute\|five-minute\|hourly\|six-hour\|daily\|weekly` | Run due WordPress cron events and small safe interval tasks |
| `wpfy cron install\|status\|disable` | Manage systemd timers for the cron intervals |
| `wpfy smtp set\|status\|test\|clear` | Store redacted SMTP settings and run explicit dry-run/test sends |
| `wpfy dns cloudflare set\|status\|test\|clear` | Store redacted Cloudflare token for wildcard SSL |
| `wpfy site backup <domain>` | Create a backup archive (files + database) |
| `wpfy backup <domain>` | Create a backup through the flat CLI |
| `wpfy backup prune <domain\|all> --keep N` | Prune local backup archives |
| `wpfy backup remote list\|restore\|delete\|prune <domain>` | Manage S3-compatible remote archives |
| `wpfy backup edge` | Back up Traefik config and ACME state |
| `wpfy backup storage set\|status\|test\|clear` | Manage default or named S3-compatible storage profiles |
| `wpfy backup schedule daily\|weekly\|status\|disable` | Manage one recurring all-site backup timer |
| `wpfy site restore <domain> <backup\|--latest>` | Restore a site from an explicit backup archive |
| `wpfy restore <domain> <backup\|--latest>` | Restore through the flat CLI |
| `wpfy site delete <domain>` | Remove a site and its resources (asks for confirmation) |
| `wpfy rm <domain>` | Delete through the flat CLI with the same confirmation rules as `wpfy site delete` |
| `wpfy wp <domain> <wp-cli args>` | Run wp-cli through the flat CLI (currently delegates to `wpfy site wp`) |
| `wpfy sftp <domain> --enable` | Enable SFTP access for a site |
| `wpfy stack status` | Show shared stack component status |
| `wpfy log show <domain> --nginx -f` | Follow a site's Nginx logs |
| `wpfy clean <domain> --all` | Clear site caches (Nginx, Redis, OPcache) |
| `wpfy secure <domain>` | Audit site/container hardening |
| `wpfy debug [domain]` | Run diagnostics across Docker, Traefik, and sites |
| `wpfy update --check` | Check for new wpfy releases |
| `wpfy version` | Print the installed wpfy version |

Run `wpfy <command> --help` for full flags on any command.

## Release validation

Page 8 validation now treats the flat CLI as the VM/operator surface under test. The disposable-VPS runner exercises flat site creation, runtime commands, config/refresh, backup/restore/listing, cron, SMTP dry-run/status, operator utilities, log cron, and flat deletion. Grouped `wpfy stack install|status` remains in validation because there is no flat stack replacement yet, and grouped site status/SSL probes remain where the flat CLI has no exact replacement.

Local release checks:

```bash
PYTHONPATH=src pytest -q
python3 -m py_compile src/wpfy/*.py
bash -n wpfy install.sh scripts/vps-release-validation.sh scripts/vps-release-validation-remote.sh
graphify update .
```

VM evidence is required before this release is considered VM-ready; parser tests alone are not enough. Evidence review must confirm `validation-failures.txt` is absent or empty and must also scan must-pass outputs for unexpected `[exit N]`, `result: FAIL`, and command-specific failure lines. If the disposable VPS cannot be reached, record the SSH/DNS blocker and keep grouped-parser cleanup blocked.

## Architecture overview

```text
                    Internet
                       │
              ┌────────▼────────┐
              │     Traefik      │  shared edge proxy
              │  :80 / :443 +    │  Let's Encrypt ACME
              │  ACME resolver   │
              └───┬─────────┬───┘
        wpfy network (shared, routing only)
          ┌───────┘         └────────┐
┌─────────▼─────────┐      ┌─────────▼─────────┐
│  site: a.com      │      │  site: b.com      │
│  ┌─────────────┐  │      │  ┌─────────────┐  │
│  │ nginx (web) │  │      │  │ nginx (web) │  │
│  │ php-fpm     │  │      │  │ php-fpm     │  │
│  │ mariadb     │  │      │  │ mariadb     │  │
│  │ redis (opt) │  │      │  │ redis (opt) │  │
│  │ sftp (opt)  │  │      │  │ sftp (opt)  │  │
│  └─────────────┘  │      │  └─────────────┘  │
│  private network  │      │  private network  │
│  unique UID       │      │  unique UID       │
└───────────────────┘      └───────────────────┘
```

Each site lives at `/opt/wpfy/sites/<domain>/`:

```text
/opt/wpfy/sites/example.com/
├── compose.yaml      # the site's Docker Compose definition
├── .env              # site configuration and credentials (root-only)
├── app/              # WordPress docroot (owned by the site's UID)
├── nginx/            # per-site Nginx configuration
├── php/              # per-site PHP configuration
├── db-data/          # MariaDB data
└── redis-data/       # Redis data (if enabled)
```

Container images used per site: `nginxinc/nginx-unprivileged` (web), `ghcr.io/wpfyorg/php-fpm` (PHP 7.4–8.4), `mariadb:11.4` (database), `redis:7.2-alpine` (optional object cache), `atmoz/sftp` (optional SFTP).

## Safety model / isolation

- **One Compose project per site** — separate containers, volumes, and database per domain.
- **Unique Unix UID per site** (allocated from 100000 upward). Site files are owned by that UID and the site's containers run as it, so site A's processes cannot read site B's files even if a container is compromised.
- **Private per-site networks** — a site's database and Redis are only reachable from that site's containers. Only the web container joins the shared Traefik network.
- **Unprivileged web server** — Nginx runs as a non-root container (`nginx-unprivileged`).
- **Credential hygiene** — per-site secrets live in the site's `.env` with restrictive permissions; backup archives are written with `0600` permissions.

This is an isolation *model*, not a guarantee. As beta software, it has not yet had an independent security review — treat multi-tenant hosting of untrusted parties as out of scope for now.

## SSL and DNS behavior

SSL is **opt-in** via `-le` / `--letsencrypt` at create time, or later with `wpfy site ssl <domain> --letsencrypt`.

Before any certificate is requested, wpfy runs a **preflight check**:

1. Resolves the domain's A/AAAA records.
2. Detects the server's public IP (via api.ipify.org, ifconfig.me, or checkip.amazonaws.com).
3. Passes if the records match the server's IP, **or** if the domain resolves to Cloudflare's IP ranges (proxied mode).
4. Fails with a clear message otherwise — no certificate request is attempted against misconfigured DNS, which protects you from Let's Encrypt rate limits.

Certificates are obtained and renewed by **Traefik's ACME resolver**. For Cloudflare-proxied domains, wpfy automatically switches to HTTP-01 challenge mode (force with `--proxied` / `--no-proxied`). Check status anytime with `wpfy site ssl <domain> --status`; run only the preflight with `--preflight-only`.

**Wildcard certificates are supported with Cloudflare DNS only.**

## Backups and restore

```bash
wpfy backup example.com --list
wpfy backup example.com --path /root/wpfy-backups
wpfy backup example.com --s3 --profile weekly --keep-local 7
wpfy backup prune example.com --keep 7 --dry-run
wpfy backup remote list example.com --profile weekly
wpfy backup remote restore example.com --latest --profile weekly
wpfy backup edge --path /root/wpfy-edge-backups
wpfy backup all --path /root/wpfy-backups
printf '%s\n' '<secret-key>' | wpfy backup storage set --profile weekly --endpoint https://s3.example.com --bucket site-backups --region auto --access-key ... --secret-key-stdin
wpfy backup schedule daily --time 02:30 --s3
wpfy restore example.com --list
wpfy restore example.com --latest
wpfy site backup example.com
wpfy site restore example.com /var/lib/wpfy/backups/example.com/example.com-20260611120000.tar.gz
```

- Backups are written to `/var/lib/wpfy/backups/<domain>/<domain>-<timestamp>.tar.gz` with `0600` permissions.
- `wpfy backup <domain> --list` and `wpfy restore <domain> --list` print local archive candidates without reading archive contents.
- `wpfy backup <domain> --path <directory>` keeps the canonical local archive and copies the verified archive to the destination directory with `0600` permissions.
- `wpfy backup all [--path <directory>] [--s3]` processes every managed site in sorted order and reports per-site failures without stopping the whole run.
- `wpfy backup <domain> --s3` uploads the verified local archive to S3-compatible storage using `WPFY_BACKUP_S3_ENDPOINT`, `WPFY_BACKUP_S3_BUCKET`, `WPFY_BACKUP_S3_REGION`, `WPFY_BACKUP_S3_ACCESS_KEY`, `WPFY_BACKUP_S3_SECRET_KEY`, and optional `WPFY_BACKUP_S3_PREFIX`.
- `wpfy backup <domain> --keep-local N` prunes older local archives only after the new archive verifies.
- `wpfy backup prune <domain|all> --keep N [--dry-run]` prunes local archives explicitly.
- `wpfy restore <domain> --latest` restores the newest local archive only when explicitly requested; restore never chooses latest by default.
- `wpfy backup storage set/status/test/clear [--profile NAME]` stores the default target in `/etc/wpfy/backup-storage.env` or named targets in `/etc/wpfy/backup-storage.d/<profile>.env`, mode `0600`. Environment variables override only the default profile.
- `wpfy backup remote list|restore|delete|prune <domain> [--profile NAME]` operates only under the managed `<prefix>/<domain>/` key prefix. Delete/prune require `--force`; remote restore downloads to a temp file and validates before live mutation.
- `wpfy backup edge [--path DIR] [--s3 --profile NAME]` captures Traefik compose/static config and `acme.json` when available; `wpfy restore edge <archive> --force` validates members before writing and restarting Traefik.
- `wpfy backup schedule daily|weekly` installs one `systemd` timer that runs `wpfy backup all`; `status` shows whether it is configured, and `disable` stops the timer without deleting backup storage config.
- An archive contains the site's `compose.yaml`, `.env`, `app/` (WordPress files), `nginx/`, `php/`, and a SQL dump taken with `mariadb-dump --single-transaction` when the database is running.
- Every archive is verified after creation.
- Restore validates the archive and checks free disk space **before** touching the live site, stops the runtime, restores files and ownership, preserves the live database credentials, restarts the stack, and imports the SQL dump. An invalid archive aborts the restore with no changes made.

Remote lifecycle policy is wpfy-managed prune, not a provider bucket lifecycle API.

## Diagnostics

```bash
wpfy debug              # whole-server diagnostics
wpfy debug example.com  # one site
```

Checks include: Docker daemon availability, Traefik status, Docker disk usage, registry/filesystem consistency, per-site scaffold and WordPress bootstrap completeness, container health (web/app/db/redis), an HTTP probe against the site's health endpoint, and SSL certificate status/expiry. Results are reported as `[PASS]`, `[WARN]`, or `[FAIL]` lines — useful output to attach to bug reports (redact your domains if you prefer).

## SFTP lifecycle

```bash
wpfy sftp example.com --enable                 # auto-generates a password
wpfy sftp example.com --enable --password ...  # or bring your own
wpfy sftp example.com --status
wpfy sftp example.com --disable
```

Enabling SFTP adds an isolated `atmoz/sftp` container to the site's stack, chrooted to the site's docroot, with a unique host port allocated from 2222 upward. The username is `sftpuser`; the generated password is shown once at enable time. Disabling removes the container and its compose service. SFTP is per-site and off by default.

## Browser control panel

```bash
wpfy panel                    # serve on 127.0.0.1:8642 with a fresh token
wpfy panel --port 9000        # different port
wpfy panel --token <token>    # bring your own token (e.g. for scripted tunnels)
```

`wpfy panel` serves a local dashboard over the same operation layer the CLI uses — site table, health and diagnostics, container logs, backups and restore, runtime start/stop, SFTP toggle, a WP-CLI runner, and PHP version changes. It is **loopback-only by design**: the server refuses to bind non-loopback addresses, and every API request requires the bearer token printed at startup (the URL carries it in the fragment, which never reaches server logs).

To use it from your workstation against a VPS, tunnel the port over SSH and open the printed URL locally:

```bash
ssh -L 8642:127.0.0.1:8642 user@your-server
```

The panel never returns `.env` or state secrets, destructive actions (stop, restore, SFTP disable) require confirmation in the UI, and nothing is exposed publicly — there is no public web admin surface.

## Example workflows

**Launch a site behind Cloudflare:**

```bash
wpfy site create example.com --wp -le   # Cloudflare proxying is auto-detected
wpfy site ssl example.com --status
```

**Move a site to PHP 8.4 with a safety net:**

```bash
wpfy site backup example.com
wpfy site update example.com --php 8.4
wpfy site status example.com
wpfy site wp example.com core verify-checksums
```

**Give a developer file access without SSH:**

```bash
wpfy sftp example.com --enable
# share the printed host, port, and one-time credentials
wpfy sftp example.com --disable   # when they're done
```

**Decommission a site:**

```bash
wpfy site backup example.com      # keep a final archive
wpfy site delete example.com      # prompts: Delete example.com? [y/N]
```

## Known limitations

- **Beta software** — interfaces and behavior may change between releases.
- **Ubuntu-first** — other distributions are untested for v1.
- **Wildcard SSL is Cloudflare-only** — use `wpfy dns cloudflare set --token-stdin` and `--letsencrypt wildcard --dns cloudflare`.
- **Remote lifecycle is explicit** — wpfy prunes managed keys; it does not configure provider bucket lifecycle policies.
- **`wpfy stack migrate` is not implemented** — there is no automated migration from host-level (non-Docker) stacks yet.
- **Helper tools are opt-in prep only** — `--phpmyadmin`, `--adminer`, and `--composer` pull pinned-major helper images but do not expose a public dashboard. `--mysqltuner` skips until a vetted pinned image exists. Host-level options from classic stack managers (`--fail2ban`, `--ufw`, `--netdata`, etc.) are intentionally not managed by wpfy's Docker-first design — configure them on the host yourself.
- **Destructive commands:**
  - `wpfy site delete` asks for confirmation interactively, but proceeds without a prompt when run non-interactively (e.g., in scripts) — treat it as immediate in automation. `--force` skips the prompt explicitly.
  - `wpfy stack purge` removes the edge proxy Compose project **without a confirmation prompt**. Know what you're running.
- **No independent security audit yet** — see [Safety model](#safety-model--isolation).

## Roadmap

See [ROADMAP.md](ROADMAP.md). Headlines: beta hardening on real-world VPS providers, installer hardening (signed/checksummed release artifacts, pinned-version installs), expanded documentation, and deferred host-stack migration.

## Security

Please report vulnerabilities privately — see [SECURITY.md](SECURITY.md). Do not open public issues for security problems.

## Contributing

Bug reports, feedback from real VPS deployments, and pull requests are welcome — this is exactly what the beta period is for. See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, test instructions, and PR expectations.

## License

wpfy is licensed under the **GNU Affero General Public License v3.0** (AGPL-3.0-only). You can use, modify, and self-host wpfy freely; if you offer a modified wpfy as a network service, the AGPL requires you to make your modified source available to its users. See [LICENSE](LICENSE).

# wpfy Public Beta Readiness Audit

> **Scope disclaimer:** This is a **public repository exposure and documentation readiness audit, not a full penetration test or production security review**. It examines what is visible in this public repository, the accuracy of its documentation, and the safety of its published install path. It does not assess the runtime security of deployed wpfy servers.

## 1. Audit metadata

| | |
|---|---|
| **Audit date** | 2026-06-11 |
| **Branch** | `claude/wpfy-beta-launch-readiness-rbeepm` |
| **Base commit inspected** | `2fcf811` ("Security & correctness remediation pass: 12 fixes from fresh-eyes review") |
| **Audit type** | Public exposure + documentation readiness |
| **Test suite at time of audit** | 201 tests, all passing (`pytest`, 1.9s, offline) |

## 2. Files and directories reviewed

- Root files: `README.md`, `LICENSE`, `pyproject.toml`, `install.sh`, `wpfy` (installer wrapper), `.gitignore`
- `src/wpfy/` — all 13 Python modules (CLI, site lifecycle, site layout, certificate lifecycle, SFTP, registry, Traefik, diagnostics, PHP runtime, etc.)
- `tests/` — all 10 test files (~3,270 lines)
- `docker/php-fpm/` — PHP-FPM image definitions (7.4–8.4)
- `.github/workflows/` — all workflow files
- Recent git history (`git log`, recent diffs) for accidentally committed sensitive files

Searches performed: secrets patterns (password/secret/token/api_key/PRIVATE KEY/ssh-rsa), real-looking domains/IPs/emails/hostnames, local machine paths, committed logs/dumps/archives/temp files, TODO/FIXME/internal-plan comments, and workflow security anti-patterns.

## 3. Findings by severity

### Critical

**None found.** No secrets, credentials, keys, certificates, customer data, personal data, internal hostnames, or private IPs were found in the repository tree or recent history.

### High

**None found.**

### Medium

| # | Finding | Location | Status |
|---|---|---|---|
| M1 | **Install path pipes a script from the mutable `main` ref** (`curl … /main/install.sh \| sudo bash`). Anyone compromising the branch could alter installs. The installer already supports pinning (`WPFY_REF`, `WPFY_SOURCE_SHA256`) but this was undocumented. | `install.sh`, `README.md` | **Mitigated in docs**: README now documents the risk, a review-first flow, and checksum/ref pinning. Full fix (tagged releases with published checksums as default path) tracked in `ROADMAP.md` → human follow-up. |
| M2 | **`wpfy stack purge` removes the edge-proxy Compose project without a confirmation prompt.** | `src/wpfy/cli.py` (`handle_stack_purge`) | **Documented** in README *Known limitations*. Adding a prompt is a small code change left to maintainers (kept out of this docs-focused pass). |
| M3 | **Version inconsistency:** `pyproject.toml` declares `1.0.0` while the CLI reports `wpfy 0.1.0` (`src/wpfy/__init__.py`). A "1.0.0" label also contradicts beta positioning. | `pyproject.toml:8`, `src/wpfy/__init__.py:5` | **Open — human decision required.** Recommend a single canonical beta version (e.g. `1.0.0-beta.1` or `0.9.x`) set in both places before tagging a release. |

### Low

| # | Finding | Location | Status |
|---|---|---|---|
| L1 | `.gitignore` had no defensive `.env*` patterns (no `.env` files exist, but site `.env` files are central to wpfy, so an accidental commit from a dev box is plausible). | `.gitignore` | **Fixed**: `.env`, `.env.*`, `*.local` added. |
| L2 | No CI ran the test suite — 201 offline tests existed but only the PHP image publish workflow was configured, so PRs were unverified. | `.github/workflows/` | **Fixed**: `tests.yml` added (pytest on Python 3.10 and 3.12, `contents: read` only). |
| L3 | `wpfy site delete` skips its `[y/N]` confirmation when stdin is not a TTY (scripts/automation delete immediately). Reasonable behavior, but surprising if undocumented. | `src/wpfy/cli.py` (`handle_site_delete`) | **Documented** in README *Known limitations*. |
| L4 | Backups are stored on the same host they protect, with no retention policy. | `src/wpfy/site_layout.py` (backup paths) | **Documented** in README (off-host copy guidance); retention tracked in `ROADMAP.md`. |

### Informational

| # | Note |
|---|---|
| I1 | Test fixtures use obvious placeholder values only (`example.com`, RFC 5737 IPs `192.0.2.x`/`203.0.113.x`, dummy passwords like `secret`). Several tests explicitly assert that passwords are **redacted from CLI output** — a good sign. |
| I2 | The SSL preflight contacts third-party services to detect the server's public IP (api.ipify.org, ifconfig.me, checkip.amazonaws.com). Not a leak (only the server's own public IP is involved), now disclosed in README prerequisites. |
| I3 | SFTP uses a fixed username (`sftpuser`) per site with a chrooted container; documented in README. |
| I4 | The repository contains no committed logs, archives, database dumps, or generated output. |
| I5 | License is AGPL-3.0-only, consistently declared in `LICENSE` and `pyproject.toml`; README now explains its practical meaning. |

## 4. Public exposure findings (summary)

**Clean.** Specifically verified absent:

- `.env` / `.env.example` files, credentials, API keys, tokens, SSH keys, private certificates — none.
- Real domains, IPs, hostnames, emails, usernames, customer/project names — none; only IANA/RFC documentation placeholders.
- Hardcoded local-machine paths — none; install paths are standard system locations, overridable via `WPFY_INSTALL_ROOT`, `WPFY_CONFIG_DIR`, `WPFY_STATE_DIR`, `WPFY_LOG_DIR`.
- Debug/install logs, temp files, backups, archives, DB dumps — none committed.
- Comments revealing private plans, pricing, internal customers, or unreleased claims — none; no TODO/FIXME/HACK noise.

## 5. Documentation gaps (state before this pass)

The previous README was 35 lines and lacked: a beta warning, prerequisites, quick start, command reference, architecture/isolation explanation, SSL/DNS behavior, backup/restore/diagnostics/SFTP documentation, known limitations, uninstall/decommission guidance, troubleshooting entry points, security policy, contribution guide, changelog, and roadmap. All addressed in this pass (see §9), except a dedicated per-command reference and compatibility matrix, which are roadmap items.

## 6. Installer safety notes

- `install.sh` downloads a GitHub source archive, optionally verifies SHA-256 (`WPFY_SOURCE_SHA256`), validates archive structure, then runs the embedded installer with step tracking and logging to `/var/log/wpfy/install.log`. Supports `--dry-run`, `--verbose`, `--no-color`.
- Default source is the **mutable `main` ref** (finding M1) — pinning supported but opt-in.
- The script uses defensive patterns (checksum tooling fallbacks, `mktemp`, structure validation) and does not embed any credentials.
- Recommended (roadmap): make tagged, checksummed release archives the default documented install path.

## 7. GitHub Actions notes

- `php-images.yml` (pre-existing): **well configured** — minimal permissions (`contents: read`, `packages: write`), no `pull_request_target`, `GITHUB_TOKEN` only (a prior PAT was already migrated out in commit `217a7c8`), publish gated to `wpfyorg/wpfy` on `main`, actions pinned to major versions.
- `tests.yml` (added in this pass): runs pytest on Python 3.10/3.12, `contents: read` only, no secrets used.
- Optional hardening (nice-to-have): pin third-party actions to full commit SHAs.

## 8. GitHub repository metadata recommendations

**Description options** (set in repo settings):

1. *Preferred:* `Docker-first WordPress VPS installer and server management CLI (beta)`
2. `Manage isolated, per-site Dockerized WordPress stacks on Ubuntu VPS — Traefik, Let's Encrypt, backups, SFTP. Beta.`
3. `WordPress hosting CLI for Ubuntu VPS: isolated Docker Compose stacks per site, Traefik edge proxy, automatic SSL`

**Topics** (all verified accurate for this project): `wordpress`, `docker`, `docker-compose`, `traefik`, `vps`, `server-management`, `wordpress-cli`, `devops`, `self-hosted`, `hosting`, `lets-encrypt`, `php`, `mariadb`, `cli`, `python`

## 9. Recommended pre-beta checklist

### Must fix before beta

- [x] Rewrite `README.md` with beta notice, accurate commands, prerequisites, limitations — **done (this pass)**.
- [x] Add `SECURITY.md` with a private reporting channel — **done**; *human action:* enable **Private vulnerability reporting** in GitHub repo settings so the advisory link works.
- [x] Document the destructive-command behaviors (`stack purge` no prompt; `site delete` non-interactive) — **done** in README.
- [x] Document installer mutable-ref risk and pinning (`WPFY_REF`/`WPFY_SOURCE_SHA256`) — **done** in README.
- [ ] **Resolve version inconsistency (M3)**: align `pyproject.toml` and `src/wpfy/__init__.py` on one beta version string — *human decision*.
- [ ] **Verify `ghcr.io/wpfyorg/php-fpm` images are public** — `site create` fails for users if pulls require auth — *human verification*.
- [ ] **Test the install command end-to-end on a fresh Ubuntu VPS** from the public repo URL — *human verification*.

### Should fix before beta

- [x] `CONTRIBUTING.md`, `CHANGELOG.md`, `ROADMAP.md`, issue templates — **done (this pass)**.
- [x] CI running the test suite (`.github/workflows/tests.yml`) — **done**.
- [x] Defensive `.env*` entries in `.gitignore` — **done**.
- [ ] Tag a first beta release (e.g. `v1.0.0-beta.1`) and publish its archive SHA-256 so the README pinning instructions have concrete values to use.
- [ ] Add a confirmation prompt to `wpfy stack purge` (small code change, maintainer call — see M2).
- [ ] Set repository description and topics (see §8) — repo settings, not files.

### Nice to have (post-beta acceptable)

- [ ] Per-command reference docs and troubleshooting guide (`docs/`).
- [ ] Tested compatibility matrix (Ubuntu releases × Docker versions × architectures).
- [ ] Pin GitHub Actions to commit SHAs.
- [ ] Backup retention/rotation and documented off-host backup workflow.
- [ ] Independent review of the isolation model before promoting multi-tenant use.
- [ ] An uninstall script/command documented end-to-end.

## 10. Human review checklist

Items a maintainer should personally confirm before announcing the beta:

1. **Version string decision (M3)** — pick the canonical beta version; update `pyproject.toml` and `src/wpfy/__init__.py` together.
2. **Enable GitHub private vulnerability reporting** (Settings → Security) so `SECURITY.md`'s link is live; optionally add a security contact email if one exists.
3. **Confirm GHCR images are public** and pullable anonymously for all PHP versions 7.4–8.4.
4. **Run one full real-world cycle** on a throwaway VPS: install → `stack install` → `site create --wp -le` → `backup` → `restore` → `sftp --enable` → `site delete`.
5. **Set repo description + topics** per §8.
6. **Review this audit and the new docs** for tone/claims you're comfortable standing behind — particularly the isolation-model language in README's *Safety model* section.
7. **Decide on the `stack purge` confirmation prompt** (M2).

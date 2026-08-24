# Changelog

All notable changes to wpfy will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project aims to follow [Semantic Versioning](https://semver.org/) once it leaves beta.

## [Unreleased]

### Added

- Panel sign-in is now two steps. The password step verifies credentials
  first; only then, and only for accounts with TOTP enabled, does the panel
  ask for a code, backed by a single-use challenge that expires in 120
  seconds and is bound to the requesting client. Accounts without TOTP sign
  in directly as before, and the combined username/password/code form keeps
  working.
- `scripts/panel-demo.sh` — spins up a throwaway control panel for auditing the
  UI without touching a real install. It seeds a sandbox (`./.panel-demo` by
  default) with its own install root, config, state and log dirs, five demo
  sites across flavors/PHP versions/cache modes, and two panel users (an admin
  and a site-manager scoped to one site), then serves `wpfy panel` against it.
  `WPFY_SKIP_RUNTIME=1` is set throughout, so no root and no Docker daemon are
  required and runtime/health panels report unavailable by design. Seeding still
  attempts the WordPress core download; without network access it fails and the
  sites stay at `needs-bootstrap`, which is the expected demo state.
- Panel account pages for every signed-in user, admin and site manager alike:
  profile editing (name, email), password change that requires the current
  secret and revokes the account's other sessions while keeping the acting
  one, TOTP enrollment with QR/secret setup and disable behind
  reauthentication, and a session list with per-session revocation. The
  routes are keyed to the session identity, so site managers get them
  without gaining system-scoped access. A begun enrollment can be cancelled
  (`DELETE /api/auth/totp/pending`), which discards the pending secret
  server-side instead of leaving "already disclosed" until the TTL.
- `/api/auth/me` now returns `first_name`, `last_name`, `email`, and
  `totp_enabled` alongside username/role/sites/version, so the
  session-scoped account pages can prefill and render TOTP state without
  system-scoped overview access.
- Settings page panel-access card: enable, rotate, and disable HTTP basic
  auth on the public panel domain from the browser. The status payload
  carries an `auth_state` derived from the router's own content:
  `enforced` (a recognized router carries exactly the stored credential),
  `staged` (stored but verifiably nothing enforces it), `stale` (a router
  enforces a different credential than stored -- or enforces one while
  nothing is stored; the old prompt is live either way), `unknown`
  (exposed but the router cannot be attributed to wpfy), and `off`. The
  card never claims the public domain is guarded -- or unguarded -- when
  disk says otherwise.

### Fixed

- Disabling panel basic auth no longer reports success while an unmanaged
  router may still be prompting. When the rewrite of a recognized router
  fails, the credential file is restored (bytes and mode) so disk state
  matches the still-enforced router and a retry converges. When the panel is
  exposed but wpfy does not recognize the router at all, the disable refuses
  with 409 naming the cause instead of silently dropping the credential.

First validation run on an IPv6-capable host. Both fixes below are in code
paths that only render when the host has global IPv6, so an IPv4-only host
never reached either of them and the offline suite asserted the wrong thing.

### Fixed

- `wpfy stack install --nginx` no longer fails fail2ban configuration on an
  IPv6-capable host. The `ip6tables` lines in the generated
  `action.d/wpfy-docker-http.conf` sat at column 0 instead of continuing the
  `actionstart` value, so fail2ban's configparser rejected the whole file and
  `fail2ban-server --test` failed. wpfy restored the previous config and
  reported `fail2ban: FAIL`, leaving the host with no Login Shield at all.
- IPv6 addresses can now actually be banned. The generated `actionban` and
  `actionunban` tested `[ "<family>" = "ipv6" ]`, but fail2ban expands
  `<family>` to `inet6`. Every IPv6 ban therefore took the IPv4 branch and
  died with `iptables: host/network not found`, while `fail2ban-client status`
  went on listing the address as banned. Verified against fail2ban 1.0.2.

### Changed

- `wpfy security fail2ban status` no longer reports `IPv6 protection: active`.
  It never could be: wpfy enables IPv6 on neither the Docker daemon nor any
  Docker network, so inbound IPv6 to a published port is relayed by
  `docker-proxy` in userland and never traverses `ip6tables FORWARD` /
  `DOCKER-USER`. A correctly installed IPv6 ban rule sits at zero packets while
  the IPv4 chain counts normally, and Traefik sees every IPv6 client as the
  bridge gateway rather than the client. The status now reads `inactive` and
  names that cause, because telling an operator with public IPv6 that half
  their surface is covered, when none of it is, is worse than telling them
  nothing.

### Known issue

- Actually enforcing IPv6 bans needs `"ipv6"` / `"ip6tables"` in the Docker
  daemon config and `enable_ipv6` on the generated networks — host daemon
  configuration plus a change to every compose file. That is an architecture
  decision and gets its own ADR; the entry above is the honest interim
  reporting fix, not the feature.

## [1.0.0-rc7] - 2026-08-24

Adds two-step panel sign-in and managed panel-edge firewall ingress.

### Added

- Panel sign-in now verifies username and password first, then requests a
  single-use, time-limited TOTP challenge only for accounts with TOTP enabled.
  Accounts without TOTP continue to sign in directly, and the combined form
  remains supported.
- Panel exposure now discovers the live Docker `wpfy-panel-edge` bridge and
  stages one exact, WPFY-owned UFW rule scoped to that bridge, its private
  subnet, gateway, and configured panel port. Reconfiguration removes stale
  managed variants; disabling exposure removes managed panel-edge rules.

### Security

- The managed rule permits panel-edge ingress only. It does not open the host's
  public panel port, so public port `8642` remains closed.

### Validation

- Oracle security review: **APPROVE**.
- Focused 324-test suite passed.
- Full local suite was not completed because of its duration; it is not claimed
  as passed.

## [1.0.0-rc6] - 2026-08-21

Fixes an outage in rc5: the Traefik Docker-socket proxy never started on a
standard Docker host, so no site was routable through the edge on a clean
install. Anyone running rc5 should upgrade.

### Fixed

- Make the Traefik Docker-socket proxy actually work. Three defects, each
  fatal on its own, meant the proxy never started on a standard Docker host,
  so Traefik never obtained a Docker provider and **no site was routable
  through the edge** on a clean install:
  - The container runs as an unprivileged image user, but the generated
    compose emitted no `group_add`, so it could not open `/var/run/docker.sock`
    (mode 660, `root:docker`) and exited with `permission denied`. The host's
    `docker` group GID is now resolved at render time and added; if no such
    group exists, rendering fails loudly with the reason instead of writing a
    compose file that cannot work.
  - The image defaults to listening on `127.0.0.1:2375`. `SP_LISTENIP=0.0.0.0`
    is now set — safe because the service publishes no host port and sits on an
    `internal: true` network.
  - The allowlist source filter was set as `SP_ALLOW_FROM`, but the pinned
    image reads `SP_ALLOWFROM`. The value was therefore ignored and fell back
    to the image default of `127.0.0.1/32`. The impact was availability, not
    exposure — the fallback is more restrictive, not less.

  Found by running the release on a clean Ubuntu 24.04 host. The offline suite
  could not see any of it, and `tests/docker-runtime-hardening.sh` had only
  ever reported SKIP on macOS. That script's synthetic compose also omitted the
  `user:` directive real site compose always sets, producing a false failure;
  it now mirrors what the product generates. On Linux the suite reports
  `failures=0 skips=0`, including the POST-mutation refusal that is the actual
  proof the allowlist enforces.

- Surface the ufw SSH-deletion guard's refusal as `409` instead of a generic
  `500`. The guard always worked and no mutation occurred, but the actionable
  message naming the port was lost behind an internal-error response.

## [1.0.0-rc5] - 2026-08-21

### Added

- Rebuild the loopback control panel client on vendored Tabler 1.4.0 (ADR 0032).
  Site detail collapses from fourteen tabs to five (Overview, Settings, Data,
  Access, Automation) with the old paths redirecting for one release; the
  site-creation wizard is rebuilt on the real API; and all ten admin pages ship
  — events, job detail, users, services, firewall, remote backup, settings,
  instance, SMTP, and the basic-auth inventory. Running operations move into a
  header popover that stays visible across navigation.

- Add host port management over `ufw`: read the rule set, add and remove
  allow/deny rules with optional source restrictions, and enable or disable the
  firewall, exposed at `GET /api/firewall` and `/api/firewall/ports|enable|
  disable`. `enable` allows the detected SSH port before the firewall comes up,
  and denying or removing the rule carrying SSH requires the port as a typed
  confirmation. wpfy does not install `ufw` — a host without it reports the fact
  and the command to run.

- Add `GET /api/metrics/latest`, the newest metrics sample for every scope in
  one query, and `GET /api/sites/{domain}/services`, so a site-manager can see
  the containers of the site they are responsible for.

- `wpfy panel expose` asks for the panel domain and, when the host has no ACME
  contact address, the Let's Encrypt email — the value that decides whether a
  certificate can issue at all. The typed domain confirmation is unchanged,
  `--email` covers scripted runs, and a non-interactive run refuses with
  instructions rather than prompting.

- Add admin-only panel API routes for settings, remote backup and schedule,
  firewall status/install, SMTP transport configuration/testing, instance facts,
  and cross-site basic-auth inventory. S3 secret keys and SMTP passwords remain
  write-only in every API response.

### Changed

- Rename the panel's **Mail** page and nav entry to **SMTP**. The page
  configures an outbound SMTP transport and sends a test message; nothing in
  wpfy sends mail when an event or failure occurs, so a name suggesting
  alerting described software that does not exist. The route (`/admin/mail`),
  the API paths, and the stored settings keys are unchanged — this is a copy
  change, not a migration.

- `wpfy site create --pass`, grouped `wpfy site update --password`, and
  `wpfy sftp --password` accept passwords only from stdin (`-`) or a TTY
  prompt (`prompt` or an omitted value), never process argv. SFTP still
  generates a password when `--password` is omitted. `wpfy panel --token`
  now refuses raw values; use `--token-file` or `WPFY_PANEL_TOKEN`.

### Fixed

- Close every WCAG AA contrast failure in the panel, both themes, measured live
  across 17 routes (`docs/audit/panel-design-audit-2026-08-21.md`). The dark
  theme remapped `--tblr-primary` without relighting `--tblr-primary-fg`, so
  every filled primary button rendered its label at 2.43:1; the keyboard focus
  ring was a 25%-alpha glow compositing to 1.57:1 against the 3:1 that WCAG
  1.4.11 requires; `.btn-outline-danger` sat at 3.15:1 on exactly the controls
  that stop containers and rotate credentials; and `.btn-link` — which the site
  file browser uses for every filename — bypassed `--tblr-link-color` entirely
  at 3.55:1. Inactive site tabs, the header health and jobs chips, and the
  light-theme filled danger button are relit to match.
- Give the panel a skip link and a real navigation landmark: the sidebar was an
  `<aside>` (complementary), leaving screen-reader users with no navigation to
  jump to, and eleven nav links plus the header preceded `<main>` in the tab
  order on every route.
- Drop `role="tablist"`/`role="presentation"` from the site tab strip. Those are
  navigation links carrying `aria-current="page"`; a tablist whose children have
  no `role="tab"` promised a widget that did not exist.
- Make visible `.form-label` text focus its control. The field builders pair a
  visual label with an `aria-label`ed control rather than a `for`/`id` pair, so
  clicking a label did nothing; one delegated handler covers every field.
- Align three accessible names with their visible labels (WCAG 2.5.3), so voice
  control reaches the flavor, denied-IP, and blocked-user-agent fields.
- Stop the site tab strip wrapping to two rows at 375px, and reserve room under
  the sticky form action bar so it no longer permanently occludes the last card.
- Honour `prefers-reduced-motion` for the three `scrollIntoView` calls — an
  explicit `behavior` argument overrides the CSS the reduced-motion block sets.
- Shorten the sidebar `.nav-link` colour transition from 300ms to 150ms and give
  buttons press feedback, dropped under reduced motion.
- Validate edge-bound panel addresses against the discovered `wpfy-panel-edge`
  CIDRs, rejecting network, IPv4 broadcast, and off-network addresses without
  restricting the public-address bind used by domainless self-signed TLS.

Found installing on a clean Ubuntu 24.04 VPS — first-run only, which is why a
green offline suite never saw them.

- Create the panel auth log before installing the fail2ban jail that watches it.
  fail2ban treats a missing `logpath` as a fatal config error, so `wpfy stack
  install` reported `fail2ban: FAIL` on every fresh host and the rollback
  removed the package it had just installed — leaving a new VPS with no
  intrusion prevention at all.
- Wait for fail2ban's socket instead of racing it. `systemctl start` returns
  when the unit is active; fail2ban-server binds its socket afterwards, so the
  single immediate `fail2ban-client ping` failed for a service seconds from
  ready.
- Green the site health badge for the states the server actually emits.
  `site_health` returns ready | running | degraded | down | needs-bootstrap; the
  badge tested for `healthy`, which is never emitted, so a fully working site
  showed its status in red.
- Report the edge proxy's parsed state instead of the `docker compose ps` table.
  The dashboard opened on "1 service degraded: wpfy-traefik" against a healthy
  container, and the Traefik card printed the table's header row as its subtext.
- Accept `healthy` as healthy across every client surface. Docker reports
  `healthy` for a container with a healthcheck and `running` for one without, so
  treating only `running` as good marked the edge proxy — and every site image
  with a healthcheck — permanently degraded.
- Refuse `panel expose --domain` without a real ACME contact address. A fresh
  install ships `admin@localhost`, which Let's Encrypt rejects at account
  registration, so exposure reported success and the certificate never issued.
  Enabling SSL for a site has refused on this since ADR 0016.
- Keep the panel router recognisable after basic auth is stored. The recognition
  check re-rendered and compared byte for byte, so storing a credential made
  wpfy's own router unreadable to wpfy — which is exactly the condition that
  prevents the credential from being applied.

Found running the panel rebuild against the validation VPS — every one of these
passed the offline suite, which stubs `subprocess.run` and builds `PanelConfig`
directly rather than running the command an operator types.

- Require the one-time setup secret on a domainless panel. The gate keyed off
  `edge_bind`, and a domainless panel is not edge-bound — it binds straight to
  the public address — so `wpfy panel --public` created the first administrator
  over the open internet with no secret at all.
- Let the setup link authenticate the request that carries it. The secret was
  only read from the request body, so the printed link returned 401 on every
  call. It now authenticates the setup routes and nothing else, and a public
  panel prints no run token: that token is a full admin grant, and a public
  panel writes it into the terminal and the systemd journal.
- Add `wpfy panel --public`. `expose --no-domain` printed a start command that
  is refused (a non-loopback host without `--edge-service` never binds) and
  nothing set `self_signed_tls`, so the mode was unreachable and its TLS unwired.
- Hash the panel basic-auth credential with APR1. sha512crypt is what nginx
  verifies for the per-site gate; Traefik's basicAuth understands MD5-APR1,
  SHA1 and bcrypt only, so it loaded the middleware silently and then rejected
  the correct password forever.
- Warn when an active firewall closes the panel's port. The panel is a host
  process, so ufw applies to it — unlike the Docker-published ports, which
  bypass ufw's INPUT chain — and it otherwise started, printed the right URL,
  and timed out from everywhere.
- List firewall rules while ufw is off. An inactive ufw prints no rule list at
  all, so rules added before enabling read as absent — and an operator shown
  "no rules" adds the port again, so enabling installs duplicates.
- Split the rule comment out of the ufw source column. Glued to the source it
  was rendered as part of the address, made a rule's IPv6 twin look like a
  separate rule (two rows, two delete buttons, one underlying rule), and was
  sent back as `source` on delete, where it is rejected as a malformed address.

- Keep the SFTP password out of `job.result` on site creation. The create job
  built its payload with `_runtime_payload` rather than `_sftp_payload`, so the
  CLI's `password (shown once): <secret>` line was stored in a job result that
  every later `GET /api/jobs` returns in full — outliving the one-time panel
  designed to show it once.

- Enforce the 12-character password minimum on every write path. It was applied
  only by the first-run setup form, so an administrator could create a
  site-manager with a one-character password.

- Accept a blank secret on `PUT /api/backup/remote` and `PUT
  /api/notifications/smtp` as "keep the stored value". Both demanded a
  write-only secret on every write, so changing a bucket prefix or a sender
  address forced the operator to re-type a credential they cannot read back, and
  a client sending an empty string replaced a working credential with an empty
  one.

- Report `GET /api/sites/{domain}/security` when the edge is unreachable instead
  of failing the whole read with a 500.

- Validate PHP image, Let's Encrypt mode, and DNS provider vocabularies before
  site lifecycle preflight or scaffold writes. CLI and panel now share the
  accepted values: PHP `7.4`, `8.0`–`8.4`; Let's Encrypt `default`,
  `wildcard`, or `off`; DNS provider `cloudflare`.

- Redact boundary-delimited `PWD`, `PASS`, `PASSWORD`, `SECRET`, `TOKEN`,
  `KEY`, `CREDENTIAL`, `AUTH`, and `AUTHORIZATION` assignments in operation
  events, including quoted values and HTTP Authorization headers. This prevents
  cron-command secrets from reaching the JSONL log or panel, while preserving
  harmless diagnostics such as `monkey=12` and `authority=high`. Event
  redaction remains best-effort pattern matching: a secret without a
  recognizable key can still be logged.

- Write new basic-auth credentials as OpenSSL sha512crypt (`$6$`) hashes,
  passing the password through stdin. Hosts without OpenSSL fall back to salted
  APR1 (`$apr1$`); the basic-auth operation event records the selected scheme.
  Restore re-applies `0640` and the site's uid:gid ownership to
  `nginx/htpasswd` before restarting the site.

- Create secret `.env`, stored S3/Cloudflare/SMTP configuration, and downloaded
  remote backup archives with mode `0600` at open time. Scaffold regeneration
  and restore preserve existing ownership and in-place writes; non-secret
  generated bind mounts remain at their established modes.

- Bound each accepted panel connection to a 30-second idle socket timeout. Slow or
  incomplete unauthenticated request lines and headers are disconnected, while
  intentional HTTP/1.1 keep-alive requests remain available between shorter idle gaps.

- Require HTTPS for S3-compatible backup endpoints by default. `backup storage set --allow-insecure` persists the explicit HTTP opt-out as `WPFY_BACKUP_S3_ALLOW_INSECURE=1`; plaintext endpoints fail closed unless that opt-out is set. The S3 opener refuses cross-host redirects so SigV4 authorization headers cannot be replayed to another host.

- Trust forwarded client address and forwarded scheme only from Traefik's discovered IPv4/IPv6 container addresses on `wpfy`, never every peer in its Docker subnet. Edge startup re-renders changed managed-site trust snippets and reloads changed running nginx services.

- Apply per-site security mutations to the running edge before reporting success: basic authentication, deny-IP, user-agent blocks, and login rate limits reload the site's nginx service; Cloudflare-only recreates `web` when the rendered Traefik labels differ from the running container's `traefik.*` label slice. Already-applied Cloudflare-only labels are not re-applied on an unchanged panel save. If a site is stopped, wpfy stages the configuration and reports success that it will apply when the site starts. If either runtime operation fails, wpfy retains the staged configuration but returns a non-zero result that says it was not applied. Repeating the same CLI or panel request retries the runtime operation safely; documented offline behavior remains unchanged.

### Security

- Add a per-client-IP token-bucket rate limiter to the panel's own request
  handler, checked once per request across `do_GET`/`do_POST`/`do_PUT`/
  `do_DELETE`/`do_PATCH`. `wpfy panel expose --no-domain` binds the panel
  directly and never passes through Traefik, so it inherited none of the
  `rateLimit` middleware the domain-fronted router gets; only the
  credential-guessing throttle in `panel_auth` applied. The limiter lives in
  the handler rather than behind a domainless branch, so it covers every
  exposure mode — Traefik-fronted, direct-bind, and loopback — and is keyed on
  the same resolved client address as login throttling, which walks the
  forwarded chain right-to-left and so cannot be pinned onto another caller.
  Refused requests get `429` with `Retry-After`. Amends ADR 0033.

- Traefik no longer mounts the Docker socket. A digest-pinned
  `wollomatic/socket-proxy` holds it on the new `internal: true`
  `wpfy-docker-socket` network, publishes no host port, and allows only
  `GET /version`, `GET /v1.NN/(version|containers/.*|events.*)` and
  `HEAD /_ping`; Traefik reads `tcp://socket-proxy:2375`. Existing installs
  pick the topology up on the next `wpfy stack install --nginx`. This removes
  the write half of the Docker API from the edge; container environment stays
  readable to anything that owns the Traefik container, because that is what
  routing needs. See ADR 0034.

- Pin every runtime image by digest through the new
  `src/wpfy/image_references.py` inventory — nginx-unprivileged, all six
  PHP-FPM tags, MariaDB, Redis, Traefik and the socket proxy — with
  `docs/IMAGE_UPDATE_POLICY.md` owning the update procedure. The PHP image
  workflow now also publishes an immutable `<version>-<sha>` tag.
  `atmoz/sftp:alpine` remains an explicit exception: its manifest is amd64-only
  while wpfy supports arm hosts.

- Serve `/healthz.html` only to `127.0.0.1` and `::1`. The generated Nginx
  config for both static and WordPress flavors denies everything else, closing
  a public liveness and identification oracle.

- Report `system_diagnostics()` as allowlisted states — `running`, `stopped`,
  `unavailable`, `available`, `consistent`, `mismatch` — with fixed messages.
  Raw `docker compose ps` output, container names, images, commands, host port
  bindings, and subprocess or exception text no longer reach the panel API.

- Answer `421` to any Host header other than the configured one when the panel
  runs self-signed or domainless, before routing. Origin checks stay exact on
  scheme, host, and port.

- Bound login cost: `auth.login` caps its body at 8 KiB, rejects malformed or
  oversized credentials before any KDF runs, and admits scrypt work through a
  non-blocking gate (2 concurrent, 1 per client) that returns a generic `429`
  with `Retry-After` instead of queueing. scrypt parameters, the dummy KDF for
  unknown users, TOTP, CSRF, and the per-user throttles are unchanged. The
  panel's client-address checks now read a startup-refreshed edge snapshot
  rather than performing Docker discovery during request handling.

- Ban DOM-to-code and DOM-to-HTML sinks in the first-party panel client, with
  `tests/test_panel_frontend_security.py` enforcing it; vendored `tabler.min.js`
  and `qrcode.min.js` are the two explicit exclusions.

- Close a panel login-throttle oracle, fail closed on CSRF token validation, and
  enforce a strict `Origin` check on state-changing panel requests. Verified
  live against a running panel on rc5.

- Return a generic `Server` header and add HSTS across panel responses; bind
  `RUN_TOKEN` to loopback only; mark the `wpfy_fm` file-manager cookie
  `Secure`. Verified live against a running panel on rc5.

- Reject TOTP replay and require reauthentication to disable TOTP; close an
  authorization/IDOR gap that let a caller reach data outside its assigned
  scope; close a host port exposure gap. Verified live against a running panel
  on rc5.

- Fix a tar-slip path on backup restore and site-level `X-Forwarded-For`
  spoofing into fail2ban banning. Both closed and now gated by tests.

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

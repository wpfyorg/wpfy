# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities **privately** via [GitHub Security Advisories](https://github.com/wpfyorg/wpfy/security/advisories/new) ("Report a vulnerability" on the repository's Security tab).

Please do **not**:

- Open a public GitHub issue for a security problem.
- Post exploit details, proof-of-concept code, or affected-server details publicly before a fix is released.
- Test vulnerabilities against servers you do not own or have permission to test.

When reporting, include what you can of: affected version/commit, the command or component involved, reproduction steps, and impact. We will acknowledge reports as quickly as we can and keep you informed of progress.

## Supported versions

wpfy is currently in **beta**. Only the latest release (and the `main` branch) receives security fixes. There are no maintained older release lines yet.

| Version | Supported |
|---|---|
| Latest beta release / `main` | ✅ |
| Anything older | ❌ — please upgrade |

## Beta security expectations

wpfy is beta software and has **not yet undergone an independent security audit or penetration test**. The design emphasizes isolation (per-site containers, unique unprivileged UIDs, private per-site networks, root-only secrets), but you should:

- Run wpfy on a **fresh or disposable VPS** first and review its behavior before any production use.
- Keep the host OS and Docker Engine patched — wpfy does not manage host-level hardening (firewall, SSH configuration, fail2ban, etc.).
- Treat Docker-daemon access, including Traefik's current socket access, as a host-level trust boundary; container isolation does not protect against Docker or host compromise.
- Treat RC2's local checks as incomplete until disposable-VPS, provider, and available external-scanner evidence is published.
- Treat per-site `.env` files, backup archives, and SFTP credentials as sensitive.
- Avoid hosting mutually untrusted tenants on one server until the isolation model has had broader review.

## Responsible disclosure

We support coordinated disclosure: report privately, give us a reasonable window to ship a fix, and we will credit you in the release notes if you wish. If you believe a report is being ignored, please follow up on the same private channel before disclosing publicly.

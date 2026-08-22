# Contributing to wpfy

Thanks for your interest in wpfy! During the beta, the most valuable contributions are **bug reports from real VPS deployments**, documentation fixes, and focused pull requests.

## Development setup

wpfy is a Python (3.10+) CLI with no third-party runtime dependencies.

```bash
git clone https://github.com/wpfyorg/wpfy.git
cd wpfy

# Run the CLI directly from source
PYTHONPATH=src python3 -m wpfy --help

# Or install editable into a virtualenv
python3 -m venv .venv && source .venv/bin/activate
pip install -e . pytest
wpfy --help
```

Commands that manage real sites require Docker Engine with the Compose plugin and root privileges on an Ubuntu host — use a **disposable VPS or VM** for end-to-end testing, never a production server.

## Running tests

The test suite is offline-friendly (no Docker or network required):

```bash
pip install pytest   # if not already installed
pytest
```

All tests must pass before a PR is reviewed. Public CI runs the Python suite on
pushes, pull requests, and manual dispatch for Python 3.10 and 3.12. Add tests
for any behavior change; the existing files in `tests/` show established mocking
patterns for Docker and network interactions.

## Auditing the panel locally

`scripts/panel-demo.sh` serves the control panel against a throwaway sandbox so
the UI can be reviewed without a provisioned server:

```bash
scripts/panel-demo.sh              # seed (if needed) and serve on 127.0.0.1:8642
scripts/panel-demo.sh --reset      # wipe the sandbox and reseed
scripts/panel-demo.sh --seed-only  # seed and print credentials, don't serve
scripts/panel-demo.sh --port 9000
scripts/panel-demo.sh --token-mode # skip panel users; the URL carries a token
```

The sandbox lives in `./.panel-demo` (gitignored; override with `--home` or
`WPFY_DEMO_HOME`) and carries its own install root, config, state and log dirs,
so `/opt/wpfy` is never touched. The script refuses a `--home` that names a
system path, `$HOME` or the repository root, and `--reset` deletes a directory
only when it carries the sandbox marker the script writes.

It seeds five sites across flavors, PHP versions and cache modes, plus two
users — `demo-admin` (admin) and `demo-manager` (site-manager, scoped to
`demo-shop.test`). A fresh sandbox gives both the password printed on startup
(`WPFY_DEMO_PASSWORD`, default `demo-panel-passw0rd`). Re-running against an
existing sandbox does not reset passwords, so it prints the accounts without
one; `--reset` reseeds them. `--token-mode` skips the users entirely and lets
the panel's run token stand in — the panel accepts that token only while no
named user exists, so it requires a sandbox with none (re-run with `--reset`).

`WPFY_SKIP_RUNTIME=1` is exported throughout, so no root and no Docker daemon
are needed, and runtime, health and service panels report unavailable. Seeding
does reach for the network: `wpfy site create` writes the scaffold, `.env` and
registry entry first, then bootstraps WordPress core over HTTP. Without network
access that download fails and each site stays at `needs-bootstrap` — expected
here, and the only `site create` failure the script tolerates. Everything that
reads the registry, the generated `.env`/compose scaffold, panel auth, roles and
site scoping is real.

## Style expectations

- Python: standard library only (no new runtime dependencies without prior discussion), type hints on new code, match the structure and naming of the surrounding module.
- Bash (`install.sh`, `wpfy`): defensive scripting — quote variables, check command availability, fail clearly.
- Keep user-facing CLI output consistent with the existing `[PASS]/[WARN]/[FAIL]` and progress-message conventions.

## Pull request expectations

- One focused change per PR; small PRs get reviewed faster.
- Describe **what** changed and **why**, including how you tested it (unit tests, and on a disposable VPS if behavior-affecting).
- Update documentation (`README.md`, `CHANGELOG.md` under *Unreleased*) when behavior or commands change.
- Never include real domains, IPs, credentials, or server details in code, tests, or issue text — use `example.com` and RFC 5737 addresses (`192.0.2.x`, `203.0.113.x`).

## Documentation contributions

Documentation accuracy is a release requirement: README commands must match actual CLI behavior. If you find a mismatch, that's a bug — please report or fix it.

## Security issues

Do **not** open public issues or PRs for vulnerabilities — see [SECURITY.md](SECURITY.md).

## License

wpfy is AGPL-3.0-only. By contributing, you agree your contributions are licensed under the same terms.

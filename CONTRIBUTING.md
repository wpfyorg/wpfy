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

All tests must pass before a PR is reviewed. Add tests for any behavior change; the existing files in `tests/` show the established mocking patterns for Docker and network interactions.

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

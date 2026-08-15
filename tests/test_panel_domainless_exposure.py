"""Domainless exposure: self-signed TLS, the setup secret, and what it unlocks.

Publishing the panel on a bare address removes the two things that protected
first-run setup: there is no CA-issued certificate, and there is no SSH tunnel.
These tests cover what replaces them.
"""

from __future__ import annotations

import shutil

import pytest

from wpfy import panel_auth, panel_exposure, panel_setup, panel_tls


needs_openssl = pytest.mark.skipif(
    shutil.which("openssl") is None, reason="openssl is not installed on this host"
)


# ---------------------------------------------------------------------------
# Certificate
# ---------------------------------------------------------------------------


@needs_openssl
def test_certificate_is_generated_once_and_reused(tmp_wpfy_home):
    """Regenerating on every start would change the fingerprint the operator was
    told to check, which trains them to ignore it."""
    first = panel_tls.ensure_self_signed("203.0.113.7")
    assert first.generated is True
    assert first.certificate_path.exists() and first.key_path.exists()

    second = panel_tls.ensure_self_signed("203.0.113.7")
    assert second.generated is False
    assert second.fingerprint == first.fingerprint


@needs_openssl
def test_private_key_is_not_world_readable(tmp_wpfy_home):
    """The key authenticates the panel to every browser trusting the printed
    fingerprint. Nothing but root needs to read it."""
    certificate = panel_tls.ensure_self_signed("203.0.113.7")
    mode = certificate.key_path.stat().st_mode & 0o777
    assert mode == 0o600, f"private key mode is {mode:o}"


@needs_openssl
def test_a_bare_address_gets_an_ip_san(tmp_wpfy_home):
    """Browsers ignore the CN. Without an IP SAN the certificate does not even
    match the address it was made for, and the warning becomes unreadable."""
    import subprocess

    certificate = panel_tls.ensure_self_signed("203.0.113.7")
    text = subprocess.run(
        ["openssl", "x509", "-in", str(certificate.certificate_path), "-noout", "-text"],
        check=True, capture_output=True, text=True,
    ).stdout
    assert "IP Address:203.0.113.7" in text


@needs_openssl
def test_fingerprint_matches_openssl(tmp_wpfy_home):
    """The printed fingerprint is what the operator compares in the browser. If
    it disagrees with the certificate, the check is worse than no check."""
    import subprocess

    certificate = panel_tls.ensure_self_signed("203.0.113.7")
    reported = subprocess.run(
        ["openssl", "x509", "-in", str(certificate.certificate_path), "-noout",
         "-fingerprint", "-sha256"],
        check=True, capture_output=True, text=True,
    ).stdout.strip().split("=", 1)[1]
    assert certificate.fingerprint == reported


def test_fingerprint_rejects_something_that_is_not_a_certificate():
    with pytest.raises(ValueError):
        panel_tls.fingerprint_of("not a certificate")


def test_missing_openssl_is_reported_not_guessed(tmp_wpfy_home, monkeypatch):
    monkeypatch.setattr(panel_tls, "openssl_available", lambda: False)
    with pytest.raises(RuntimeError, match="openssl is required"):
        panel_tls.ensure_self_signed("203.0.113.7")


# ---------------------------------------------------------------------------
# Setup secret
# ---------------------------------------------------------------------------


def test_setup_secret_is_single_use(tmp_wpfy_home):
    secret = panel_setup.issue_setup_secret()
    assert panel_setup.consume_setup_secret(secret) is True
    assert panel_setup.consume_setup_secret(secret) is False, "the secret was replayable"


def test_setup_secret_is_stored_hashed(tmp_wpfy_home):
    """A readable state file must not hand over the right to create the
    administrator."""
    secret = panel_setup.issue_setup_secret()
    stored = panel_setup.state_path().read_text(encoding="utf-8")
    assert secret not in stored
    assert panel_setup.state()["setup_secret_hash"]


def test_setup_secret_expires(tmp_wpfy_home, monkeypatch):
    """A secret granting account creation should not stay valid on an
    internet-facing panel for as long as nobody happens to use it."""
    secret = panel_setup.issue_setup_secret()
    monkeypatch.setattr(panel_setup, "SETUP_SECRET_TTL_SECONDS", -1)
    assert panel_setup.consume_setup_secret(secret) is False


@pytest.mark.parametrize("value", [None, "", 0, b"bytes", "wrong-secret"])
def test_setup_secret_rejects_junk(tmp_wpfy_home, value):
    panel_setup.issue_setup_secret()
    assert panel_setup.consume_setup_secret(value) is False


def test_consuming_when_none_was_issued_is_false(tmp_wpfy_home):
    assert panel_setup.consume_setup_secret("anything") is False


# ---------------------------------------------------------------------------
# What the secret unlocks
# ---------------------------------------------------------------------------


def _account_body(**overrides) -> dict:
    body = {
        "first_name": "Ada", "last_name": "Lovelace", "username": "ada",
        "email": "ada@example.test", "password": "a-long-enough-password",
        "confirm_password": "a-long-enough-password", "license_accepted": True,
    }
    body.update(overrides)
    return body


def test_edge_bound_setup_is_still_refused_without_a_secret(tmp_wpfy_home):
    """The original refusal is unchanged, wording included, when no secret is
    presented. The relaxation is narrow on purpose."""
    with pytest.raises(ValueError, match="use the SSH tunnel"):
        panel_setup.create_account(_account_body(), client=None, remote=True)


def test_edge_bound_setup_is_refused_with_a_wrong_secret(tmp_wpfy_home):
    panel_setup.issue_setup_secret()
    with pytest.raises(ValueError, match="use the SSH tunnel"):
        panel_setup.create_account(
            _account_body(setup_secret="not-the-secret"), client=None, remote=True
        )


def test_edge_bound_setup_succeeds_with_the_issued_secret(tmp_wpfy_home):
    secret = panel_setup.issue_setup_secret()
    token, user = panel_setup.create_account(
        _account_body(setup_secret=secret), client=None, remote=True
    )
    assert token
    assert user["username"] == "ada"


def test_the_secret_is_burned_even_though_the_account_call_continues(tmp_wpfy_home):
    """A secret checked but not burned would let a second attempt through after
    the first failed on a later validation step."""
    secret = panel_setup.issue_setup_secret()
    with pytest.raises(ValueError):
        panel_setup.create_account(
            _account_body(setup_secret=secret, email="not-an-email"), client=None, remote=True
        )
    with pytest.raises(ValueError, match="use the SSH tunnel"):
        panel_setup.create_account(
            _account_body(setup_secret=secret), client=None, remote=True
        )


def test_loopback_setup_needs_no_secret(tmp_wpfy_home):
    """The tunnel path is untouched: nothing new is required of an operator who
    was already reaching the panel the supported way."""
    token, _ = panel_setup.create_account(_account_body(), client=None, remote=False)
    assert token


def test_a_self_signed_panel_is_treated_as_remote(tmp_wpfy_home):
    """Found on the validation VPS: `wpfy panel --public` created the first
    administrator over the open internet with no secret at all.

    The gate was keyed to `edge_bind`, and a domainless panel is not edge-bound
    -- it is bound straight to the public address. The condition that matters is
    "can this request have come from off the host", which both modes satisfy.
    """
    from wpfy import panel

    config = panel.PanelConfig(host="127.0.0.1", port=0, token="t", self_signed_tls=True)
    assert (config.edge_bind or config.self_signed_tls) is True

    with pytest.raises(ValueError) as excinfo:
        panel_setup.create_account(_account_body(), client=None, remote=True)
    assert "setup link" in str(excinfo.value)
    assert not panel_auth.login_required(), "no account may exist after a refused setup"


def test_the_setup_secret_authenticates_setup_and_nothing_else(tmp_wpfy_home):
    """Found on the validation VPS: the printed setup link 401'd on every request.

    The secret was only ever read from the request body, so it could not
    authenticate the request carrying it -- and a domainless panel prints no run
    token, so the browser had no credential at all. It authenticates now, and
    its authority stops at the setup routes.
    """
    from wpfy import panel

    secret = panel_setup.issue_setup_secret()
    assert panel_setup.setup_secret_matches(secret) is True
    assert panel_setup.setup_secret_matches(secret) is True, "checking must not burn it"
    assert panel_setup.setup_secret_matches("wrong") is False

    principal = {"_setup_secret": "s", "username": None, "role": None, "sites": ()}
    panel.authorize(principal, panel.RouteMeta("setup.create", "setup", True), None)
    for action, scope in (("site.list", "system"), ("site.read", "site"), ("job.list", "system")):
        with pytest.raises(panel.PanelError) as excinfo:
            panel.authorize(principal, panel.RouteMeta(action, scope), "example.com")
        assert excinfo.value.status == 403

    assert panel_setup.consume_setup_secret(secret) is True
    assert panel_setup.setup_secret_matches(secret) is False, "spent secrets stop authenticating"


def test_a_public_panel_url_carries_no_run_token(tmp_wpfy_home):
    """The run token is a full admin grant. On loopback, printing it costs
    nothing -- reaching the panel already proves shell access. On a public
    address it goes into the terminal and the systemd journal while the port is
    open to the internet, so the expiring single-use secret is the only way in.
    """
    from wpfy import panel

    public = panel.PanelConfig(host="127.0.0.1", port=3939, token="grant-me", self_signed_tls=True)
    assert "#token=" not in panel.panel_url(public)
    assert panel.panel_url(public).startswith("https://")

    loopback = panel.PanelConfig(host="127.0.0.1", port=8642, token="grant-me")
    assert "#token=grant-me" in panel.panel_url(loopback)


# ---------------------------------------------------------------------------
# The command
# ---------------------------------------------------------------------------


def test_expose_without_domain_requires_the_typed_confirmation(tmp_wpfy_home):
    result = panel_exposure.expose_without_domain(confirm="yes")
    assert result.exit_code == 2
    assert "expose" in result.message


@needs_openssl
def test_expose_without_domain_prints_the_url_fingerprint_and_setup_link(tmp_wpfy_home, monkeypatch):
    monkeypatch.setattr(panel_exposure, "public_bind_address", lambda: "203.0.113.7")
    result = panel_exposure.expose_without_domain(confirm="expose")
    assert result.exit_code == 0, result.message
    assert "https://203.0.113.7:3939/" in result.message
    assert "fingerprint (SHA-256)" in result.message
    assert "#setup=" in result.message, "no account exists, so a setup link is required"
    assert "untrusted" in result.message, "the browser warning must be stated, not left as a surprise"


@needs_openssl
def test_expose_without_domain_issues_no_setup_link_once_an_account_exists(tmp_wpfy_home, monkeypatch):
    from wpfy import panel_auth

    panel_auth.add_user("existing", "a-long-enough-password", role="admin")
    monkeypatch.setattr(panel_exposure, "public_bind_address", lambda: "203.0.113.7")
    result = panel_exposure.expose_without_domain(confirm="expose")
    assert result.exit_code == 0, result.message
    assert "#setup=" not in result.message, "a setup link would be a standing account-creation grant"


def test_expose_without_domain_reports_a_host_with_no_public_address(tmp_wpfy_home, monkeypatch):
    def no_address():
        raise RuntimeError("cannot determine a public address for this host")

    monkeypatch.setattr(panel_exposure, "public_bind_address", no_address)
    result = panel_exposure.expose_without_domain(confirm="expose")
    assert result.exit_code == 2
    assert "public address" in result.message


def test_public_bind_address_refuses_loopback_and_wildcard(tmp_wpfy_home, monkeypatch):
    """Binding a "public" panel to 127.0.0.1 or 0.0.0.0 would either do nothing
    or expose more than the operator was told."""
    monkeypatch.setattr(
        panel_exposure.certificate_lifecycle, "detect_public_ips",
        lambda: (("127.0.0.1", "0.0.0.0"), ()),
    )
    with pytest.raises(RuntimeError):
        panel_exposure.public_bind_address()


@needs_openssl
def test_the_panel_actually_serves_tls_with_the_generated_certificate(tmp_wpfy_home):
    """The point of the whole mode: the socket must be encrypted, and it must be
    encrypted with the certificate whose fingerprint the operator was given.

    Verified against that certificate as the only trust anchor, so a connection
    presenting anything else fails rather than quietly succeeding.
    """
    import http.client
    import ssl as ssl_module
    import threading

    from wpfy import panel

    certificate = panel_tls.ensure_self_signed("127.0.0.1")
    config = panel.PanelConfig(host="127.0.0.1", port=0, token="tls-test-token", self_signed_tls=True)
    server = panel.make_panel_server(config)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        context = ssl_module.create_default_context(cafile=str(certificate.certificate_path))
        connection = http.client.HTTPSConnection("127.0.0.1", port, context=context, timeout=10)
        connection.request("GET", "/api/setup/status", headers={"Authorization": "Bearer tls-test-token"})
        response = connection.getresponse()
        response.read()
        assert response.status in {200, 410}, response.status
        assert connection.sock.version().startswith("TLS")
        connection.close()

        # A plaintext request to the same socket must not be answered as HTTP.
        plain = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        with pytest.raises(Exception):
            plain.request("GET", "/api/setup/status")
            plain.getresponse()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_the_client_reads_the_setup_secret_from_the_fragment():
    """The secret rides in the URL fragment, which browsers never transmit.

    A query string would put an account-creation grant into the access log of
    every proxy on the path and into Referer headers. The client has to read it
    from `location.hash`, strip it from the address bar, and send it in the
    request body itself.
    """
    from pathlib import Path

    import wpfy.panel

    source = (Path(wpfy.panel.__file__).parent / "panel_static" / "panel.js").read_text(encoding="utf-8")
    assert "setup=" in source and "location.hash" in source
    assert "setup_secret" in source, "the secret is read but never sent"
    assert "?setup=" not in source, "the secret must not be put in a query string"


# ---------------------------------------------------------------------------
# Panel basic auth
# ---------------------------------------------------------------------------


def test_panel_basic_auth_is_absent_from_the_router_until_configured(tmp_wpfy_home):
    config = panel_exposure.render_router_config("panel.example.test", "http://10.0.0.2:8642")
    assert "basicAuth" not in config
    assert "wpfy-panel-rate-limit" in config


def test_panel_basic_auth_reaches_the_router_when_configured(tmp_wpfy_home):
    result = panel_exposure.set_panel_basic_auth("operator", "a-long-enough-password")
    assert result.exit_code == 0, result.message
    config = panel_exposure.render_router_config("panel.example.test", "http://10.0.0.2:8642")
    assert "basicAuth" in config
    assert "wpfy-panel-basic-auth" in config
    assert "operator:" in config


def test_panel_basic_auth_never_stores_the_password(tmp_wpfy_home):
    password = "a-long-enough-password"
    panel_exposure.set_panel_basic_auth("operator", password)
    stored = panel_exposure.panel_basic_auth_path().read_text(encoding="utf-8")
    assert password not in stored
    assert stored.startswith("operator:")

    config = panel_exposure.render_router_config("panel.example.test", "http://10.0.0.2:8642")
    assert password not in config


def test_panel_basic_auth_hash_is_a_format_traefik_can_verify(tmp_wpfy_home):
    """Found on the validation VPS: Traefik returned 401 for the right password.

    The per-site gate is verified by nginx, which hashes through crypt(3) and
    accepts sha512crypt. This one is verified by Traefik, whose basicAuth
    understands MD5-APR1, SHA1 and bcrypt only -- a `$6$` line loads without a
    single log line and then rejects the correct password forever, which reads
    as "I mistyped it" rather than "this can never work".
    """
    panel_exposure.set_panel_basic_auth("operator", "a-long-enough-password")
    _, _, hashed = panel_exposure.read_panel_basic_auth().partition(":")
    assert hashed.startswith("$apr1$"), hashed[:8]
    assert not hashed.startswith("$6$"), "sha512crypt is unverifiable by Traefik"


def test_panel_basic_auth_file_is_not_world_readable(tmp_wpfy_home):
    panel_exposure.set_panel_basic_auth("operator", "a-long-enough-password")
    mode = panel_exposure.panel_basic_auth_path().stat().st_mode & 0o777
    assert mode == 0o600, f"credential file mode is {mode:o}"


@pytest.mark.parametrize("username,password", [
    ("bad user", "a-long-enough-password"),
    ("op", "short"),
    ("", "a-long-enough-password"),
    ("operator", ""),
    ("op:erator", "a-long-enough-password"),
])
def test_panel_basic_auth_rejects_bad_input(tmp_wpfy_home, username, password):
    """A colon in the username would forge a second field in the htpasswd line."""
    result = panel_exposure.set_panel_basic_auth(username, password)
    assert result.exit_code != 0
    assert panel_exposure.read_panel_basic_auth() is None


def test_clearing_panel_basic_auth_removes_it_from_the_router(tmp_wpfy_home):
    panel_exposure.set_panel_basic_auth("operator", "a-long-enough-password")
    assert panel_exposure.clear_panel_basic_auth().exit_code == 0
    assert panel_exposure.panel_basic_auth_status()["enabled"] is False
    config = panel_exposure.render_router_config("panel.example.test", "http://10.0.0.2:8642")
    assert "basicAuth" not in config


def test_clearing_when_absent_is_not_an_error(tmp_wpfy_home):
    result = panel_exposure.clear_panel_basic_auth()
    assert result.exit_code == 0
    assert result.ran is False


def test_expose_refuses_without_a_real_acme_contact_address(tmp_wpfy_home, monkeypatch):
    """Found on a clean VPS: `expose --domain` succeeded and the certificate
    never issued.

    A fresh install ships the placeholder `admin@localhost`, which Let's Encrypt
    rejects at account registration -- "contact email has invalid domain" -- so
    Traefik served its own self-signed default forever. Enabling SSL for a site
    has refused on this since ADR 0016; the panel path skipped the same guard.
    """
    from wpfy import certificate_lifecycle, panel_auth, traefik

    monkeypatch.setattr(panel_auth, "login_required", lambda: True)
    monkeypatch.setattr(panel_exposure, "_has_totp_user", lambda: True)
    monkeypatch.setattr(
        certificate_lifecycle, "preflight_ssl",
        lambda domain: certificate_lifecycle.SSLPreflightResult(
            domain=domain, a_records=(), aaaa_records=(), public_ipv4=(), public_ipv6=(),
            passed=True, message="ok"))
    monkeypatch.setattr(traefik, "acme_email_problem", lambda: "ACME contact email is not configured; run wpfy stack acme-email")

    result = panel_exposure.expose("panel.example.test", confirm="panel.example.test")

    assert result.exit_code == 2
    assert "acme-email" in result.message
    assert not panel_exposure.panel_router_path().exists(), "a router was written despite the refusal"


def test_a_router_stays_recognised_after_basic_auth_is_stored(tmp_wpfy_home):
    """Found on a clean VPS: storing a credential made wpfy's own router
    unrecognisable, so the credential could never be applied.

    `_router_details` re-rendered the config and compared byte for byte. Storing
    a credential changes what the renderer produces, so a router wpfy had just
    written stopped matching -- and `set_panel_basic_auth` only rewrites a
    router it recognises. Exposure status went blind at the same time.
    """
    domain, target = "panel.example.test", "http://10.0.0.2:8642"
    panel_exposure.panel_router_path().parent.mkdir(parents=True, exist_ok=True)
    panel_exposure.panel_router_path().write_text(
        panel_exposure.render_router_config(domain, target), encoding="utf-8")
    assert panel_exposure.exposure_status()["domain"] == domain

    result = panel_exposure.set_panel_basic_auth("operator", "a-long-enough-password")
    assert result.exit_code == 0

    status = panel_exposure.exposure_status()
    assert status["recognised"] is True, "the router wpfy wrote became unreadable to wpfy"
    assert status["domain"] == domain
    assert status["target_port"] == 8642


def test_a_hand_edited_router_is_still_refused(tmp_wpfy_home):
    """The recognition check exists to avoid claiming understanding of a file
    wpfy did not write. Loosening it for the credential must not lose that."""
    panel_exposure.panel_router_path().parent.mkdir(parents=True, exist_ok=True)
    panel_exposure.panel_router_path().write_text(
        panel_exposure.render_router_config("panel.example.test", "http://10.0.0.2:8642")
        + "\n  # hand-edited by the administrator\n", encoding="utf-8")

    assert panel_exposure.exposure_status()["recognised"] is False


# ---------------------------------------------------------------------------
# `wpfy panel expose` asks for what it needs
# ---------------------------------------------------------------------------


def _expose_args(**overrides):
    import argparse

    from wpfy import panel

    values = {
        "panel_command": "expose", "status": False, "no_domain": False, "disable": False,
        "domain": None, "confirm": None, "email": None, "port": panel.DEFAULT_PANEL_PORT,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def test_expose_asks_for_the_domain_then_the_email(tmp_wpfy_home, monkeypatch):
    """A bare `wpfy panel expose` collects both, in that order.

    The contact address is asked for *before* exposing: a fresh install ships a
    placeholder Let's Encrypt refuses at account registration, and asking after
    the fact means the operator learns about it from a browser TLS error.
    """
    from wpfy import cli, stack

    prompts, captured = [], {}

    def fake_input(prompt):
        prompts.append(prompt)
        return {0: "panel.example.test", 1: "panel.example.test", 2: "ops@example.com"}[len(prompts) - 1]

    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", fake_input)
    monkeypatch.setattr(stack.traefik, "acme_email_problem", lambda: "no contact address")
    monkeypatch.setattr(stack.traefik, "set_acme_email", lambda address: captured.setdefault("email", address))
    monkeypatch.setattr(
        cli.panel_exposure, "expose",
        lambda domain, *, confirm, port: captured.update(domain=domain, confirm=confirm)
        or panel_exposure.RuntimeResult(0, "exposed", ran=True))

    cli.handle_panel_exposure(_expose_args())

    assert "domain" in prompts[0].lower()
    assert "email" in prompts[2].lower()
    assert captured == {"domain": "panel.example.test", "confirm": "panel.example.test",
                        "email": "ops@example.com"}


def test_expose_does_not_ask_for_an_email_the_host_already_has(tmp_wpfy_home, monkeypatch):
    from wpfy import cli, stack

    prompts = []
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt: prompts.append(prompt) or "panel.example.test")
    monkeypatch.setattr(stack.traefik, "acme_email_problem", lambda: None)
    monkeypatch.setattr(stack.traefik, "set_acme_email", lambda address: pytest.fail("re-asked for a stored address"))
    monkeypatch.setattr(
        cli.panel_exposure, "expose",
        lambda domain, *, confirm, port: panel_exposure.RuntimeResult(0, "exposed", ran=True))

    cli.handle_panel_exposure(_expose_args(domain="panel.example.test"))

    assert all("email" not in prompt.lower() for prompt in prompts)


def test_expose_without_a_tty_still_refuses_rather_than_hanging(tmp_wpfy_home, monkeypatch):
    """Scripted runs must fail with instructions, never block on a prompt."""
    from wpfy import cli

    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: False)
    monkeypatch.setattr("builtins.input", lambda prompt: pytest.fail("prompted with no tty"))

    result = cli.handle_panel_exposure(_expose_args())

    assert result.exit_code == 2
    assert "--domain" in result.message


def test_a_blank_domain_cancels(tmp_wpfy_home, monkeypatch):
    from wpfy import cli

    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt: "  ")
    monkeypatch.setattr(
        cli.panel_exposure, "expose",
        lambda *a, **k: pytest.fail("exposed despite a blank domain"))

    assert "cancelled" in cli.handle_panel_exposure(_expose_args()).message


def test_an_invalid_email_is_reported_before_anything_is_exposed(tmp_wpfy_home, monkeypatch):
    from wpfy import cli, stack

    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt: "panel.example.test")
    monkeypatch.setattr(stack.traefik, "acme_email_problem", lambda: "no contact address")
    monkeypatch.setattr(
        cli.panel_exposure, "expose",
        lambda *a, **k: pytest.fail("exposed despite a rejected contact address"))

    result = cli.handle_panel_exposure(_expose_args(domain="panel.example.test", email="not-an-email"))

    assert result.exit_code == 2
    assert "email" in result.message.lower()

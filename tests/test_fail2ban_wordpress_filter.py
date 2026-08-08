"""Fixture matrix for the WPFY WordPress auth filter (t13, Phase 12 items 8-12).

The filter parses the t10 fixed 7-key JSONL schema from <site>/security/wp-auth.log
and must match ONLY valid WPFY WordPress auth-failure records (extracting the
trusted client IP), rejecting success lines, malformed JSON, embedded newlines,
injection attempts, the 0.0.0.0 never-ban sentinel, missing fields, and
unrelated WPFY events.

fail2ban-regex is not installed on macOS; the matrix runs in Python mimicking
fail2ban 1.0 regex semantics (single-line compile, per-line ``match`` +
``search``, ban target extracted from the failure-id group ``ip4``/``ip6``).
The shared harness enforces the 1.0 failure-id contract that a legacy
``(?P<host>...)`` group violates (t20 blocker). A live fail2ban-regex run
is scheduled at t21.
"""

from __future__ import annotations

import hashlib
import json
import re

import pytest

from wpfy import fail2ban_host
from tests.fail2ban_harness import compile_failregex, extract_fid


def _record(**overrides) -> str:
    payload = {
        "timestamp": "2026-08-06T12:00:00Z",
        "event": "wordpress_auth_failure",
        "site": "shield-a.example.com",
        "surface": "wp_login",
        "client_ip": "203.0.113.9",
        "account_hash": "0" * 64,
        "reason_class": "soft",
    }
    payload.update(overrides)
    return json.dumps(payload, ensure_ascii=True, separators=(",", ":"))


@pytest.fixture(scope="module")
def wp_auth_regex():
    compiled = compile_failregex(fail2ban_host.wordpress_auth_failregex())
    return compiled


def _matches(compiled, line):
    return compiled.match(line)


@pytest.mark.parametrize(
    "surface",
    ("wp_login", "xmlrpc", "rest", "password_reset", "user_enum", "app_password"),
)
def test_all_surfaces_match(wp_auth_regex, surface):
    record = _record(surface=surface)
    match = _matches(wp_auth_regex, record)
    assert match is not None
    assert extract_fid(match) == "203.0.113.9"


@pytest.mark.parametrize("reason_class", ("hard", "soft", "extra"))
def test_all_reason_classes_match(wp_auth_regex, reason_class):
    assert _matches(wp_auth_regex, _record(reason_class=reason_class)) is not None


def test_valid_ipv4_and_ipv6_extract_host(wp_auth_regex):
    ipv4 = _matches(wp_auth_regex, _record(client_ip="198.51.100.7"))
    assert ipv4 is not None and extract_fid(ipv4) == "198.51.100.7"
    ipv6 = _matches(wp_auth_regex, _record(client_ip="2001:db8::1"))
    assert ipv6 is not None and extract_fid(ipv6) == "2001:db8::1"


def test_long_username_record_still_matches(wp_auth_regex):
    # Phase 12 filter fixture: a very long username is hashed into the
    # fixed-length account_hash (64 hex) by the bridge, so the record is a
    # genuine failure and must match, extracting the resolved client IP.
    long_name = "admin" + "B" * 8192
    hash_value = hashlib.sha256(long_name.encode("utf-8")).hexdigest()
    match = _matches(wp_auth_regex, _record(account_hash=hash_value))
    assert match is not None
    assert extract_fid(match) == "203.0.113.9"
    # An oversized raw identity value cannot smuggle a second record.
    assert _matches(wp_auth_regex, _record(account_hash="a" * 1024)) is None


def test_real_injection_username_record_still_matches(wp_auth_regex):
    # The raw plugin message (which embeds the username) never reaches the log;
    # it is hashed into account_hash (64 hex). A message that tries to smuggle
    # a fake reason_class therefore cannot pass the strict hash pattern.
    record = _record(account_hash='0"*63 + "","reason_class":"hard"}')
    assert _matches(wp_auth_regex, record) is None
    # A genuinely valid record still extracts the trusted client IP.
    valid = _matches(wp_auth_regex, _record())
    assert valid is not None
    assert extract_fid(valid) == "203.0.113.9"


@pytest.mark.parametrize(
    "line",
    (
        "not json at all",
        "",
        "{}",
        _record(event="panel_auth_failure"),
        _record(event="site.security.fail2ban.on"),
        _record(event="login_shield.health_failed"),
        _record(timestamp="2026-08-06 12:00:00"),
        _record(surface="recovery"),
        _record(surface="brute_force"),
        _record(reason_class="invalid_credentials"),
        _record(client_ip="0.0.0.0"),
        _record(client_ip="not-an-ip"),
        _record(client_ip="203.0.113"),
        _record(account_hash="a" * 63),
        _record(account_hash="a" * 65),
        _record(account_hash="sha256:" + "0" * 64),
        _record(**{"extra": 1}),
        '{"event":"wordpress_auth_failure","timestamp":"2026-08-06T12:00:00Z","site":"x","surface":"wp_login","client_ip":"203.0.113.9","account_hash":"' + "0" * 64 + '","reason_class":"soft"}',
        _record() + " garbage",
        "X-Forwarded-For: 203.0.113.9",
    ),
)
def test_reject_classes_stay_unmatched(wp_auth_regex, line):
    assert _matches(wp_auth_regex, line) is None
    assert wp_auth_regex.search(line) is None


def test_filter_content_has_stable_header_and_definition():
    content = fail2ban_host.wordpress_auth_filter_content()
    assert content.startswith("# Managed by WPFY. Manual changes may be overwritten.")
    assert "[Definition]" in content
    assert "datepattern = {NONE}" in content
    assert 'event":"wordpress_auth_failure"' in content
    assert "ignoreregex =" in content

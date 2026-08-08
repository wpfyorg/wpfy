"""Shared fail2ban 1.0 regex-semantics harness for WPFY filter tests.

fail2ban >=1.0 requires every failregex to carry a failure-id named group
(fid/ip4/ip6/dns); a legacy ``(?P<host>...)`` group raises RegexException at
jail start (fail2ban/server/failregex.py, FAILURE_ID_GROUPS). fail2ban compiles
each failregex line standalone and matches per physical line, so the harness
uses single-line flags (no MULTILINE, no DOTALL).

This module encodes that contract so the Python fixture matrix cannot drift
from the live binary again (t20 blocker). Every compiled failregex in the
suite must pass ``compile_failregex``; that is the shared guard.
"""

from __future__ import annotations

import re

# fail2ban 1.0 failure-id named groups (server/failregex.py FAILURE_ID_GROUPS).
FAILURE_ID_GROUPS = frozenset({"fid", "ip4", "ip6", "dns"})

# fail2ban compiles each failregex standalone against a single physical line.
FAIL2BAN_FLAGS = 0


def compile_failregex(pattern: str) -> re.Pattern:
    """Compile a failregex under fail2ban 1.0 semantics and enforce the
    failure-id group contract.

    Raises AssertionError when the pattern lacks a failure-id named group or
    still uses the legacy ``(?P<host>...)`` group. This is the guard that
    would have caught the t20 blocker.
    """
    rx = re.compile(pattern, FAIL2BAN_FLAGS)
    groups = set(rx.groupindex)
    assert groups & FAILURE_ID_GROUPS, (
        "failregex has no failure-id group (fid/ip4/ip6/dns); fail2ban >=1.0 "
        f"rejects it with RegexException: {pattern!r}"
    )
    assert "host" not in groups, (
        "failregex uses legacy (?P<host>...) group; fail2ban >=1.0 reads "
        f"ip4/ip6/dns, not host: {pattern!r}"
    )
    return rx


def extract_fid(match: re.Match) -> str:
    """Extract the ban target from a fail2ban 1.0 match.

    Exactly one of the failure-id groups is populated per match; prefer
    ip4/ip6 (the WPFY filters never emit fid/dns).
    """
    for name in ("ip4", "ip6", "dns", "fid"):
        value = match.group(name)
        if value is not None:
            return value
    raise AssertionError(f"match carries no failure-id group value: {match.re.pattern!r}")


def failregex_lines(content: str) -> list[str]:
    """Extract full failregex patterns (continuation lines joined) from a
    rendered filter body."""
    patterns: list[str] = []
    current: str | None = None
    for line in content.splitlines():
        if line.lstrip().startswith("failregex"):
            current = line.split("=", 1)[1].strip()
        elif line.startswith(" ") and current is not None and line.strip():
            current = f"{current} {line.strip()}"
        elif current is not None and not line.strip():
            patterns.append(current)
            current = None
    if current is not None:
        patterns.append(current)
    return patterns

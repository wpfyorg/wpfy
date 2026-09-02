"""Secret redaction utilities."""
from __future__ import annotations

import re
from typing import Final, Iterable


REDACTION_MARKER: Final = "***REDACTED***"


def redact_values(text: str, values: Iterable[str]) -> str:
    """Redact values."""
    secrets = sorted({value for value in values if value}, key=len, reverse=True)
    if not secrets:
        return text
    pattern = re.compile("|".join((re.escape(REDACTION_MARKER), *(re.escape(secret) for secret in secrets))))
    return pattern.sub(REDACTION_MARKER, text)

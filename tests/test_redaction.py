from wpfy.redaction import REDACTION_MARKER, redact_values


def test_redact_values_handles_empty_duplicate_overlap_unicode_and_existing_marker():
    text = f"prefix secret secret-key secret-key sęcret {REDACTION_MARKER} suffix"

    result = redact_values(text, ("", "secret", "secret-key", "secret", "sęcret"))

    assert result == " ".join((
        "prefix",
        REDACTION_MARKER,
        REDACTION_MARKER,
        REDACTION_MARKER,
        REDACTION_MARKER,
        REDACTION_MARKER,
        "suffix",
    ))
    assert "secret" not in result
    assert "sęcret" not in result


def test_redact_values_without_secrets_keeps_text():
    assert redact_values("safe", ("", "")) == "safe"

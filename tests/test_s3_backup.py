from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import hmac
import io
import stat
from urllib.parse import urlsplit

import pytest

from wpfy.s3_backup import S3Config, S3Uploader, signed_put_request


def _config() -> S3Config:
    return S3Config(
        endpoint="https://storage.example.test",
        bucket="site-backups",
        region="us-east-1",
        prefix="daily",
        access_key="AKIDEXAMPLE",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
    )


class Response(io.BytesIO):
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def _reconstruct_signature(request, secret_key):
    authorization = request.headers["Authorization"]
    fields = dict(part.split("=", 1) for part in authorization.split(" ", 1)[1].split(", "))
    credential_scope = fields["Credential"].split("/", 1)[1]
    signed_headers = fields["SignedHeaders"].split(";")
    headers = {name.lower(): value.strip() for name, value in request.headers.items()}
    parsed = urlsplit(request.full_url)
    canonical_headers = "".join(f"{name}:{headers[name]}\n" for name in signed_headers)
    canonical_request = "\n".join([
        request.method,
        parsed.path,
        parsed.query,
        canonical_headers,
        fields["SignedHeaders"],
        headers["x-amz-content-sha256"],
    ])
    amz_date = headers["x-amz-date"]
    string_to_sign = "\n".join([
        "AWS4-HMAC-SHA256",
        amz_date,
        credential_scope,
        hashlib.sha256(canonical_request.encode()).hexdigest(),
    ])
    date_stamp, region, service, terminal = credential_scope.split("/")
    date_key = hmac.new(f"AWS4{secret_key}".encode(), date_stamp.encode(), hashlib.sha256).digest()
    region_key = hmac.new(date_key, region.encode(), hashlib.sha256).digest()
    service_key = hmac.new(region_key, service.encode(), hashlib.sha256).digest()
    signing_key = hmac.new(service_key, terminal.encode(), hashlib.sha256).digest()
    return fields, hmac.new(signing_key, string_to_sign.encode(), hashlib.sha256).hexdigest()


def test_signed_put_request_has_deterministic_signature(monkeypatch):
    import wpfy.s3_backup as s3_backup

    class FixedDatetime:
        @classmethod
        def now(cls, tz):
            return datetime(2013, 5, 24, tzinfo=timezone.utc)

    monkeypatch.setattr(s3_backup, "datetime", FixedDatetime)
    request = signed_put_request(_config(), "daily/example.com/archive.tar.gz", b"payload")

    assert request.full_url == (
        "https://storage.example.test/site-backups/daily/example.com/archive.tar.gz"
    )
    assert request.headers["X-amz-content-sha256"] == hashlib.sha256(b"payload").hexdigest()
    assert request.headers["X-amz-date"] == "20130524T000000Z"
    assert request.headers["Authorization"] == (
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20130524/us-east-1/s3/aws4_request, "
        "SignedHeaders=host;x-amz-content-sha256;x-amz-date, "
        "Signature=2bcf3ac62dfcb881664b3a93b50be364255000267247cc673251f3e433b750c5"
    )


@pytest.mark.parametrize("payload", [b"", b"archive payload\n" * 1000], ids=["empty", "nonempty"])
def test_upload_archive_uses_file_body_with_exact_hash_and_length(tmp_path, monkeypatch, payload):
    import wpfy.s3_backup as s3_backup

    class FixedDatetime:
        @classmethod
        def now(cls, tz):
            return datetime(2013, 5, 24, tzinfo=timezone.utc)

    monkeypatch.setattr(s3_backup, "datetime", FixedDatetime)
    archive = tmp_path / "example.tar.gz"
    archive.write_bytes(payload)
    observed = {}

    def opener(request, *, timeout):
        body = request.data
        observed["is_bytes"] = isinstance(body, bytes)
        observed["payload"] = body.read()
        observed["length"] = request.headers["Content-length"]
        observed["hash"] = request.headers["X-amz-content-sha256"]
        fields, reconstructed = _reconstruct_signature(request, _config().secret_key)
        observed["signed_headers"] = fields["SignedHeaders"]
        observed["signature_matches"] = reconstructed == fields["Signature"]
        return Response()

    uploaded = S3Uploader(opener).upload_archive(_config(), archive, "example.com")

    assert uploaded == "s3://site-backups/daily/example.com/example.tar.gz"
    assert observed == {
        "is_bytes": False,
        "payload": payload,
        "length": str(len(payload)),
        "hash": hashlib.sha256(payload).hexdigest(),
        "signed_headers": "content-length;host;x-amz-content-sha256;x-amz-date",
        "signature_matches": True,
    }


def test_download_to_path_reads_bounded_chunks_and_makes_file_private(tmp_path):
    payload = b"remote archive" * 100_000

    class BoundedResponse(Response):
        def __init__(self, value):
            super().__init__(value)
            self.read_sizes = []

        def read(self, size=-1):
            assert size > 0
            self.read_sizes.append(size)
            return super().read(size)

    response = BoundedResponse(payload)
    destination = tmp_path / "remote.tar.gz"

    result = S3Uploader(lambda request, timeout: response).download_to_path(
        _config(), "daily/example.com/remote.tar.gz", destination
    )

    assert result == destination
    assert destination.read_bytes() == payload
    assert response.read_sizes
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600


def test_download_to_path_propagates_interrupted_read(tmp_path):
    destination = tmp_path / "remote.tar.gz"

    class InterruptedResponse(Response):
        calls = 0

        def read(self, size=-1):
            self.calls += 1
            if self.calls == 2:
                raise OSError("connection interrupted")
            return b"partial"

    with pytest.raises(OSError, match="interrupted"):
        S3Uploader(lambda request, timeout: InterruptedResponse()).download_to_path(
            _config(), "daily/example.com/remote.tar.gz", destination
        )

    assert destination.read_bytes() == b"partial"


def test_download_to_path_rejects_short_response(tmp_path):
    destination = tmp_path / "remote.tar.gz"

    class ShortResponse(Response):
        headers = {"Content-Length": "20"}

    with pytest.raises(OSError, match="incomplete download"):
        S3Uploader(lambda request, timeout: ShortResponse(b"short")).download_to_path(
            _config(), "daily/example.com/remote.tar.gz", destination
        )

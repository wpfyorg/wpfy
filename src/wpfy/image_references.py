"""Authoritative image references used by generated WPFY Compose files.

Every normal runtime image has both a human-readable tag and an OCI digest.
The SFTP image is an explicit temporary exception: ``atmoz/sftp:alpine`` is
currently verified only as a single-architecture amd64 image, while WPFY
supports arm hosts.  See ``docs/IMAGE_UPDATE_POLICY.md`` for its owner,
replacement criteria, and update procedure.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Final, Mapping


PHP_IMAGE_REPOSITORY: Final = "ghcr.io/wpfyorg/php-fpm"

PHP_IMAGE_REFERENCES: Final[Mapping[str, str]] = MappingProxyType({
    "7.4": (
        f"{PHP_IMAGE_REPOSITORY}:7.4@"
        "sha256:050d85df4c44949050cb05edf907ae31475d37ecf7bf980c39e0602ddb0aa97b"
    ),
    "8.0": (
        f"{PHP_IMAGE_REPOSITORY}:8.0@"
        "sha256:6c6679d87c47f53c5bd8772a8af36b2a7bd05813315bb660cd615282a5949d5f"
    ),
    "8.1": (
        f"{PHP_IMAGE_REPOSITORY}:8.1@"
        "sha256:f7ee4ff09a6e4edcbce8080d354fc93530cec29261d0909f98c18de5997afe29"
    ),
    "8.2": (
        f"{PHP_IMAGE_REPOSITORY}:8.2@"
        "sha256:d084eb567d3f15427e7fa8c2968b30d9d42311ccd64b97bea3f9743f54281b4b"
    ),
    "8.3": (
        f"{PHP_IMAGE_REPOSITORY}:8.3@"
        "sha256:fcea329577b7f1dae83ac9ce5e66ca1012a2f4deee478956c52da3c5781185cb"
    ),
    "8.4": (
        f"{PHP_IMAGE_REPOSITORY}:8.4@"
        "sha256:65e4641e8afb712c78a1ff0e295d4758a9bac7523fce2901e47dfe2050d8dd3f"
    ),
})

WEB_IMAGE: Final = (
    "nginxinc/nginx-unprivileged:1.27-alpine@"
    "sha256:65e3e85dbaed8ba248841d9d58a899b6197106c23cb0ff1a132b7bfe0547e4c0"
)
MARIADB_IMAGE: Final = (
    "mariadb:11.4.12@"
    "sha256:b822597b1c5225aa3b891b1b16cd5ef666b3b419614730fd19a7f4056bc3f776"
)
REDIS_IMAGE: Final = (
    "redis:7.2.15-alpine@"
    "sha256:05a97a479bc73de66f087dc05b569010772880f778cc8671fa6b8aadee32e5c6"
)
TRAEFIK_IMAGE: Final = (
    "traefik:v3.6.17@"
    "sha256:802adc80a7bb20a6766c9385c2ad547f0de98564cd20d31d0b6d8f726f906f66"
)
ADMINER_IMAGE: Final = (
    "adminer:5.5.1@"
    "sha256:890cffec7caa20159fb6f68c1a521b2e5879f7314f4845d4ebca7cc1cf145971"
)

# The socket-proxy digest predates this inventory and remains pinned here.
SOCKET_PROXY_IMAGE: Final = (
    "wollomatic/socket-proxy:1.12.3@"
    "sha256:74e770f5ed3cfc9ecb6350e177d2aa55873568c85bc953079834e68607dbf71b"
)

# Quantum's existing digest is preserved deliberately.  Its provider is
# outside the Phase 1 write boundary, but the reference is recorded here so
# the inventory remains complete for auditing.
QUANTUM_IMAGE: Final = (
    "gtstef/filebrowser:1.5.0-stable-slim@"
    "sha256:aadfaa026ebae24e373e523662cd9e8f562b5e3c404ac1df65ef13ddcd14b2fc"
)

# Temporary, documented exception; do not add a digest until a multi-platform
# manifest is available and verified for every supported WPFY architecture.
SFTP_IMAGE: Final = "atmoz/sftp:alpine"

# These are stack-install helper-only pulls, not images emitted into site
# Compose files. They are still part of the authoritative pinned inventory.
HELPER_IMAGE_REFERENCES: Final[Mapping[str, str]] = MappingProxyType({
    "phpmyadmin": (
        "phpmyadmin:5.2.2-apache@"
        "sha256:6b5ab5f9ebfe3dbb38388b5695c2ff5ba3e26cdc2c4ce0bd97092eefc6a20bfd"
    ),
    "composer": (
        "composer:2.8.8@"
        "sha256:3df281ca83119bff1332f0f5f311960cb16b99238f8273acd965be6bd508aa8e"
    ),
})

PINNED_RUNTIME_IMAGES: Final = (
    *PHP_IMAGE_REFERENCES.values(),
    WEB_IMAGE,
    MARIADB_IMAGE,
    REDIS_IMAGE,
    TRAEFIK_IMAGE,
    SOCKET_PROXY_IMAGE,
    ADMINER_IMAGE,
    QUANTUM_IMAGE,
    *HELPER_IMAGE_REFERENCES.values(),
)


def php_image(version: str) -> str:
    """Return the checked-in immutable PHP image for a supported version."""
    try:
        return PHP_IMAGE_REFERENCES[version]
    except KeyError as exc:
        supported = ", ".join(PHP_IMAGE_REFERENCES)
        raise ValueError(f"unsupported PHP version {version!r}; supported versions: {supported}") from exc

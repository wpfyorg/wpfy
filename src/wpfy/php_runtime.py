from __future__ import annotations

PHP_IMAGE_REPOSITORY = "ghcr.io/wpfyorg/php-fpm"
SUPPORTED_PHP_VERSIONS = ("7.4", "8.0", "8.1", "8.2", "8.3", "8.4")
DEFAULT_PHP_VERSION = "8.4"


def php_image(version: str) -> str:
    return f"{PHP_IMAGE_REPOSITORY}:{version}"

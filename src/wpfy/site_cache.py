"""Site-level cache configuration (page cache, object cache, opcache)."""
from __future__ import annotations

from dataclasses import dataclass, replace
import os
from pathlib import Path
import secrets
import stat
import time

from . import cache_operations
from .events import record_event
from .site_definition import (
    PAGE_CACHE_OPTIONS,
    WORDPRESS_FLAVORS,
    SiteDefinition,
    validate_object_cache,
    validate_page_cache,
)
from .site_layout import (
    BASE_SECURITY_HEADERS as WPFY_SECURITY_HEADERS,
    HSTS_HEADER as WPFY_HSTS_HEADER,
    ensure_site_scaffold,
)
from .site_paths import env_path, nginx_dir, read_env, site_exists, validate_domain
from .site_runtime import (
    ProcessResult,
    compose_command,
    docker_available,
    run_wp_cli,
    runtime_skip_requested,
    start_site_runtime,
)


FREE_PAGE_CACHE_PLUGINS = frozenset({
    "wp-super-cache",
    "w3-total-cache",
    "cache-enabler",
    "wp-fastest-cache",
})
BYO_PAGE_CACHE_PLUGINS = frozenset({"wp-rocket", "flying-press"})
# WP Rocket's own default mobile-detection list. Only consulted when the site is
# keeping a separate mobile cache, so a false positive costs nothing.
MOBILE_USER_AGENTS = (
    "android|blackberry|iphone|ipad|ipod|iemobile|opera mobile|palmos|webos|googlebot-mobile"
)
# WP Rocket writes its page cache here, under the site's document root.
ROCKET_CACHE_DIR = "/var/www/html/wp-content/cache/wp-rocket"
MANAGED_PAGE_CACHE_PLUGINS = frozenset({*FREE_PAGE_CACHE_PLUGINS, "nginx-helper"})
PAGE_CACHE_PLUGIN_SLUG = {
    "wpfc": "nginx-helper",
    "wp-super-cache": "wp-super-cache",
    "w3-total-cache": "w3-total-cache",
    "cache-enabler": "cache-enabler",
    "wp-fastest-cache": "wp-fastest-cache",
}
PLUGIN_PURGE_ARGS = {
    "wpfc": ("nginx-helper", "purge-all"),
    "wp-super-cache": ("super-cache", "flush"),
    "w3-total-cache": ("w3-total-cache", "flush", "all"),
    "cache-enabler": ("cache-enabler", "clear"),
    "wp-fastest-cache": ("fastest-cache", "clear", "all"),
    "wp-rocket": ("rocket", "clean", "--confirm"),
    # FlyingPress registers preload-cache, purge-pages-and-preload,
    # purge-everything and activate-license — there is no bare "purge".
    "flying-press": ("flying-press", "purge-everything"),
}


@dataclass(frozen=True, slots=True)
class CacheActionResult:
    """Cache action result."""
    status: str
    message: str
    exit_code: int = 0
    changed: bool = False


@dataclass(frozen=True, slots=True)
class CacheConfigurationResult:
    """Cache configuration result."""
    definition: SiteDefinition
    actions: tuple[CacheActionResult, ...]
    touched: tuple[str, ...] = ()

    @property
    def exit_code(self) -> int:
        """Return exit code."""
        return next((action.exit_code for action in self.actions if action.exit_code != 0), 0)

    @property
    def message(self) -> str:
        """Return message."""
        return "; ".join(action.message for action in self.actions if action.message)


def _definition(domain: str) -> SiteDefinition:
    validate_domain(domain)
    if not site_exists(domain):
        raise FileNotFoundError(f"site not found: {domain}")
    definition = SiteDefinition.from_env(domain, read_env(env_path(domain)))
    if definition.flavor not in WORDPRESS_FLAVORS:
        raise ValueError(f"cache integration requires a WordPress site: {domain}")
    return definition


def _bypass_conditions() -> str:
    return "\n".join([
        "set $wpfy_skip_cache 0;",
        'if ($http_cookie ~* "wordpress_logged_in") { set $wpfy_skip_cache 1; }',
        'if ($http_cookie ~* "comment_author") { set $wpfy_skip_cache 1; }',
        'if ($http_cookie ~* "wp-postpass") { set $wpfy_skip_cache 1; }',
        'if ($request_method = POST) { set $wpfy_skip_cache 1; }',
        'if ($query_string != "") { set $wpfy_skip_cache 1; }',
        'if ($request_uri ~* "^/wp-admin(?:/|$)") { set $wpfy_skip_cache 1; }',
    ])


def _rocket_nginx_lines(ssl_enabled: bool) -> list[str]:
    """Serve WP Rocket's cached HTML from nginx instead of routing it through PHP.

    Adapted from Rocket-Nginx 3.1.2 (MIT), https://github.com/satellitewp/rocket-nginx.
    Two deliberate departures from upstream:

    * wpfy's own `$wpfy_skip_cache` decides whether a request may be served from
      cache. Upstream re-derives that from its own cookie/method list; keeping one
      authority means the bypass invariant cannot drift between the two halves.
    * The pre-gzipped `.html_gzip` variants are never served. Handing a client a
      pre-encoded body means owning Content-Encoding by hand, and getting it wrong
      corrupts the response; nginx's own gzip compresses the plain file instead.
      # ponytail: re-compresses per request. Serve `_gzip` if CPU ever shows up.
    """
    cached_html = "^/wp-content/cache/wp-rocket/.*\\.html$"
    headers = list(WPFY_SECURITY_HEADERS)
    if ssl_enabled:
        headers.append(WPFY_HSTS_HEADER)
    return [
        "# WP Rocket static cache (Rocket-Nginx 3.1.2, MIT).",
        "set $rocket_bypass 1;",
        'set $rocket_cache "MISS";',
        'set $rocket_https_prefix "";',
        'set $rocket_mobile_prefix "";',
        'set $rocket_device "desktop";',
        "# wpfy's bypass rules are authoritative; rocket only resolves the filename.",
        "if ($wpfy_skip_cache = 1) { set $rocket_bypass 0; }",
        # WP Rocket names its directories from the raw request path, so the lookup
        # has to use $request_uri (percent-encoded) rather than the decoded $uri.
        "set $rocket_uri_path $request_uri;",
        'if ($request_uri ~* "^([^?]*)\\?") { set $rocket_uri_path $1; }',
        'if ($wpfy_https = "on") { set $rocket_https_prefix "-https"; }',
        'set $rocket_dir "$document_root/wp-content/cache/wp-rocket/$http_host$rocket_uri_path";',
        # WP Rocket drops a .mobile-active marker only when it is keeping a separate
        # mobile cache. Without this check a phone would be served the desktop page.
        f'if ($http_user_agent ~* "{MOBILE_USER_AGENTS}") {{ set $rocket_device "mobile"; }}',
        'if (-f "$rocket_dir/.mobile-active") { set $rocket_mobile_prefix "-mobile"; }',
        'if ($rocket_device != "mobile") { set $rocket_mobile_prefix ""; }',
        'set $rocket_name "index$rocket_mobile_prefix$rocket_https_prefix.html";',
        'if (!-f "$rocket_dir/$rocket_name") { set $rocket_bypass 0; }',
        'if (-f "$document_root/.maintenance") { set $rocket_bypass 0; }',
        'if ($rocket_bypass = 1) { set $rocket_cache "HIT"; }',
        "add_header X-Wpfy-Cache $rocket_cache always;",
        "if ($rocket_bypass = 1) {",
        '    rewrite .* "/wp-content/cache/wp-rocket/$http_host$rocket_uri_path/$rocket_name" last;',
        "}",
        f"location ~ {cached_html} {{",
        *(f"    {header}" for header in headers),
        "    add_header X-Wpfy-Cache $rocket_cache always;",
        # A shared cache in front of the site sees one URL answered either from this
        # file or by PHP for a logged-in visitor. Vary on Cookie so it cannot merge
        # the two, and refuse to let it keep a copy of a page wpfy may purge.
        '    add_header Vary "Accept-Encoding, Cookie" always;',
        '    add_header Cache-Control "no-cache, no-store, must-revalidate" always;',
        "}",
    ]


def _cache_snippet(plugin: str, ssl_enabled: bool = False) -> str:
    plugin = validate_page_cache(plugin)
    if plugin == "none":
        return ""
    lines = [
        "# Generated by wpfy. Cache safety rules are managed; do not edit.",
        f"# Page cache: {plugin}",
        _bypass_conditions(),
    ]
    if plugin == "wpfc":
        lines.extend([
            "fastcgi_cache WPFY;",
            "add_header X-Wpfy-Cache $upstream_cache_status always;",
            "fastcgi_cache_methods GET HEAD;",
            'fastcgi_cache_key "$scheme$request_method$host$request_uri";',
            "fastcgi_cache_valid 200 301 302 10m;",
        ])
    elif plugin == "wp-rocket":
        lines.extend(_rocket_nginx_lines(ssl_enabled))
    lines.extend([
        "fastcgi_cache_bypass $wpfy_skip_cache;",
        "fastcgi_no_cache $wpfy_skip_cache;",
        "",
    ])
    return "\n".join(lines)


def _cache_path_snippet(plugin: str) -> str:
    if plugin != "wpfc":
        return ""
    return (
        "# Generated by wpfy for the per-site FastCGI cache.\n"
        "fastcgi_cache_path /var/cache/nginx/fastcgi levels=1:2 "
        "keys_zone=WPFY:100m inactive=60m max_size=1g use_temp_path=off;\n"
    )


def _safe_write(root: Path, name: str, content: str) -> None:
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        file_fd = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
            0o644,
            dir_fd=root_fd,
        )
        with os.fdopen(file_fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(root_fd)


def _safe_read(root: Path, name: str) -> str | None:
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        try:
            file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=root_fd)
        except FileNotFoundError:
            return None
        with os.fdopen(file_fd, "r", encoding="utf-8") as handle:
            return handle.read()
    finally:
        os.close(root_fd)


def _safe_unlink(root: Path, name: str) -> bool:
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        try:
            metadata = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        except FileNotFoundError:
            return False
        if stat.S_ISLNK(metadata.st_mode):
            raise OSError(f"managed cache config is a symlink: {name}")
        os.unlink(name, dir_fd=root_fd)
        return True
    finally:
        os.close(root_fd)


def _replace_file(root: Path, target: str, replacement: str) -> None:
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        try:
            metadata = os.stat(target, dir_fd=root_fd, follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode):
                raise OSError(f"managed cache config is a symlink: {target}")
        except FileNotFoundError:
            pass
        os.replace(replacement, target, src_dir_fd=root_fd, dst_dir_fd=root_fd)
    finally:
        os.close(root_fd)


def _cleanup(root: Path, name: str) -> None:
    try:
        _safe_unlink(root, name)
    except OSError:
        pass


def render_cache_nginx(domain: str) -> CacheActionResult:
    """Render cache nginx."""
    definition = _definition(domain)
    plugin = validate_page_cache(definition.page_cache)
    cache_content = _cache_snippet(plugin, definition.ssl_enabled)
    path_content = _cache_path_snippet(plugin)
    nginx_root = nginx_dir(domain)
    extra_root = nginx_root / "extra"
    cache_name = "wpfy-cache.conf"
    path_name = "cache-path.conf"
    cache_candidate_name = f".wpfy-cache-{secrets.token_hex(8)}.candidate"

    try:
        current_cache = _safe_read(extra_root, cache_name)
        current_path = _safe_read(nginx_root, path_name)
        if current_cache == (cache_content or None) and current_path == path_content:
            return CacheActionResult("ok", "nginx cache config unchanged")
        # These are deterministic wpfy templates from validated inputs. Do not
        # container-validate them here: scaffold can precede app startup, and the
        # include directory is mounted read-only. Operator custom.conf keeps the
        # fail-closed nginx -t path in site_layout.
        _safe_write(extra_root, cache_candidate_name, cache_content)
        # cache-path.conf is mounted individually, so it must retain its inode.
        # O_NOFOLLOW keeps the in-place write from following a destination symlink.
        _safe_write(nginx_root, path_name, path_content)

        if plugin == "wpfc":
            _replace_file(extra_root, cache_name, cache_candidate_name)
            cache_candidate_name = ""
        elif plugin == "none":
            changed = _safe_unlink(extra_root, cache_name)
            if not changed and current_path == path_content:
                return CacheActionResult("ok", "nginx cache config unchanged")
        else:
            _replace_file(extra_root, cache_name, cache_candidate_name)
            cache_candidate_name = ""
    except OSError as exc:
        return CacheActionResult("error", f"failed to install nginx cache config: {exc}", 3)
    finally:
        if cache_candidate_name:
            _cleanup(extra_root, cache_candidate_name)

    if not runtime_skip_requested() and docker_available():
        for attempt in range(3):
            try:
                proc = compose_command(domain, "exec", "-T", "web", "nginx", "-s", "reload")
            except OSError as exc:
                return CacheActionResult(
                    "error",
                    f"cache config installed but nginx reload failed: {exc}; run wpfy debug {domain}",
                    3,
                    True,
                )
            if proc.returncode == 0:
                break
            if attempt < 2:
                time.sleep(0.5)
        if proc.returncode != 0:
            output = proc.stderr.strip() or proc.stdout.strip() or "no nginx error output"
            return CacheActionResult(
                "error",
                f"cache config installed but nginx reload failed: {output}; run wpfy debug {domain}",
                proc.returncode or 1,
                True,
            )
    return CacheActionResult("ok", f"nginx cache config staged for {plugin}", changed=True)


def _deactivate_other_page_plugins(domain: str, selected_slug: str | None) -> None:
    for slug in sorted(MANAGED_PAGE_CACHE_PLUGINS):
        if slug != selected_slug:
            run_wp_cli(domain, "plugin", "deactivate", slug, interactive=False)


def _process_message(proc: ProcessResult, fallback: str) -> str:
    return proc.stderr.strip() or proc.stdout.strip() or fallback


def install_page_cache(domain: str, plugin: str) -> CacheActionResult:
    """Install page cache."""
    _definition(domain)
    plugin = validate_page_cache(plugin)
    selected_slug = PAGE_CACHE_PLUGIN_SLUG.get(plugin)
    _deactivate_other_page_plugins(domain, selected_slug)
    if plugin in BYO_PAGE_CACHE_PLUGINS:
        return CacheActionResult(
            "awaiting-upload",
            f"{plugin} server configuration staged; awaiting operator upload and activation",
        )
    if plugin == "none":
        return CacheActionResult("ok", "page-cache plugins deactivated")
    if selected_slug is None:
        return CacheActionResult("error", f"unsupported page cache: {plugin}", 2)
    proc = run_wp_cli(domain, "plugin", "install", selected_slug, "--activate", interactive=False)
    if proc.exit_code != 0:
        return CacheActionResult("error", _process_message(proc, f"failed to install {selected_slug}"), proc.exit_code or 1)
    return CacheActionResult("ok", f"{selected_slug} installed and activated", changed=True)


def set_wp_cache_constants(domain: str) -> CacheActionResult:
    """Set wp cache constants."""
    definition = _definition(domain)
    value = "true" if definition.page_cache != "none" else "false"
    proc = run_wp_cli(
        domain,
        "config",
        "set",
        "WP_CACHE",
        value,
        "--raw",
        "--type=constant",
        interactive=False,
    )
    if proc.exit_code != 0:
        return CacheActionResult("error", _process_message(proc, "failed to set WP_CACHE"), proc.exit_code or 1)
    return CacheActionResult("ok", f"WP_CACHE asserted {value}")


def wire_redis_backend(domain: str) -> CacheActionResult:
    """Wire redis backend."""
    definition = _definition(domain)
    if definition.object_cache == "none":
        run_wp_cli(domain, "redis", "disable", interactive=False)
        run_wp_cli(domain, "plugin", "deactivate", "redis-cache", interactive=False)
        return CacheActionResult("ok", "Redis object cache disabled")

    steps = (
        ("plugin", "install", "redis-cache", "--activate"),
        ("config", "set", "WP_REDIS_HOST", "redis", "--type=constant"),
        ("config", "set", "WP_REDIS_PORT", "6379", "--raw", "--type=constant"),
        ("redis", "enable"),
    )
    for args in steps:
        proc = run_wp_cli(domain, *args, interactive=False)
        if proc.exit_code != 0:
            return CacheActionResult("error", _process_message(proc, f"wp {' '.join(args)} failed"), proc.exit_code or 1)
    return CacheActionResult("ok", "Redis Object Cache installed, wired to redis:6379, and enabled", changed=True)


def configure_site_cache(domain: str) -> CacheConfigurationResult:
    """Configure site cache."""
    definition = _definition(domain)
    actions = (
        render_cache_nginx(domain),
        install_page_cache(domain, definition.page_cache),
        set_wp_cache_constants(domain),
        wire_redis_backend(domain),
    )
    return CacheConfigurationResult(definition, actions)


def set_page_cache(domain: str, plugin: str) -> CacheConfigurationResult:
    """Set page cache."""
    definition = _definition(domain)
    plugin = validate_page_cache(plugin)
    desired = replace(definition, page_cache=plugin)
    touched = tuple(ensure_site_scaffold(desired))
    runtime = start_site_runtime(domain)
    if runtime.exit_code != 0 and not runtime.skipped:
        action = CacheActionResult("error", runtime.message, runtime.exit_code)
        result = CacheConfigurationResult(desired, (action,), touched)
    else:
        configured = configure_site_cache(domain)
        result = CacheConfigurationResult(configured.definition, configured.actions, touched)
    record_event(
        "cache.page.set",
        domain=domain,
        outcome="ok" if result.exit_code == 0 else "error",
        detail=f"page cache={plugin}",
    )
    return result


def set_object_cache(domain: str, backend: str) -> CacheConfigurationResult:
    """Set object cache."""
    definition = _definition(domain)
    backend = validate_object_cache(backend)
    desired = replace(definition, object_cache=backend, use_redis=backend == "redis")
    touched = tuple(ensure_site_scaffold(desired))
    runtime = start_site_runtime(domain)
    if runtime.exit_code != 0 and not runtime.skipped:
        action = CacheActionResult("error", runtime.message, runtime.exit_code)
        result = CacheConfigurationResult(desired, (action,), touched)
    else:
        action = wire_redis_backend(domain)
        result = CacheConfigurationResult(desired, (action,), touched)
    record_event(
        "cache.object.set",
        domain=domain,
        outcome="ok" if result.exit_code == 0 else "error",
        detail=f"object cache={backend}",
    )
    return result


def _purge_rocket_files(domain: str) -> cache_operations.CacheOutcome:
    """Delete WP Rocket's cached HTML from disk.

    nginx serves these files without consulting PHP, so a failed `wp rocket clean`
    would otherwise leave purged pages still being served. Runs in the app
    container, which owns the files; the web container mounts the app read-only.
    """
    if runtime_skip_requested() or not docker_available():
        return cache_operations.CacheOutcome(
            domain, "rocket", "error", "runtime unavailable (Docker/Compose not available)",
        )
    try:
        proc = compose_command(
            domain,
            "exec",
            "-T",
            "app",
            "sh",
            "-lc",
            f"rm -rf {ROCKET_CACHE_DIR}/* 2>/dev/null || true",
        )
    except Exception as exc:  # noqa: BLE001 - surfaced as an outcome, never raised
        return cache_operations.CacheOutcome(domain, "rocket", "error", f"exec failed: {exc}")
    if proc.returncode == 0:
        return cache_operations.CacheOutcome(domain, "rocket", "ok", "static page cache cleared")
    return cache_operations.CacheOutcome(
        domain, "rocket", "error", "exec failed (site may be stopped)",
    )


def purge_site_cache(domain: str) -> cache_operations.CacheResult:
    """Purge site cache."""
    definition = _definition(domain)
    outcomes: list[cache_operations.CacheOutcome] = []
    purge_args = PLUGIN_PURGE_ARGS.get(definition.page_cache)
    if purge_args:
        proc = run_wp_cli(domain, *purge_args, interactive=False)
        if proc.exit_code == 0:
            outcomes.append(cache_operations.CacheOutcome(domain, "plugin", "ok", "plugin cache flushed"))
        else:
            outcomes.append(cache_operations.CacheOutcome(
                domain,
                "plugin",
                "skipped",
                _process_message(proc, "plugin purge command unavailable"),
            ))
    if definition.page_cache == "wp-rocket":
        outcomes.append(_purge_rocket_files(domain))
    outcomes.append(cache_operations._nginx(domain))
    outcomes.append(cache_operations._redis(domain))
    result = cache_operations.CacheResult(tuple(outcomes))
    # Report which layers actually cleared, not merely which were attempted:
    # after an incident the question is "was the cache purged", and a layer that
    # was skipped or errored must be visible without consulting anything else.
    if result.exit_code != 0:
        event_outcome = "error"
    elif all(outcome.status == "ok" for outcome in outcomes):
        event_outcome = "ok"
    else:
        event_outcome = "partial"
    record_event(
        "cache.purge",
        domain=domain,
        outcome=event_outcome,
        detail="layers=" + ",".join(f"{o.cache}:{o.status}" for o in outcomes),
    )
    return result

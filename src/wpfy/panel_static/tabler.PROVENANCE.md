# Vendored Tabler UI kit

- Upstream project: Tabler (`@tabler/core`)
- Upstream package version: `1.4.0`
- Licence: MIT (see `tabler.LICENSE`, fetched from https://raw.githubusercontent.com/tabler/tabler/main/LICENSE, SHA-256 `ef5d45031adce79eeaf17f04a966871137589f9b60d18e4520ade84b291dcd05`)
- Upstream repository: https://github.com/tabler/tabler

| vendored file | source URL | upstream SHA-256 | shipped bytes | shipped SHA-256 |
|---|---|---|---|---|
| `tabler.min.css` | https://cdn.jsdelivr.net/npm/@tabler/core@1.4.0/dist/css/tabler.min.css | `7ef750bd10546a695d0b12767ad8048bd8f3ec5de7daefb1067f9d0daa3d1c9a` | 536099 | `e2f5c542d00f15513e80d527655e82a2e12573799ea278a8b298206edb4b9ff3` |
| `tabler.min.js` | https://cdn.jsdelivr.net/npm/@tabler/core@1.4.0/dist/js/tabler.min.js | `b60c76160e97624574dbb8cf10abe6aee9a6493b60096fdfc15dd1dd2bd99eb9` | 83517 | `f5ca44ee5ffb40f2ad571b4f988e28ed760f4e4a5e4025231a76d741444ba6e1` |

## The only modification

The trailing `sourceMappingURL` comment was removed from each file. The `.map`
files are not vendored, so the reference only produced a 404 in devtools — and
under `default-src 'self'` the fetch would be blocked anyway. Nothing else was
touched; re-verify by fetching the source URL and stripping the same comment.

## Why this passes the panel CSP unchanged

The panel serves `default-src 'self'` and loads nothing from a third-party
origin (`CLAUDE.md`). Verified against the vendored bytes:

- `tabler.min.css` contains **zero `@font-face` rules** and **zero external
  `url()`** references — its only three `url()` values are inline `data:` URIs.
- `tabler.min.js` contains no `fetch`, `XMLHttpRequest`, `WebSocket`,
  `importScripts`, dynamic `import()`, `eval`, or `new Function`. It bundles
  Bootstrap 5.3.7 + Popper and manipulates the DOM only.

Both files are UTF-8 text, so `tests/gates/test_phase7c_gates.py::_all_assets`
(which reads every file in `panel_static/` as text) keeps working.

## Icons

Tabler Icons ships as ~11k individual SVG files with no prebuilt sprite, and a
webfont could not be served anyway (`_STATIC_TYPES` in `panel.py` allows only
`.html/.css/.js/.svg`). So no icon package is vendored. Instead the 18 outline
glyphs the shell actually uses are inlined as `<symbol>` elements in the sprite
at the top of `index.html`, copied verbatim from:

    https://cdn.jsdelivr.net/npm/@tabler/icons@3.36.0/icons/outline/<name>.svg

MIT, same project and licence text as above. Adding an icon means adding one
more `<symbol>` from that path — never a `<script>` or a remote reference.

## Layout

Files stay **flat** in `panel_static/`: `pyproject.toml` declares
`package-data = ["panel_static/*"]`, which is not recursive — a `vendor/`
subdirectory would work in a checkout and silently vanish from the built wheel.

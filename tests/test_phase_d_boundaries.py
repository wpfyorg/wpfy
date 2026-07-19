from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).parents[1] / "src" / "wpfy"


def _function_nodes(path: Path, names: set[str]) -> list[ast.FunctionDef]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name in names]


def test_phase_d_cli_and_panel_have_no_raw_runtime_commands():
    cli_path = ROOT / "cli.py"
    panel_path = ROOT / "panel.py"
    cli = cli_path.read_text(encoding="utf-8")
    targets = _function_nodes(cli_path, {
        "handle_stack_install", "handle_stack_status", "handle_stack_remove", "handle_stack_upgrade",
        "handle_stack_purge", "handle_clean", "handle_log_show", "handle_log_reset", "handle_site_wp",
    }) + _function_nodes(panel_path, {"api_site_logs", "api_site_wp"})
    assert len(targets) == 11
    for function in targets:
        names = {node.id for node in ast.walk(function) if isinstance(node, ast.Name)}
        strings = {
            node.value
            for node in ast.walk(function)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        }
        assert "subprocess" not in names
        assert "docker" not in strings
    assert "def _clear_nginx_cache" not in cli
    assert "def _pull_image" not in cli


def test_production_uses_public_probe_and_wait_names():
    production = "\n".join(path.read_text(encoding="utf-8") for path in ROOT.glob("*.py"))
    assert "_http_probe_site" not in production
    assert "_wait_for_service" not in production


def test_domain_modules_do_not_import_surfaces():
    for name in ("stack.py", "cache_operations.py", "site_runtime.py"):
        source = (ROOT / name).read_text(encoding="utf-8")
        assert "from .cli" not in source
        assert "from .panel" not in source

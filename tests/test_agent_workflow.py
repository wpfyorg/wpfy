from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from wpfy.agent_workflow import GateIntegrityError, GateManifest, StateTransitionError, TaskLock, Workflow, WorkflowConfig, _redact, build_provider_command, run_demo


def test_demo_completes(tmp_path: Path) -> None:
    task = run_demo(tmp_path)
    assert json.loads((task / "status.json").read_text(encoding="utf-8"))["status"] == "COMPLETED"


def test_provider_command_uses_role_sandbox_and_optional_model(tmp_path: Path) -> None:
    config = WorkflowConfig(work_dir=tmp_path, terra_model="configured")
    assert "workspace-write" in build_provider_command(config, "terra")
    assert "read-only" in build_provider_command(config, "sol")
    assert "configured" in build_provider_command(config, "terra")
    assert "--model" not in build_provider_command(config, "sol")


def test_transitions_are_checked(tmp_path: Path) -> None:
    workflow = Workflow(WorkflowConfig(work_dir=tmp_path), tmp_path)
    workflow.init("task", "request", isolate=False)
    with pytest.raises(StateTransitionError):
        workflow.transition("task", "COMPLETED", "sol")


def test_failed_validation_can_enter_sol_review(tmp_path: Path) -> None:
    workflow = Workflow(WorkflowConfig(work_dir=tmp_path), tmp_path)
    task = workflow.init("task", "request", isolate=False)
    state = workflow._state(task)
    state.update(status="CHANGES_REQUIRED", current_agent="system")
    workflow._write_state(task, state)

    workflow.transition("task", "REVIEWING", "sol")

    assert workflow._state(task)["status"] == "REVIEWING"


def test_sol_cannot_approve_failed_mechanical_validation(tmp_path: Path) -> None:
    workflow = Workflow(WorkflowConfig(work_dir=tmp_path), tmp_path)
    task = workflow.init("task", "request", isolate=False)
    workflow.plan("task", demo=True)
    workflow.investigate("task", demo=True)
    workflow.implement("task", demo=True)
    state = workflow._state(task)
    state.update(status="CHANGES_REQUIRED", current_agent="system")
    workflow._write_state(task, state)

    decision, correction = workflow.review("task", demo=True, allow_approval=False)

    assert decision == "CHANGES_REQUIRED"
    assert correction == "Resolve every failed validation command."
    assert workflow._state(task)["status"] == "CHANGES_REQUIRED"


def test_python_310_config_subset_and_agent_environment(tmp_path: Path) -> None:
    config_file = tmp_path / "workflow.toml"
    config_file.write_text('provider = "codex"\nvalidation_commands = ["python3 -m pytest -q"]\n', encoding="utf-8")
    config = WorkflowConfig.from_sources(config_file, {"AGENT_PROVIDER": "codex", "AGENT_MAX_TERRA_RETRIES": "4"})
    assert config.provider == "codex"
    assert config.max_terra_retries == 4
    assert config.max_luna_retries == 1
    assert config.max_review_loops == 3


def test_provider_uses_schema_and_last_message_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workflow = Workflow(WorkflowConfig(work_dir=tmp_path, max_review_loops=1), tmp_path)
    workflow.init("task", "request", isolate=False)
    worktree = tmp_path / "task" / "worktree"
    worktree.mkdir()
    manifest = worktree / ".agent-tests" / "sol-gates" / "manifest.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text('{"files": {}, "gate_command": "python3 -m pytest -q .agent-tests/sol-gates"}', encoding="utf-8")
    calls: list[list[str]] = []
    schemas: list[Path] = []

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        if len(calls) == 1:
            return subprocess.CompletedProcess(command, 1, "", "failed")
        schemas.append(Path(command[command.index("--output-schema") + 1]))
        output = Path(command[command.index("-o") + 1])
        output.write_text('{"brief":"ok","investigations":[],"gate_files":[]}', encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    workflow.plan("task")
    assert len(calls) == 2
    command = calls[-1]
    assert command[0:2] == ["codex", "exec"]
    assert schemas and not schemas[0].exists()
    assert "-C" in command and "-o" in command


def test_provider_paths_are_absolute_with_relative_work_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    workflow = Workflow(WorkflowConfig(work_dir=Path(".agent-work")), tmp_path)
    workflow.init("task", "request", isolate=False)
    worktree = tmp_path / ".agent-work" / "task" / "worktree"
    worktree.mkdir()
    static = worktree / ".agent-tests" / "sol-gates" / "manifest.json"
    static.parent.mkdir(parents=True)
    static.write_text('{"files": {}}', encoding="utf-8")

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert Path(command[command.index("-C") + 1]).is_absolute()
        assert Path(command[command.index("--output-schema") + 1]).is_absolute()
        output = Path(command[command.index("-o") + 1])
        assert output.is_absolute()
        output.write_text('{"brief":"ok","investigations":[],"gate_files":[]}', encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    workflow.plan("task")


def test_task_specific_skip_marker_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    workflow = Workflow(WorkflowConfig(work_dir=tmp_path / "tasks"), root)
    task = workflow.init("task", "request", isolate=False)
    workflow.plan("task", demo=True)
    gate = root / ".agent-tests" / "sol-gates" / "task" / "test_bad.py"
    gate.parent.mkdir(parents=True)
    gate.write_text("import pytest\npytest.skip('bad')\n", encoding="utf-8")
    GateManifest.capture(root, [gate], "python3 -m pytest -q .agent-tests/sol-gates").write(task / "gates.json")
    with pytest.raises(GateIntegrityError, match="skip"):
        workflow._verify_gates(task, demo=True)


def test_demo_state_inventories_phase_artifacts(tmp_path: Path) -> None:
    state = json.loads((run_demo(tmp_path) / "status.json").read_text(encoding="utf-8"))
    assert {"investigation_reports", "handoff", "validation_report", "validation_luna_report", "review_decision"} <= set(state["artifacts"])


def test_missing_worktree_blocks_before_provider(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workflow = Workflow(WorkflowConfig(work_dir=tmp_path), tmp_path)
    workflow.init("task", "request", isolate=False)
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: pytest.fail("provider or git invoked"))
    with pytest.raises(RuntimeError, match="worktree is missing"):
        workflow.plan("task")
    assert json.loads((tmp_path / "task" / "status.json").read_text(encoding="utf-8"))["status"] == "BLOCKED"


def test_run_reviews_failed_validation_before_returning(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workflow = Workflow(WorkflowConfig(work_dir=tmp_path), tmp_path)
    task = workflow.init("task", "request", isolate=False)
    monkeypatch.setattr(workflow, "init", lambda *args, **kwargs: task)
    monkeypatch.setattr(workflow, "plan", lambda *args, **kwargs: None)
    monkeypatch.setattr(workflow, "investigate", lambda *args, **kwargs: None)
    monkeypatch.setattr(workflow, "implement", lambda *args, **kwargs: None)
    monkeypatch.setattr(workflow, "validate", lambda *args, **kwargs: False)
    reviews: list[str] = []
    monkeypatch.setattr(workflow, "review", lambda *args, **kwargs: (reviews.append("sol") or ("BLOCKED", "")))
    workflow.run("request", "task")
    assert reviews == ["sol"]


def test_review_gets_full_request_and_brief(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "root"
    root.mkdir()
    workflow = Workflow(WorkflowConfig(work_dir=tmp_path / "tasks"), root)
    task = workflow.init("task", "x" * 6100 + " REQUEST-TAIL", isolate=False)
    (task / "worktree").mkdir()
    workflow.plan("task", demo=True)
    workflow.investigate("task", demo=True)
    workflow.implement("task", demo=True)
    workflow.validate("task", demo=True)
    static = task / "worktree" / ".agent-tests" / "sol-gates" / "manifest.json"
    static.parent.mkdir(parents=True)
    static.write_text('{"files": {}}', encoding="utf-8")
    (task / "sol-brief.md").write_text("# Sol brief\n\n" + "y" * 6100 + " BRIEF-TAIL\n", encoding="utf-8")
    prompts: list[str] = []

    def fake_provider(task_dir: Path, role: str, prompt: str, **kwargs: object) -> str:
        prompts.append(prompt)
        return '{"decision":"APPROVED","review":"ok","correction_brief":""}'

    monkeypatch.setattr(workflow, "_provider", fake_provider)
    workflow.review("task")
    assert "REQUEST-TAIL" in prompts[0] and "BRIEF-TAIL" in prompts[0]


def test_validation_is_shell_free_and_logs_argv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workflow = Workflow(WorkflowConfig(work_dir=tmp_path, validation_commands=("python3 -c pass",)), tmp_path)
    workflow.init("task", "request", isolate=False)
    worktree = tmp_path / "task" / "worktree"
    worktree.mkdir(parents=True)
    static_manifest = worktree / ".agent-tests" / "sol-gates" / "manifest.json"
    static_manifest.parent.mkdir(parents=True)
    static_manifest.write_text(
        '{"files": {}, "gate_command": "python3 -m pytest -q .agent-tests/sol-gates"}',
        encoding="utf-8",
    )
    workflow.plan("task", demo=True)
    workflow.investigate("task", demo=True)
    workflow.implement("task", demo=True)
    seen: list[object] = []

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        seen.append(kwargs.get("shell"))
        return subprocess.CompletedProcess(command, 0, "ok", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert workflow.validate("task")
    assert seen[:2] == [False, False]
    assert '"command": ["python3", "-c", "pass"]' in (tmp_path / "task" / "actions.jsonl").read_text(encoding="utf-8")


def test_gate_tampering_blocks_terra(tmp_path: Path) -> None:
    root = tmp_path / "root"
    (root / ".agent-tests" / "sol-gates").mkdir(parents=True)
    (root / "src" / "wpfy").mkdir(parents=True)
    (root / "src" / "wpfy" / "agent_workflow.py").write_text("x", encoding="utf-8")
    workflow = Workflow(WorkflowConfig(work_dir=tmp_path / "tasks"), root)
    workflow.init("task", "request", isolate=False)
    workflow.plan("task", demo=True)
    manifest = GateManifest.read(tmp_path / "tasks" / "task" / "gates.json")
    (root / "src" / "wpfy" / "agent_workflow.py").write_text("changed", encoding="utf-8")
    with pytest.raises(Exception):
        manifest.verify(root)


def test_gate_tampering_blocks_validation_before_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "root"
    protected = root / "src" / "wpfy" / "agent_workflow.py"
    protected.parent.mkdir(parents=True)
    protected.write_text("original", encoding="utf-8")
    workflow = Workflow(WorkflowConfig(work_dir=tmp_path / "tasks"), root)
    workflow.init("task", "request", isolate=False)
    workflow.plan("task", demo=True)
    workflow.investigate("task", demo=True)
    workflow.implement("task", demo=True)
    protected.write_text("tampered", encoding="utf-8")
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: pytest.fail("validation command executed"))

    with pytest.raises(Exception):
        workflow.validate("task", demo=True)

    assert json.loads((tmp_path / "tasks" / "task" / "status.json").read_text(encoding="utf-8"))["status"] == "BLOCKED"


def test_task_lock_is_used_by_phase(tmp_path: Path) -> None:
    workflow = Workflow(WorkflowConfig(work_dir=tmp_path), tmp_path)
    workflow.init("task", "request", isolate=False)
    with TaskLock(tmp_path / "task" / "task.lock"):
        with pytest.raises(RuntimeError, match="already locked"):
            workflow.plan("task", demo=True)


def test_dirty_intake_leaves_no_partial_task(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workflow = Workflow(WorkflowConfig(work_dir=tmp_path / "tasks"), tmp_path)
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, " M src/x\n", ""))
    with pytest.raises(RuntimeError, match="dirty"):
        workflow.init("task", "request")
    assert not (tmp_path / "tasks" / "task").exists()


def test_redaction_handles_bearer_and_named_secrets() -> None:
    assert "abc" not in _redact("Authorization: Bearer abc")
    assert "abc" not in _redact("token=abc password=abc")


def test_action_log_redacts_command_arguments(tmp_path: Path) -> None:
    workflow = Workflow(WorkflowConfig(work_dir=tmp_path), tmp_path)
    task = workflow.init("task", "request", isolate=False)
    workflow._log(task, "task", "system", "validate", "command", command=("password=supersecret",))
    assert "supersecret" not in (task / "actions.jsonl").read_text(encoding="utf-8")


def test_run_allows_only_configured_correction_cycles(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workflow = Workflow(WorkflowConfig(work_dir=tmp_path, max_review_loops=2), tmp_path)
    task = workflow.init("task", "request", isolate=False)
    monkeypatch.setattr(workflow, "init", lambda *args, **kwargs: task)
    monkeypatch.setattr(workflow, "plan", lambda *args, **kwargs: None)
    monkeypatch.setattr(workflow, "investigate", lambda *args, **kwargs: None)
    calls: list[str] = []
    monkeypatch.setattr(workflow, "implement", lambda *args, **kwargs: calls.append("implement"))
    monkeypatch.setattr(workflow, "validate", lambda *args, **kwargs: True)
    reviews = iter([("CHANGES_REQUIRED", "first"), ("CHANGES_REQUIRED", "second"), ("APPROVED", "")])
    monkeypatch.setattr(workflow, "review", lambda *args, **kwargs: next(reviews))
    monkeypatch.setattr(workflow, "complete", lambda *args, **kwargs: calls.append("complete"))
    workflow.run("request", "task")
    assert calls == ["implement", "implement", "implement", "complete"]

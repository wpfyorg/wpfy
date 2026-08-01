"""File-backed, provider-aware workflow kept separate from the product CLI."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any, Callable, Iterable, Iterator, Mapping, Sequence


STATUSES = (
    "RECEIVED", "PLANNING", "INVESTIGATING", "READY_FOR_IMPLEMENTATION", "IMPLEMENTING",
    "VALIDATING", "REVIEWING", "CHANGES_REQUIRED", "BLOCKED", "APPROVED", "COMPLETED",
)
_TRANSITIONS = {
    "RECEIVED": {"PLANNING", "BLOCKED"}, "PLANNING": {"INVESTIGATING", "BLOCKED"},
    "INVESTIGATING": {"READY_FOR_IMPLEMENTATION", "BLOCKED"},
    "READY_FOR_IMPLEMENTATION": {"IMPLEMENTING", "BLOCKED"},
    "IMPLEMENTING": {"VALIDATING", "BLOCKED"},
    "VALIDATING": {"REVIEWING", "CHANGES_REQUIRED", "BLOCKED"},
    "REVIEWING": {"APPROVED", "CHANGES_REQUIRED", "BLOCKED"},
    "CHANGES_REQUIRED": {"IMPLEMENTING", "VALIDATING", "REVIEWING", "CHANGES_REQUIRED", "BLOCKED"},
    "APPROVED": {"COMPLETED"},
    "BLOCKED": set(), "COMPLETED": set(),
}
_TASK_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_SECRET = re.compile(r"(?i)(token|secret|password|credential|api[_-]?key)\s*[:=]\s*\S+|bearer\s+\S+")
_HIGH_RISK = re.compile(r"(?i)\b(security|auth(?:entication|orization)?|database integrity|destructive|delete|drop)\b")
_LOG_LOCK = Lock()
_GATE_MARKER = re.compile(r"(?i)\b(?:skipif|pytest\.skip|pytest\.mark\.skip|xfail)\b")
_GATE_COMMAND = "python3 -m pytest -q .agent-tests/sol-gates"


class GateIntegrityError(RuntimeError):
    """A protected file changed after Sol created its manifest."""


class StateTransitionError(RuntimeError):
    """A state transition is not permitted."""


class StructuredOutputError(ValueError):
    """A provider output did not meet its JSON contract."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as handle:
        handle.write(text)
        temporary = Path(handle.name)
    os.replace(temporary, path)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _redact(value: str) -> str:
    def replacement(match: re.Match[str]) -> str:
        return (match.group(1) or "bearer") + "=<redacted>"
    return _SECRET.sub(replacement, value)[-2000:]


def _toml_subset(path: Path) -> dict[str, Any]:
    """Parse this project's flat JSON-compatible TOML subset on Python 3.10."""
    values: dict[str, Any] = {}
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, raw = line.partition("=")
        key, raw = key.strip(), raw.strip()
        if not separator or not re.fullmatch(r"[a-z_][a-z0-9_]*", key):
            raise ValueError(f"invalid config line {number}")
        try:
            values[key] = json.loads(raw)
        except json.JSONDecodeError as error:
            raise ValueError(f"config line {number} must use JSON-compatible TOML values") from error
    return values


@dataclass(frozen=True)
class WorkflowConfig:
    provider: str = "codex"
    provider_executable: str = "codex"
    sol_model: str = ""
    terra_model: str = ""
    luna_model: str = ""
    max_terra_retries: int = 2
    max_luna_retries: int = 1
    max_review_loops: int = 3
    work_dir: Path = Path(".agent-work")
    validation_commands: tuple[str, ...] = ("python3 -m pytest -q",)

    @classmethod
    def from_sources(cls, config_path: Path | None = None, env: Mapping[str, str] | None = None) -> "WorkflowConfig":
        values = _toml_subset(config_path) if config_path and config_path.is_file() else {}
        environment = os.environ if env is None else env
        aliases = {
            "provider": ("AGENT_PROVIDER", "WPFY_AGENT_PROVIDER", "PROVIDER"),
            "provider_executable": ("AGENT_PROVIDER_EXECUTABLE", "WPFY_AGENT_PROVIDER_EXECUTABLE", "PROVIDER_EXECUTABLE"),
            "sol_model": ("AGENT_SOL_MODEL", "WPFY_AGENT_SOL_MODEL", "SOL_MODEL"),
            "terra_model": ("AGENT_TERRA_MODEL", "WPFY_AGENT_TERRA_MODEL", "TERRA_MODEL"),
            "luna_model": ("AGENT_LUNA_MODEL", "WPFY_AGENT_LUNA_MODEL", "LUNA_MODEL"),
            "max_terra_retries": ("AGENT_MAX_TERRA_RETRIES", "WPFY_AGENT_MAX_TERRA_RETRIES", "MAX_TERRA_RETRIES"),
            "max_luna_retries": ("AGENT_MAX_LUNA_RETRIES", "WPFY_AGENT_MAX_LUNA_RETRIES", "MAX_LUNA_RETRIES"),
            "max_review_loops": ("AGENT_MAX_REVIEW_LOOPS", "WPFY_AGENT_MAX_REVIEW_LOOPS", "MAX_REVIEW_LOOPS"),
            "work_dir": ("AGENT_WORK_DIR", "WPFY_AGENT_WORK_DIR"),
        }
        for key, names in aliases.items():
            for name in names:
                if name in environment:
                    values[key] = environment[name]
                    break
        for key in ("max_terra_retries", "max_luna_retries", "max_review_loops"):
            if key in values:
                try:
                    values[key] = int(values[key])
                except (TypeError, ValueError) as error:
                    raise ValueError(f"{key} must be an integer") from error
                if values[key] < 0:
                    raise ValueError(f"{key} must not be negative")
        if "validation_commands" in values:
            commands = values["validation_commands"]
            if not isinstance(commands, list) or not all(isinstance(item, str) and item.strip() for item in commands):
                raise ValueError("validation_commands must be a non-empty list of strings")
            values["validation_commands"] = tuple(commands)
        if "work_dir" in values:
            values["work_dir"] = Path(str(values["work_dir"]))
        return cls(**{key: value for key, value in values.items() if key in cls.__dataclass_fields__})


@dataclass(frozen=True)
class GateManifest:
    files: dict[str, str]
    validation_command: str

    @classmethod
    def capture(cls, root: Path, paths: Iterable[Path], validation_command: str) -> "GateManifest":
        root, files = root.resolve(), {}
        for path in paths:
            resolved = path.resolve()
            try:
                relative = resolved.relative_to(root)
            except ValueError as error:
                raise ValueError("protected path must be inside root") from error
            if not resolved.is_file():
                raise FileNotFoundError(resolved)
            files[str(relative)] = _sha256(resolved)
        return cls(files, validation_command)

    def write(self, path: Path) -> None:
        _atomic_write(path, json.dumps({"files": self.files, "validation_command": self.validation_command}, sort_keys=True) + "\n")

    @classmethod
    def read(cls, path: Path) -> "GateManifest":
        value = json.loads(path.read_text(encoding="utf-8"))
        files = value.get("files", value.get("hashes"))
        if not isinstance(files, dict) or not all(isinstance(name, str) and isinstance(digest, str) for name, digest in files.items()):
            raise GateIntegrityError("invalid gate manifest")
        return cls(files, str(value.get("validation_command", value.get("gate_command", ""))))

    def verify(self, root: Path) -> None:
        root = root.resolve()
        for relative, expected in self.files.items():
            path = (root / relative).resolve()
            if root not in path.parents or not path.is_file() or _sha256(path) != expected:
                raise GateIntegrityError(f"protected file changed: {relative}")


class TaskLock:
    def __init__(self, path: Path) -> None:
        self.path, self._held = path, False

    def __enter__(self) -> "TaskLock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError as error:
            raise RuntimeError(f"task is already locked: {self.path}") from error
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(str(os.getpid()))
        self._held = True
        return self

    def __exit__(self, *_: object) -> None:
        if self._held:
            self.path.unlink(missing_ok=True)
            self._held = False


def build_provider_command(
    config: WorkflowConfig, role: str, *, worktree: Path | None = None,
    schema_path: Path | None = None, output_path: Path | None = None,
) -> list[str]:
    if config.provider != "codex":
        raise ValueError(f"unsupported provider: {config.provider}")
    model = {"sol": config.sol_model, "terra": config.terra_model, "luna": config.luna_model}.get(role)
    if model is None:
        raise ValueError(f"unknown role: {role}")
    command = [config.provider_executable, "exec", "--ephemeral", "--sandbox", "workspace-write" if role == "terra" else "read-only"]
    if model:
        command.extend(["--model", model])
    if worktree is not None:
        command.extend(["-C", str(worktree)])
    if schema_path is not None:
        command.extend(["--output-schema", str(schema_path)])
    if output_path is not None:
        command.extend(["-o", str(output_path)])
    return command


def parse_structured_output(text: str, required: Iterable[str]) -> dict[str, Any]:
    try:
        value = json.loads(text)
    except json.JSONDecodeError as error:
        raise StructuredOutputError("provider returned invalid JSON") from error
    if not isinstance(value, dict) or any(not isinstance(value.get(key), str) for key in required):
        raise StructuredOutputError("provider response does not match required schema")
    return value


def _safe_task_id(task_id: str) -> str:
    if not _TASK_ID.fullmatch(task_id):
        raise ValueError("task id must be lowercase letters, digits, and hyphens")
    return task_id


def _safe_gate_name(task_id: str, value: str) -> Path:
    path = Path(value)
    if path.is_absolute() or ".." in path.parts or path.name != value or not re.fullmatch(r"test_[a-zA-Z0-9_]+\.py", path.name):
        raise StructuredOutputError("gate file names must be simple test_*.py names")
    return Path(".agent-tests") / "sol-gates" / task_id / path.name


@dataclass
class Workflow:
    config: WorkflowConfig
    repository: Path = field(default_factory=Path.cwd)

    def task_dir(self, task_id: str) -> Path:
        return self.config.work_dir / _safe_task_id(task_id)

    def _task_root(self, task_dir: Path, *, allow_primary: bool = False) -> Path:
        worktree = task_dir / "worktree"
        if worktree.is_dir():
            return worktree
        if allow_primary:
            return self.repository
        raise RuntimeError("task worktree is missing; refusing to use the primary repository")

    def _phase_root(self, task_dir: Path, *, demo: bool = False) -> Path:
        try:
            return self._task_root(task_dir, allow_primary=demo)
        except RuntimeError as error:
            state = self._state(task_dir)
            if state["status"] != "BLOCKED" and "BLOCKED" in _TRANSITIONS[state["status"]]:
                self._transition(task_dir, "BLOCKED", "sol", reason=str(error))
            raise

    @contextmanager
    def _locked(self, task_id: str) -> Iterator[Path]:
        task_dir = self.task_dir(task_id)
        with TaskLock(task_dir / "task.lock"):
            yield task_dir

    def _state(self, task_dir: Path) -> dict[str, Any]:
        return json.loads((task_dir / "status.json").read_text(encoding="utf-8"))

    def _write_state(self, task_dir: Path, state: Mapping[str, Any]) -> None:
        required = {"task_id", "status", "current_agent", "attempt", "created_at", "updated_at", "blocking_reason", "artifacts"}
        if not required.issubset(state) or state["status"] not in STATUSES:
            raise StateTransitionError("invalid state")
        _atomic_write(task_dir / "status.json", json.dumps(dict(state), sort_keys=True) + "\n")

    def _transition(self, task_dir: Path, status: str, agent: str, *, reason: str | None = None) -> None:
        state = self._state(task_dir)
        if status not in _TRANSITIONS[state["status"]]:
            raise StateTransitionError(f"cannot transition {state['status']} to {status}")
        state.update(status=status, current_agent=agent, updated_at=_utc_now(), blocking_reason=reason)
        state["attempt"] += 1
        self._write_state(task_dir, state)
        self._log(task_dir, state["task_id"], agent, status.lower(), "transition", result=status)

    def transition(self, task_id: str, status: str, agent: str) -> None:
        with self._locked(task_id) as task_dir:
            self._transition(task_dir, status, agent)

    def _log(self, task_dir: Path, task_id: str, agent: str, phase: str, action: str, *, command: Sequence[str] | None = None, result: str = "ok", duration: float = 0.0, files_affected: Sequence[str] = (), error: str = "") -> None:
        record = {"timestamp": _utc_now(), "task_id": task_id, "agent": agent, "phase": phase, "action": action,
                  "command": [_redact(part) for part in command or ()], "result": result, "duration": round(duration, 3),
                  "files_affected": list(files_affected), "error": _redact(error)}
        with _LOG_LOCK:
            with (task_dir / "actions.jsonl").open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, sort_keys=True) + "\n")

    def _preflight(self) -> None:
        status = subprocess.run(["git", "status", "--porcelain"], cwd=self.repository, text=True, capture_output=True, check=True)
        if status.stdout.strip():
            raise RuntimeError("refusing workflow intake from a dirty repository")

    def init(self, task_id: str, request: str, *, isolate: bool = True) -> Path:
        task_id, task_dir = _safe_task_id(task_id), self.task_dir(task_id)
        if task_dir.exists():
            raise FileExistsError(task_dir)
        if isolate:
            self._preflight()  # Must precede task-dir creation.
        task_dir.mkdir(parents=True)
        with TaskLock(task_dir / "task.lock"):
            now = _utc_now()
            state = {"task_id": task_id, "status": "RECEIVED", "current_agent": "system", "attempt": 0,
                     "created_at": now, "updated_at": now, "blocking_reason": None, "artifacts": {"request": "request.md"}}
            self._write_state(task_dir, state)
            _atomic_write(task_dir / "request.md", request.strip() + "\n")
            self._log(task_dir, task_id, "system", "intake", "init", files_affected=("request.md", "status.json"))
            if isolate:
                worktree = task_dir / "worktree"
                command = ["git", "worktree", "add", "-b", f"codex/agent-{task_id}", str(worktree), "HEAD"]
                subprocess.run(command, cwd=self.repository, check=True)
                base = subprocess.run(["git", "rev-parse", "HEAD"], cwd=worktree, text=True, capture_output=True, check=True).stdout.strip()
                state = self._state(task_dir)
                state["artifacts"]["base_commit"] = base
                self._write_state(task_dir, state)
                self._log(task_dir, task_id, "system", "intake", "worktree_created", command=command, files_affected=("worktree",))
        return task_dir

    def _schema(self, role: str) -> dict[str, Any]:
        if role == "sol-plan":
            return {"type": "object", "additionalProperties": False, "required": ["brief", "investigations", "gate_files"], "properties": {
                "brief": {"type": "string"}, "investigations": {"type": "array", "items": {"type": "string"}},
                "gate_files": {"type": "array", "items": {"type": "object", "additionalProperties": False, "required": ["name", "content"], "properties": {"name": {"type": "string"}, "content": {"type": "string"}}}},
            }}
        if role == "sol-review":
            return {"type": "object", "additionalProperties": False, "required": ["decision", "review", "correction_brief"], "properties": {
                "decision": {"type": "string", "enum": ["APPROVED", "CHANGES_REQUIRED", "BLOCKED"]}, "review": {"type": "string"}, "correction_brief": {"type": "string"},
            }}
        return {"type": "object", "additionalProperties": False, "required": ["report"], "properties": {"report": {"type": "string"}}}

    def _provider(self, task_dir: Path, role: str, prompt: str, *, structured: str | None = None, retries: int = 0) -> str:
        task_dir = task_dir.resolve()
        root, task_id = self._task_root(task_dir).resolve(), self._state(task_dir)["task_id"]
        provider_dir = (task_dir / "provider").resolve()
        provider_dir.mkdir(exist_ok=True)
        for attempt in range(retries + 1):
            schema_kind = structured or "report"
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=provider_dir, suffix=".json", delete=False) as schema_file:
                schema_path = Path(schema_file.name).resolve()
                json.dump(self._schema(schema_kind), schema_file)
            output_path = (provider_dir / f"{role}-{attempt}.last-message").resolve()
            command = build_provider_command(self.config, role, worktree=root, schema_path=schema_path, output_path=output_path)
            started = datetime.now().timestamp()
            result = subprocess.run(command, input=prompt, text=True, cwd=root, capture_output=True)
            duration = datetime.now().timestamp() - started
            self._log(task_dir, task_id, role, role, "provider", command=command, result=str(result.returncode), duration=duration, files_affected=(str(output_path.relative_to(task_dir)),), error=result.stderr)
            try:
                if result.returncode == 0 and output_path.is_file():
                    output = output_path.read_text(encoding="utf-8")
                    if structured:
                        return output
                    return parse_structured_output(output, ("report",))["report"]
            finally:
                schema_path.unlink(missing_ok=True)
                output_path.unlink(missing_ok=True)
            prompt += "\nRetry: report uncertainties and use the required contract."
        raise RuntimeError(f"{role} provider failed after {retries + 1} attempts")

    def _manifest_paths(self, root: Path, task_id: str) -> list[Path]:
        names = ["src/wpfy/agent_workflow.py", ".agent-workflow.toml", ".agent-workflow.example.toml", "pyproject.toml", "tests/conftest.py", "tests/test_agent_workflow.py", ".agent-tests/sol-gates/manifest.json", ".agent-tests/sol-gates/test_agent_workflow_gates.py"]
        paths = [root / name for name in names if (root / name).is_file()]
        static = root / ".agent-tests" / "sol-gates" / "manifest.json"
        if static.is_file():
            paths.extend(root / path for path in GateManifest.read(static).files if (root / path).is_file())
        gate_dir = root / ".agent-tests" / "sol-gates" / task_id
        return paths + [path for path in gate_dir.rglob("*") if path.is_file()]

    def _verify_static_manifest(self, root: Path) -> None:
        static = root / ".agent-tests" / "sol-gates" / "manifest.json"
        if not static.is_file():
            raise GateIntegrityError("missing static Sol gate manifest")
        static_manifest = GateManifest.read(static)
        static_manifest.verify(root)
        for relative in static_manifest.files:
            source = root / relative
            if source.suffix in {".py", ".sh"} and _GATE_MARKER.search(source.read_text(encoding="utf-8")):
                raise GateIntegrityError(f"forbidden skip/xfail marker in {relative}")

    def _verify_gates(self, task_dir: Path, *, demo: bool = False) -> None:
        root = self._phase_root(task_dir, demo=demo)
        try:
            if not demo:
                self._verify_static_manifest(root)
            task_manifest = GateManifest.read(task_dir / "gates.json")
            task_manifest.verify(root)
            for relative in task_manifest.files:
                source = root / relative
                if ".agent-tests/sol-gates" in source.as_posix() and source.suffix in {".py", ".sh"}:
                    if _GATE_MARKER.search(source.read_text(encoding="utf-8")):
                        raise GateIntegrityError(f"forbidden skip/xfail marker in {relative}")
        except GateIntegrityError as error:
            state = self._state(task_dir)
            failures = int(state["artifacts"].get("gate_integrity_failures", 0)) + 1
            state["artifacts"]["gate_integrity_failures"] = failures
            self._write_state(task_dir, state)
            if failures >= 2:
                self._log(task_dir, state["task_id"], "sol", "gates", "critical_gate_escalation", result="escalated", error=str(error))
            if state["status"] != "BLOCKED" and "BLOCKED" in _TRANSITIONS[state["status"]]:
                self._transition(task_dir, "BLOCKED", "sol", reason=str(error))
            raise

    @staticmethod
    def _read(path: Path, limit: int | None = 6000) -> str:
        text = path.read_text(encoding="utf-8") if path.is_file() else "(missing)"
        if limit is None:
            return text
        return text[:limit] + ("\n[truncated]" if len(text) > limit else "")

    def _git_evidence(self, task_dir: Path, *, demo: bool = False) -> str:
        root = self._phase_root(task_dir, demo=demo)
        status = subprocess.run(["git", "status", "--short"], cwd=root, text=True, capture_output=True)
        stat = subprocess.run(["git", "diff", "--stat"], cwd=root, text=True, capture_output=True)
        base = self._state(task_dir)["artifacts"].get("base_commit", "HEAD")
        commits = subprocess.run(["git", "log", f"{base}..HEAD", "--oneline"], cwd=root, text=True, capture_output=True)
        return "git status --short:\n" + _redact(status.stdout) + "\n\ngit diff --stat:\n" + _redact(stat.stdout) + "\n\ngit log " + base + "..HEAD:\n" + _redact(commits.stdout)

    def plan(self, task_id: str, *, demo: bool = False) -> None:
        with self._locked(task_id) as task_dir:
            self._transition(task_dir, "PLANNING", "sol")
            if demo:
                data = {"brief": "Plan approved for deterministic demonstration.", "investigations": ["repository", "tests"], "gate_files": []}
            else:
                request = (task_dir / "request.md").read_text(encoding="utf-8")
                risk = " Flag security/auth/database/destructive concerns explicitly." if _HIGH_RISK.search(request) else ""
                self._verify_static_manifest(self._phase_root(task_dir))
                data = json.loads(self._provider(
                    task_dir, "sol", "Original request:\n" + request + "\n\nReturn only JSON with brief, investigations, and gate_files. "
                    "brief must state scope, risks, validation, and an implementation path. investigations must be read-only assignments. "
                    "gate_files must contain only name/content for critical gates. "
                    "Luna reports must contain Assignment, Files inspected, Commands, Findings, Evidence, Risks, Uncertainties, and Recommended next step." + risk,
                    structured="sol-plan", retries=self.config.max_review_loops,
                ))
            if not isinstance(data, dict) or not isinstance(data.get("brief"), str) or not isinstance(data.get("investigations"), list) or not all(isinstance(item, str) for item in data["investigations"]) or not isinstance(data.get("gate_files"), list):
                raise StructuredOutputError("invalid Sol plan")
            root, created = self._phase_root(task_dir, demo=demo), []
            for gate in data["gate_files"]:
                if not isinstance(gate, dict) or not isinstance(gate.get("name"), str) or not isinstance(gate.get("content"), str):
                    raise StructuredOutputError("invalid Sol gate file")
                relative = _safe_gate_name(task_id, gate["name"])
                _atomic_write(root / relative, gate["content"])
                created.append(str(relative))
            _atomic_write(task_dir / "sol-brief.md", "# Sol brief\n\n" + data["brief"] + "\n")
            _atomic_write(task_dir / "plan.json", json.dumps(data, sort_keys=True) + "\n")
            GateManifest.capture(root, self._manifest_paths(root, task_id), _GATE_COMMAND).write(task_dir / "gates.json")
            state = self._state(task_dir); state["artifacts"].update(plan="plan.json", gates="gates.json", sol_brief="sol-brief.md"); self._write_state(task_dir, state)
            self._log(task_dir, task_id, "sol", "plan", "gates_captured", files_affected=tuple(created))

    def investigate(self, task_id: str, topics: Sequence[str] | None = None, *, demo: bool = False) -> None:
        with self._locked(task_id) as task_dir:
            self._transition(task_dir, "INVESTIGATING", "luna")
            self._phase_root(task_dir, demo=demo)
            if topics is None:
                topics = tuple(json.loads((task_dir / "plan.json").read_text(encoding="utf-8"))["investigations"])
            topics = topics or ("repository",)
            def one(pair: tuple[int, str]) -> None:
                number, topic = pair
                if demo:
                    report = f"Assignment: {topic}\nFiles inspected: none\nCommands: none\nFindings: complete\nEvidence: demo\nRisks: none\nUncertainties: none\nRecommended next step: implement\n"
                else:
                    report = self._provider(
                        task_dir, "luna", "Original request:\n" + self._read(task_dir / "request.md") + "\n\nSol brief:\n" + self._read(task_dir / "sol-brief.md")
                        + "\n\nAssignment: " + topic + ". Return report JSON whose report includes Assignment, Files inspected, Commands, Findings, Evidence, Risks, Uncertainties, and Recommended next step.",
                        retries=self.config.max_luna_retries,
                    )
                _atomic_write(task_dir / "investigation" / f"{number:02d}.md", report)
            with ThreadPoolExecutor(max_workers=len(topics)) as executor:
                list(executor.map(one, enumerate(topics, 1)))
            state = self._state(task_dir)
            state["artifacts"]["investigation_reports"] = [str(path.relative_to(task_dir)) for path in sorted((task_dir / "investigation").glob("*.md"))]
            self._write_state(task_dir, state)
            self._transition(task_dir, "READY_FOR_IMPLEMENTATION", "sol")

    def implement(self, task_id: str, *, demo: bool = False, correction: str = "") -> None:
        with self._locked(task_id) as task_dir:
            self._transition(task_dir, "IMPLEMENTING", "terra")
            try:
                self._phase_root(task_dir, demo=demo)
                self._verify_gates(task_dir, demo=demo)
                reports = "\n\n".join(self._read(path) for path in sorted((task_dir / "investigation").glob("*.md")))
                gates = GateManifest.read(task_dir / "gates.json")
                handoff = "No repository changes in deterministic demonstration." if demo else self._provider(
                    task_dir, "terra", "Original request:\n" + self._read(task_dir / "request.md") + "\n\nSol brief:\n" + self._read(task_dir / "sol-brief.md")
                    + "\n\nLuna reports:\n" + reports + "\n\nProject instructions: inspect AGENTS.md and CLAUDE.md. "
                    "Protected files (do not modify):\n" + "\n".join(sorted(gates.files)) + "\nAllowed scope: implement only the approved request in this isolated worktree. "
                    "Gate command: " + gates.validation_command + "\nValidation commands: " + " | ".join(self.config.validation_commands)
                    + "\nNever commit, amend, rebase, merge, reset, clean, or push.\nCorrection brief: " + correction + "\nReturn JSON report with a Terra handoff including changed files, tests, risks, and unresolved issues.",
                    retries=self.config.max_terra_retries,
                )
                self._verify_gates(task_dir, demo=demo)
            except GateIntegrityError as error:
                self._transition(task_dir, "BLOCKED", "sol", reason=str(error))
                raise
            _atomic_write(task_dir / "implementation" / "handoff.md", "# Terra handoff\n\n" + handoff + "\n")
            state = self._state(task_dir); state["artifacts"]["handoff"] = "implementation/handoff.md"; self._write_state(task_dir, state)
            self._log(task_dir, task_id, "terra", "implement", "handoff_written", files_affected=("implementation/handoff.md",))

    def validate(self, task_id: str, *, demo: bool = False) -> bool:
        with self._locked(task_id) as task_dir:
            self._transition(task_dir, "VALIDATING", "system")
            self._phase_root(task_dir, demo=demo)
            self._verify_gates(task_dir, demo=demo)
            reports: list[dict[str, Any]] = []
            gates = GateManifest.read(task_dir / "gates.json")
            if not demo and gates.validation_command != _GATE_COMMAND:
                raise GateIntegrityError("task gate command was modified")
            commands = ("demo",) if demo else (gates.validation_command,) + self.config.validation_commands
            for command in commands:
                argv = ["demo"] if demo else shlex.split(command)
                if not argv or any(part in {"|", "&&", ";", ">", "<"} for part in argv):
                    raise ValueError("validation command is empty or unsafe")
                started = datetime.now().timestamp()
                result = None if demo else subprocess.run(argv, cwd=self._task_root(task_dir), text=True, capture_output=True, shell=False)
                duration = datetime.now().timestamp() - started
                code, output = (0, "deterministic validation passed") if demo else (result.returncode, _redact(result.stdout + result.stderr))
                reports.append({"argv": argv, "exit_code": code, "duration_seconds": round(duration, 3), "output": output})
                self._log(task_dir, task_id, "system", "validate", "command", command=argv, result=str(code), duration=duration, error=output)
            _atomic_write(task_dir / "validation" / "report.md", "# Validation report\n\n" + json.dumps(reports, indent=2) + "\n")
            validation_context = "Original request:\n" + self._read(task_dir / "request.md") + "\n\nSol brief:\n" + self._read(task_dir / "sol-brief.md")
            validation_context += "\n\nActual git evidence:\n" + self._git_evidence(task_dir, demo=demo)
            validation_context += "\n\nMechanical command report:\n" + self._read(task_dir / "validation" / "report.md")
            validation_context += "\n\nReturn report JSON covering repo status/diff; tests/gates/lint/type/build/format applicability; generated/migrations/links/deps; secrets/debug/skips/deletions/scope; and exact commands/exits."
            try:
                luna_report = (
                    "Repo status/diff: demo\nTests/gates/lint/type/build/format applicability: demo\nGenerated/migrations/links/deps: none\nSecrets/debug/skips/deletions/scope: none\nExact commands/exits: demo 0\n"
                    if demo else self._provider(task_dir, "luna", validation_context, retries=self.config.max_luna_retries)
                )
            except (OSError, RuntimeError, StructuredOutputError, ValueError) as error:
                luna_report = "Luna validation unavailable after retries: " + _redact(str(error)) + "\n"
            _atomic_write(task_dir / "validation" / "luna-report.md", luna_report)
            state = self._state(task_dir)
            state["artifacts"].update(validation_report="validation/report.md", validation_luna_report="validation/luna-report.md")
            self._write_state(task_dir, state)
            passed = all(report["exit_code"] == 0 for report in reports)
            if not passed:
                self._transition(task_dir, "CHANGES_REQUIRED", "system", reason="objective validation failed")
            return passed

    def review(self, task_id: str, *, demo: bool = False, allow_approval: bool = True) -> tuple[str, str]:
        with self._locked(task_id) as task_dir:
            self._phase_root(task_dir, demo=demo)
            self._verify_gates(task_dir, demo=demo)
            self._transition(task_dir, "REVIEWING", "sol")
            context = "Original request:\n" + self._read(task_dir / "request.md", limit=None) + "\n\nSol brief:\n" + self._read(task_dir / "sol-brief.md", limit=None)
            context += "\n\nLuna reports:\n" + "\n\n".join(self._read(path) for path in sorted((task_dir / "investigation").glob("*.md")))
            context += "\n\nTerra handoff:\n" + self._read(task_dir / "implementation" / "handoff.md")
            context += "\n\nValidation report:\n" + self._read(task_dir / "validation" / "report.md")
            context += "\n\nLuna validation report:\n" + self._read(task_dir / "validation" / "luna-report.md")
            context += "\n\nCorrection history:\n" + self._read(task_dir / "review" / "correction-brief.md")
            context += "\n\nActual worktree evidence:\n" + self._git_evidence(task_dir, demo=demo)
            context += "\n\nInspect the actual worktree diff. Include git status --short and git diff --stat evidence or changed paths. Return JSON decision, review, correction_brief."
            data = {"decision": "APPROVED", "review": "Demo approved.", "correction_brief": ""} if demo else json.loads(self._provider(task_dir, "sol", context, structured="sol-review", retries=self.config.max_review_loops))
            if not isinstance(data, dict) or data.get("decision") not in {"APPROVED", "CHANGES_REQUIRED", "BLOCKED"} or not all(isinstance(data.get(key), str) for key in ("review", "correction_brief")):
                raise StructuredOutputError("invalid Sol review")
            if data["decision"] == "APPROVED" and not allow_approval:
                data["decision"] = "CHANGES_REQUIRED"
                data["review"] += "\nApproval withheld because mechanical validation failed."
                data["correction_brief"] = data["correction_brief"] or "Resolve every failed validation command."
            _atomic_write(task_dir / "review" / "decision.md", data["decision"] + "\n\n" + data["review"] + "\n")
            _atomic_write(task_dir / "review" / "correction-brief.md", data["correction_brief"] + "\n")
            state = self._state(task_dir); state["artifacts"].update(review_decision="review/decision.md", correction_brief="review/correction-brief.md"); self._write_state(task_dir, state)
            self._transition(task_dir, data["decision"], "sol", reason=data["review"] if data["decision"] == "BLOCKED" else None)
            return data["decision"], data["correction_brief"]

    def complete(self, task_id: str) -> None:
        with self._locked(task_id) as task_dir:
            self._transition(task_dir, "COMPLETED", "sol")

    def run(self, request: str, task_id: str | None = None) -> Path:
        generated = "task-" + hashlib.sha256(request.encode("utf-8")).hexdigest()[:12]
        task_id = task_id or generated
        task_dir = self.init(task_id, request)
        self.plan(task_id); self.investigate(task_id); self.implement(task_id)
        validation_passed = self.validate(task_id)
        decision, correction = self.review(task_id, allow_approval=validation_passed)
        if decision == "APPROVED":
            self.complete(task_id); return task_dir
        if decision == "BLOCKED":
            return task_dir
        for _ in range(self.config.max_review_loops):
            self.implement(task_id, correction=correction)
            validation_passed = self.validate(task_id)
            decision, correction = self.review(task_id, allow_approval=validation_passed)
            if decision == "APPROVED":
                self.complete(task_id); return task_dir
            if decision == "BLOCKED":
                return task_dir
        self.transition(task_id, "BLOCKED", "sol")
        return task_dir


def run_demo(work_dir: Path) -> Path:
    workflow, task_id = Workflow(WorkflowConfig(work_dir=work_dir), work_dir), "demo"
    workflow.init(task_id, "Deterministic workflow demonstration", isolate=False)
    workflow.plan(task_id, demo=True); workflow.investigate(task_id, demo=True); workflow.implement(task_id, demo=True)
    if not workflow.validate(task_id, demo=True):
        raise RuntimeError("demo validation failed")
    decision, _ = workflow.review(task_id, demo=True)
    if decision != "APPROVED":
        raise RuntimeError("demo review was not approved")
    workflow.complete(task_id)
    return workflow.task_dir(task_id)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="wpfy-agent")
    parser.add_argument("--config", type=Path, default=Path(".agent-workflow.toml"))
    subparsers = parser.add_subparsers(dest="command", required=True)
    init = subparsers.add_parser("init"); init.add_argument("task_id"); init.add_argument("request")
    for name in ("plan", "investigate", "implement", "validate", "review", "status", "verify-gates"):
        subparsers.add_parser(name).add_argument("task_id")
    run = subparsers.add_parser("run"); run.add_argument("request"); run.add_argument("--task-id")
    demo = subparsers.add_parser("demo"); demo.add_argument("--work-dir", type=Path, default=Path(".agent-work"))
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "demo":
            print(run_demo(args.work_dir)); return 0
        workflow = Workflow(WorkflowConfig.from_sources(args.config), Path.cwd())
        if args.command == "init": workflow.init(args.task_id, args.request)
        elif args.command == "plan": workflow.plan(args.task_id)
        elif args.command == "investigate": workflow.investigate(args.task_id)
        elif args.command == "implement": workflow.implement(args.task_id)
        elif args.command == "validate": return 0 if workflow.validate(args.task_id) else 1
        elif args.command == "review": workflow.review(args.task_id)
        elif args.command == "status": print((workflow.task_dir(args.task_id) / "status.json").read_text(encoding="utf-8"), end="")
        elif args.command == "verify-gates": workflow._verify_gates(workflow.task_dir(args.task_id))
        elif args.command == "run":
            task_dir = workflow.run(args.request, args.task_id)
            state = workflow._state(task_dir)
            print(json.dumps({"task_id": state["task_id"], "task_dir": str(task_dir), "status": state["status"]}, sort_keys=True))
            return 0 if state["status"] == "COMPLETED" else 1
        return 0
    except (GateIntegrityError, OSError, RuntimeError, StateTransitionError, StructuredOutputError, ValueError, subprocess.SubprocessError) as error:
        print(f"wpfy-agent: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

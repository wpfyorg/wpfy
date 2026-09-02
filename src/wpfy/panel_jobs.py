"""Panel background job orchestration."""
from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from .events import _redact


@dataclass
class Job:
    """Background job."""
    id: str
    action: str
    domain: str | None
    state: str = "running"
    steps: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    result: dict | None = None
    one_time: dict | None = None


_JOBS: dict[str, Job] = {}
_LOCK = threading.RLock()


def create_job(action: str, domain: str | None = None) -> Job:
    """Create job."""
    job = Job(id=uuid.uuid4().hex, action=action, domain=domain)
    with _LOCK:
        _JOBS[job.id] = job
    return job


def complete_job(job_id: str, *, result: dict | None = None, one_time: dict | None = None) -> None:
    """Complete job."""
    with _LOCK:
        job = _JOBS[job_id]
        job.result = result
        job.one_time = one_time
        job.state = "succeeded"


def fail_job(job_id: str, message: str) -> None:
    """Fail job."""
    with _LOCK:
        job = _JOBS[job_id]
        job.result = {"error": message}
        job.one_time = None
        job.state = "failed"


def append_step(job_id: str, step: str) -> None:
    """Append step."""
    with _LOCK:
        job = _JOBS.get(job_id)
        if job is not None:
            job.steps.append(str(step))


def get_job(job_id: str) -> Job | None:
    """Get job."""
    with _LOCK:
        return _JOBS.get(job_id)


def consume_job(job_id: str) -> tuple[Job | None, dict | None]:
    """Consume job."""
    with _LOCK:
        job = _JOBS.get(job_id)
        if job is None:
            return None, None
        one_time = job.one_time
        job.one_time = None
        return job, one_time


def list_jobs() -> list[Job]:
    """List jobs."""
    with _LOCK:
        return sorted(_JOBS.values(), key=lambda job: job.created_at, reverse=True)


def run_job(fn: Callable[[], dict | None], *, action: str, domain: str | None = None) -> Job:
    """Run job."""
    job = create_job(action, domain)

    def runner() -> None:
        """Runner."""
        try:
            value = fn()
            if isinstance(value, tuple) and len(value) == 2:
                result, one_time = value
            else:
                result, one_time = value, None
            complete_job(job.id, result=result or {}, one_time=one_time)
        except Exception as exc:  # job boundary: callers inspect failure through the job
            fail_job(job.id, _redact(str(exc)))

    threading.Thread(target=runner, name=f"wpfy-panel-{job.id[:8]}", daemon=True).start()
    return job

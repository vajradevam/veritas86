"""
base.py — the Injector backend interface (IMPLEMENTATION_PLAN.md §2).

Every backend (Ring3Injector now; QemuInjector/KvmInjector/BaremetalInjector/
SimInjector later) implements this so corpus/orchestrator code is written
once against the abstraction, not against any one backend's quirks.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterable, Iterator

from ..proto import Job, Result


class Injector(ABC):
    @abstractmethod
    def submit(self, job: Job) -> Result:
        """Run one job, return its result. Blocking."""

    def submit_batch(self, jobs: Iterable[Job]) -> Iterator[Result]:
        """Default: sequential submit(). Backends that can pipeline
        (e.g. Ring3Injector over its pipe) should override this."""
        for job in jobs:
            yield self.submit(job)

    @abstractmethod
    def identity(self) -> dict:
        """Static facts about what's being probed: cpu model, microcode
        revision, backend kind, etc. -- goes into the fingerprint record's
        identity block (docs: fingerprint-schema.md, not yet written)."""

    @abstractmethod
    def close(self) -> None:
        """Release any subprocess/VM/connection this backend holds."""

    def __enter__(self) -> "Injector":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

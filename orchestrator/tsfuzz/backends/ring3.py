"""
ring3.py — drives core/injector/injector as a subprocess.

Speaks the wire protocol documented in docs/injector-protocol.md: read the
bx862_hello handshake once at startup, then one bx862_job write / one
bx862_result read per submit() (pipelined in submit_batch()).
"""
from __future__ import annotations

import platform
import subprocess
from pathlib import Path
from typing import BinaryIO, Iterable, Iterator

from ..proto import HELLO_SIZE, JOB_SIZE, RESULT_SIZE, Hello, Job, Result
from .base import Injector

_DEFAULT_BINARY = Path(__file__).resolve().parents[3] / "core" / "injector" / "injector"


def _read_exact(f: BinaryIO, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = f.read(n - len(buf))
        if not chunk:
            raise EOFError(f"injector closed stdout after {len(buf)}/{n} bytes")
        buf += chunk
    return bytes(buf)


class Ring3Injector(Injector):
    """Ring-3 backend. One subprocess per instance -- per
    docs/injector-protocol.md, the daemon is single-threaded and its
    trampoline state is not safe to share, so parallelism means multiple
    Ring3Injector instances (and the caller pinning each to a distinct
    core), not multiple threads against one instance."""

    def __init__(self, binary: str | Path = _DEFAULT_BINARY):
        self._binary = Path(binary)
        if not self._binary.exists():
            raise FileNotFoundError(
                f"injector binary not found at {self._binary} -- "
                f"run `make` in core/injector first"
            )
        self._proc = subprocess.Popen(
            [str(self._binary)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
        )
        assert self._proc.stdin is not None and self._proc.stdout is not None
        try:
            hello_buf = _read_exact(self._proc.stdout, HELLO_SIZE)
        except EOFError as e:
            stderr = self._proc.stderr.read().decode(errors="replace") if self._proc.stderr else ""
            self._proc.wait()
            raise RuntimeError(f"injector failed to start: {e}\nstderr: {stderr}") from None
        self.hello = Hello.unpack(hello_buf)
        self._closed = False

    def default_gpr(self) -> list[int]:
        """The only known-safe gpr state for this process instance --
        see proto.h's bx862_hello doc comment. Callers should start from
        a copy of this and override only the fields they actually want
        to probe, especially leaving gpr[Gpr.RSP] alone."""
        return list(self.hello.default_gpr)

    def submit(self, job: Job) -> Result:
        assert self._proc.stdin is not None and self._proc.stdout is not None
        self._proc.stdin.write(job.pack())
        buf = _read_exact(self._proc.stdout, RESULT_SIZE)
        return Result.unpack(buf)

    # Chunk size for submit_batch's write-ahead pipelining. Large enough to
    # hide per-job round-trip latency, small enough to bound how much
    # unacknowledged data is ever in flight across the pipe at once.
    #
    # History: an earlier version of this method used ONE writer thread
    # for the entire batch, unbounded. That deadlocked on batches over a
    # few hundred jobs (OS pipe buffer fills in both directions at once --
    # see the chunked design below) and, once threaded, reproducibly
    # crashed the daemon on one fleet machine (Debian testing, kernel
    # 7.3.0-rc6) at ~4600 jobs of continuous backlog -- NOT reproducible
    # with the same instructions submitted sequentially, or in a small
    # pipelined batch, on that same machine or any other in the fleet.
    # Root cause not fully isolated, but it tracks the amount of
    # unacknowledged in-flight data, not any particular candidate -- so
    # bounding that amount via chunking is the fix, independent of
    # whatever the exact kernel/pipe-buffering interaction was.
    _BATCH_CHUNK = 128

    def submit_batch(self, jobs: Iterable[Job]) -> Iterator[Result]:
        """Pipeline writes ahead of reads within each chunk -- the daemon
        processes jobs strictly in order, one in one out, so this avoids a
        round trip of latency per job without needing any id/sequence
        field, while bounding in-flight unacknowledged data to one chunk
        (see _BATCH_CHUNK's comment)."""
        import threading

        assert self._proc.stdin is not None and self._proc.stdout is not None
        jobs = list(jobs)

        for start in range(0, len(jobs), self._BATCH_CHUNK):
            chunk = jobs[start:start + self._BATCH_CHUNK]

            def _writer(chunk=chunk):
                assert self._proc.stdin is not None
                try:
                    for job in chunk:
                        self._proc.stdin.write(job.pack())
                except (BrokenPipeError, OSError):
                    # The daemon died (or we're closing) and the reader
                    # side already raised/is raising EOFError for the
                    # caller -- nothing more to report from here.
                    pass

            t = threading.Thread(target=_writer, daemon=True)
            t.start()
            for _ in chunk:
                buf = _read_exact(self._proc.stdout, RESULT_SIZE)
                yield Result.unpack(buf)
            t.join(timeout=5)

    def identity(self) -> dict:
        info = {
            "backend": "ring3",
            "machine": platform.node(),
            "uname": " ".join(platform.uname()),
            "null_page_mapped": self.hello.null_page_mapped,
        }
        try:
            with open("/proc/cpuinfo") as f:
                text = f.read()
            for line in text.splitlines():
                if line.startswith("model name") and "cpu_model" not in info:
                    info["cpu_model"] = line.split(":", 1)[1].strip()
                elif line.startswith("microcode") and "microcode" not in info:
                    info["microcode"] = line.split(":", 1)[1].strip()
                elif line.startswith("stepping") and "stepping" not in info:
                    info["stepping"] = line.split(":", 1)[1].strip()
        except OSError:
            pass
        return info

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._proc.stdin:
            self._proc.stdin.close()
        self._proc.wait(timeout=5)

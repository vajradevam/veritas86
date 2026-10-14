"""
runner.py — drive Ring3Injector over corpus.full_corpus(), write one JSONL
file: first line is the identity block, every following line is one
fingerprint record (fingerprint.py).

Usage:
    python3 -m tsfuzz.runner [out.jsonl]

Defaults the output path to data/fingerprints/<hostname>.jsonl (relative
to the repo root), creating the directory if needed.
"""
from __future__ import annotations

import json
import platform
import subprocess
import sys
import time
from pathlib import Path

from .backends.ring3 import Ring3Injector
from .corpus import full_corpus
from .fingerprint import job_for, record, scratch_v1_gpr


def read_cpu_identity() -> dict:
    info: dict[str, str] = {}
    try:
        text = Path("/proc/cpuinfo").read_text()
        for line in text.splitlines():
            if ":" not in line:
                continue
            k, v = line.split(":", 1)
            k, v = k.strip(), v.strip()
            if k in ("model name", "microcode", "stepping", "cpu family", "model", "vendor_id") and k not in info:
                info[k] = v
    except OSError:
        pass
    try:
        info["mmap_min_addr"] = subprocess.run(
            ["sysctl", "-n", "vm.mmap_min_addr"], capture_output=True, text=True
        ).stdout.strip()
    except Exception:
        pass
    return info


def run_state_resilient(make_injector, corpus, state_fn, state_name: str, f, records: list,
                         crash_log: list) -> None:
    """Submit corpus under one input state, auto-reconnecting to a fresh
    daemon on an EOFError (the daemon died) instead of aborting the whole
    sweep.

    This exists because of a real, reproducible finding (see
    docs/safety.md / data/reports): on one fleet machine (Debian testing,
    kernel 7.3.0-rc6+), the daemon is reliably killed by an UNCAUGHT
    SIGBUS -- not routed through bx862_signals_install's own handler --
    at a specific point in the scratch_v1 sweep (REX.W POPFQ, `48 9d`,
    after ~1999 preceding same-state submissions to that daemon
    instance). Confirmed NOT a pipe/threading race (reproduces with
    plain sequential submit(), no batching) and NOT cross-state
    accumulation (reproduces on a freshly-started daemon running only
    this state). Root cause not pinned down beyond that -- flagged as an
    open item, not swept under the rug. Reconnecting gets a complete
    dataset anyway; every crash is logged into the output (`_crashes` in
    the identity block) rather than silently retried.

    `state_fn(default_gpr) -> gpr` is recomputed against the NEW
    daemon's own handshake after every reconnect, never reused from a
    previous process -- each daemon instance has its own ASLR layout, so
    a 'scratch_v1'-style pointer value from one process is garbage in
    another."""
    start = 0
    inj = make_injector()
    gpr = state_fn(inj.default_gpr())
    try:
        while start < len(corpus):
            remaining = corpus[start:]
            jobs = [job_for(c, gpr) for c in remaining]
            try:
                for cand, res in zip(remaining, inj.submit_batch(jobs)):
                    rec = record(cand, res, state=state_name)
                    records.append(rec)
                    f.write(json.dumps(rec) + "\n")
                    start += 1
                f.flush()
            except EOFError as e:
                crash_log.append({
                    "state": state_name,
                    "at_index": start,
                    "label": corpus[start].label,
                    "enc": corpus[start].prefix.hex(),
                    "error": str(e),
                })
                print(
                    f"[runner] injector died in state={state_name} at candidate "
                    f"{start}/{len(corpus)} ({corpus[start].label}) -- reconnecting "
                    f"and resuming (see docs/safety.md for the known cause)",
                    file=sys.stderr,
                )
                try:
                    inj.close()
                except Exception:
                    pass
                inj = make_injector()
                gpr = state_fn(inj.default_gpr())
    finally:
        inj.close()


def main() -> int:
    repo_root = Path(__file__).resolve().parents[2]
    out_path = Path(sys.argv[1]) if len(sys.argv) > 1 else (
        repo_root / "data" / "fingerprints" / f"{platform.node()}.jsonl"
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)

    corpus = full_corpus()
    print(f"[runner] {platform.node()}: {len(corpus)} candidates -> {out_path}", file=sys.stderr)

    t0 = time.time()
    bootstrap = Ring3Injector()
    identity = bootstrap.identity()
    identity.update(read_cpu_identity())
    identity["ts"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    identity["corpus_size"] = len(corpus)
    states = {
        "zero_v1": (lambda default_gpr: default_gpr),
        "scratch_v1": scratch_v1_gpr,
    }
    identity["states"] = list(states)
    bootstrap.close()

    records: list = []
    crash_log: list = []
    tmp_path = out_path.with_suffix(out_path.suffix + ".partial")
    with tmp_path.open("w") as f:
        f.write(json.dumps({"_identity": identity}) + "\n")
        f.flush()
        for state_name, state_fn in states.items():
            run_state_resilient(Ring3Injector, corpus, state_fn, state_name, f, records, crash_log)
        f.flush()

    elapsed = time.time() - t0
    identity["elapsed_s"] = round(elapsed, 3)
    identity["crashes"] = crash_log
    if crash_log:
        # Rewrite the identity line in place now that we know the final
        # crash count -- cheap since it's always the first line.
        lines = tmp_path.read_text().splitlines(keepends=True)
        lines[0] = json.dumps({"_identity": identity}) + "\n"
        tmp_path.write_text("".join(lines))
    tmp_path.rename(out_path)

    n_executed = sum(1 for r in records if r["fault"] == "NONE")
    n_ud = sum(1 for r in records if r["fault"] == "UD")
    n_priv = sum(1 for r in records if r["fault"] == "GP_OR_PF")
    n_bad_arena = sum(1 for r in records if not r["in_arena"])
    print(
        f"[runner] done in {elapsed:.2f}s — executed={n_executed} ud={n_ud} "
        f"priv/gp_or_pf={n_priv} other={len(records) - n_executed - n_ud - n_priv} "
        f"bad_arena={n_bad_arena}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

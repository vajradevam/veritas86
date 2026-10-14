# Veritas86 — Do We Trust Silicon?

A black-box x86 instruction-set auditor. It single-steps candidate byte
strings on real ring-3 hardware, classifies what the chip actually does
with each one from the fault it raises (or doesn't), and diffs that
behavior across machines and microarchitecture generations, in the
spirit of Christopher Domas's *Breaking the x86 ISA* (sandsifter).

Cryptography is the project's motivating example, not its boundary:
hardware-accelerated primitives like AES-NI are executed by the same
opaque silicon as everything else, and this tool audits that silicon in
general. The full writeup, including methodology diagrams, three
experimental sweeps across a six-machine fleet, and every finding, is
in [`report/report.pdf`](report/report.pdf).

## How it works, in one paragraph

A long-lived daemon maps a candidate's bytes at the very end of a
mapped, executable page, with an unmapped guard page immediately after
it. Single-stepping (via `RFLAGS.TF`) lets the real CPU decoder, not
this project's own guess, decide what happens next: `SIGILL` means the
encoding does not exist, a `SIGSEGV` exactly at the guard-page boundary
means the decoder wanted more bytes than were resident (a length
signal, not an existence signal), a `SIGSEGV` elsewhere means the
encoding exists but ring 3 cannot run it, and `SIGTRAP` means it
executed cleanly. Sliding the candidate's window back one byte at a
time against that same boundary resolves exact instruction length
without ever implementing a decoder. Section 3.2 of the report works
through this with diagrams and a worked byte-by-byte example.

## Repository layout

```
core/injector/       C daemon: the ring-3 execution engine (one job in,
                      one result out, over a pipe; see docs/injector-protocol.md)
core/tests/           known-answer smoke tests against the in-process C API
orchestrator/tsfuzz/  Python driver: candidate corpus generation, the
                      wire-protocol client, cross-machine diffing
orchestrator/tests/   orchestrator-level tests against the real subprocess
data/fingerprints/    raw per-machine sweep output (JSONL, one row per candidate)
data/reports/         narrative write-ups and raw diffs for each sweep
docs/                 wire protocol, safety design and incident writeups,
                      original planning docs
report/               the LaTeX report (source, figures, generated PDF)
scripts/              safety preflight checks, environment probing
```

## Quick start

```sh
just build     # build core/injector + core/tests
just smoke     # safety preflight, then known-answer tests -- run this before anything else
just pytest    # orchestrator-level tests against the real injector subprocess
just sweep     # run the full candidate corpus on this machine
                # writes data/fingerprints/<hostname>.jsonl
just diff data/fingerprints/*.jsonl   # cross-machine divergence report
```

No `just`? Each recipe is a thin wrapper; read `justfile` and run the
underlying `make`/`python3` commands directly.

## Safety

Every result in this project comes from unprivileged, ring-3 execution;
no privilege escalation is attempted anywhere in this codebase. A
byte-pattern blacklist (`core/injector/blacklist.c`) refuses to execute
encodings whose effect cannot be safely recovered from inside a signal
handler (segment-register loads, `syscall`/`sysenter`, and a few gaps
found empirically by running the harness at scale, documented in
`docs/safety.md`). `scripts/safety_preflight.sh` refuses to run as root
unless an explicit sacrificial-hardware flag is set, and that flag was
never set for any result in the report. Read `docs/safety.md` before
pointing this at any machine you care about.

## Status

Three sweeps completed across a six-machine fleet spanning five Intel
microarchitecture generations (Sandy Bridge-EP 2012 through Tiger Lake
2020): 823 candidates / 1 state / 4 machines, then 2,689 candidates / 2
states / 5 machines, then 4,996 candidates / 2 states / 6 machines
(59,952 total data points). Findings include a reproduction of
sandsifter's own headline result on this fleet, three real safety gaps
found and two fixed in this harness's own code, detection of UMIP and
PKU purely from `#UD`-versus-executes behavior with no privileged
access, a hardware-RNG (RDRAND/RDSEED) generational boundary pinned to
specific machines, and a decoder-level EVEX-recognition split that
exists nowhere in the CPUID feature flags the SDM exposes. Full results
in `report/report.pdf`; raw data in `data/`.

## License

MIT, see `LICENSE`.

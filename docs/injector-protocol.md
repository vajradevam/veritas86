# The injector wire protocol

What `core/injector/main.c` (the daemon) speaks over stdin/stdout, and what
a driver (e.g. `orchestrator/tsfuzz/backends/ring3.py`, not yet written)
must implement. All structs are defined once, canonically, in
`core/injector/proto.h` — this document explains the *sequence*, not the
byte layout (read proto.h for that; the struct comments there are the
source of truth and this file must be kept in sync with them).

## Sequence

1. Launch `core/injector/injector` as a subprocess (stdin/stdout as pipes).
2. **Read exactly `sizeof(struct bx862_hello)` bytes first, before writing
   anything.** This handshake is sent once, unconditionally, before the
   daemon reads its first job. It exists because the daemon's 4-page arena
   lives inside an ASLR'd `mmap` the driver has no other way to learn —
   `hello.default_gpr` is the *only* register state guaranteed valid for
   this specific process instance, and in particular
   `hello.default_gpr[GPR_RSP]` is the only `%rsp` value safe to put in an
   outgoing job's `gpr[GPR_RSP]` without inspecting the daemon's memory
   layout yourself. See `docs/safety.md` for why this matters (a bad
   `gpr[GPR_RSP]` is recoverable but produces a garbage result, not a
   candidate finding).
3. For each candidate: write exactly `sizeof(struct bx862_job)` bytes, then
   read exactly `sizeof(struct bx862_result)` bytes back. One in, one out,
   no batching at the wire level (batching, if wanted, is a driver-side
   concern — pipeline several jobs' writes before draining the matching
   reads).
4. Close stdin (or just let the subprocess handle end) to signal clean
   shutdown; the daemon exits 0 on EOF.

## Building a job

- Start from `hello.default_gpr` and only override the fields you actually
  want to test (e.g. set `gpr[GPR_RAX]` to some nonzero probe value while
  leaving everything else, especially `gpr[GPR_RSP]`, at the handshake
  default).
- `mode`: `MODE_LENGTH` (1) — resolve length only, via the page-fault
  slide. `MODE_EXECUTE` (2) — execute exactly `enc_len` bytes as given (no
  length resolution; refused outright, `rc != 0` equivalent via
  `result.fault_class == FAULT_UNKNOWN` with `valid_length == 0`, if the
  encoding matches the blacklist). `MODE_BOTH` (3) — the normal case for
  fuzzing: resolve length via the slide, and the resolving probe doubles as
  the actual execution, so `result` carries valid output state whenever
  `result.fault_class == FAULT_NONE`.
- `enc`/`enc_len`: up to 15 bytes. For `MODE_LENGTH`/`MODE_BOTH` this is a
  *candidate* — the true instruction may resolve to fewer bytes than
  `enc_len` supplies (or, if `enc_len` was too short, `result.valid_length`
  comes back 0 and `result.fault_class == FAULT_BOUNDARY_PF`, meaning "give
  me more bytes"). For `MODE_EXECUTE`, `enc_len` is taken as authoritative.

## Reading a result

- `fault_class` (see `proto.h`'s `enum bx862_fault_class`) is the primary
  signal: `FAULT_NONE` = executed, output state is meaningful;
  `FAULT_UD` = doesn't exist; `FAULT_BOUNDARY_PF` = (MODE_LENGTH/BOTH only,
  should not normally surface to a driver unless `enc_len` was too short)
  needs more bytes; `FAULT_GP_OR_PF` = exists but ring 3 can't run it, OR a
  non-boundary page fault — these are NOT distinguished (see
  `docs/safety.md`); `FAULT_FP`/`FAULT_BUS` = self-explanatory; `UNKNOWN` =
  refused (blacklist) or an unrecognized signal.
- **Sanity-check `rip_off` against `[0, page_size]` (4096 on every machine
  in this fleet; upper bound INCLUSIVE) before trusting a fault as a
  candidate finding.** The inclusive upper bound matters: `length.c`
  right-justifies candidates against the end of `exec_page`, so an
  instruction that fully consumes the page legitimately lands its
  post-execution RIP exactly at `page_size` — that is a real result, not a
  host fault. A value *beyond* `page_size` means the fault happened in the
  daemon's own code, not in the candidate — see `docs/safety.md`'s "faults
  from our own code" section. This should only happen if a driver builds a
  job with a bad `gpr[GPR_RSP]` instead of using the handshake value; it
  should not happen in ordinary use. (`orchestrator/tsfuzz/proto.py`'s
  `Result.in_arena()` implements this check — verified live: a plain `nop`
  at the full-page-slide position produces `rip_off == 4096` exactly, which
  must pass this check.)
- `length`/`valid_length`: the resolved instruction length, only meaningful
  when `valid_length == 1`.
- `gpr`/`rflags`: post-execution state when `fault_class == FAULT_NONE`,
  otherwise the state at the moment of the fault (useful for diagnostics,
  not for fingerprinting an "output").

## Process model

One daemon process handles one job at a time, single-threaded, no
concurrency inside the process (the trampoline's jump-target global is not
thread-safe — see `trampoline.S`). For parallel scanning across CPU cores,
run multiple daemon subprocesses, each pinned to a distinct core (see
`scripts/pin.sh`, not yet implemented) with its own independent handshake —
do not share one daemon process across cores.

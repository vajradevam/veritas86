# Safety notes — core/injector

This documents what actually turned out to matter while building the ring-3
injector (core/injector), as opposed to what IMPLEMENTATION_PLAN.md predicted
in advance. Read this before modifying signals.c, trampoline.S, or length.c.

## The TF single-stepping trap — the bug that took the longest to find

**Symptom:** every candidate, regardless of content, resolved to length 1
with "executed successfully" — including `0f0b` (ud2), which cannot possibly
be a valid 1-byte instruction.

**Root cause:** the original trampoline armed the trap flag (via `popfq`)
*before* jumping to the candidate. Single-stepping a `jmp` traps as soon as
the `jmp` itself completes — you land exactly at the target with nothing
there executed yet. So the trap fired on arrival, before the candidate's
first instruction ever ran, and every result looked like a trivial 1-byte
success.

**Fix:** the `popfq` that arms TF must be the instruction *immediately
before* the candidate's own bytes in the instruction stream — not reached
via an intervening jump. `bx862_run_attempt` (signals.c) now plants a single
`0x9D` (POPFQ) byte directly adjacent to, and immediately before, the
candidate, and reaches it with TF still *off* via an ordinary jmp (safe,
since TF isn't armed yet). The planted `popfq` then arms TF, and the very
next instruction boundary the CPU crosses — the candidate's real first
instruction — is what correctly receives the single-step trap. See the long
comment at the top of `trampoline.S` for the full mechanics.

**Side effect worth remembering:** because the planted `popfq` is a real
pop, it consumes the qword at the configured `%rsp` (which `run_attempt`
pre-seeds with the RFLAGS value to install) and advances `%rsp` by 8 before
the candidate runs. The candidate's *observed* entry `%rsp` is therefore
`gpr[GPR_RSP] + 8`, not `gpr[GPR_RSP]` itself.

**Contract this creates for callers of `bx862_run_attempt`:** `target` must
have at least one writable byte immediately before it in the same mapping.
Both `length.c`'s sliding window and `inject.c`'s EXECUTE-mode placement
reserve that byte (`inject.c` places the candidate at `exec_page + 1`, not
`+ 0`, specifically for this).

## Faults from our own code vs. faults from the candidate

The signal handler installed by `bx862_signals_install` catches
`SIGILL/SIGSEGV/SIGBUS/SIGFPE/SIGTRAP` for the *entire process* — not just
for code inside the candidate. That means a bug in the injector itself (for
example: a caller supplying an invalid `gpr[GPR_RSP]`, which `run_attempt`
dereferences to seed the planted `popfq`) can also land in this handler.

Two things make that safe rather than catastrophic:

1. **`g_armed`** (signals.c) is true only from the start of the
   `sigsetjmp()` block onward. If a handled signal ever arrives while
   `g_armed` is false, that is unambiguously an injector bug, not a
   candidate fault — the handler writes a diagnostic (via the
   async-signal-safe `write()`, not `fprintf`) and calls `_exit()` rather
   than risk `siglongjmp`-ing into a stale or uninitialized
   `g_recovery_env`.
2. **Even armed, a fault from our own seed-write is distinguishable from a
   candidate fault** by checking `result.rip_off` against `[0, page_size)`
   — a candidate fault's RIP falls inside `exec_page`; a fault from
   `run_attempt`'s own pointer dereference does not (its RIP is wherever
   `signals.c` itself lives). This was verified empirically: feeding a
   deliberately-invalid `gpr[GPR_RSP] = 0` (unsafe without the NULL page
   mapped — see below) through the daemon produces a result with
   `rip_off` far outside `[0, 4096)`, rather than a crash.

This is why `state.h` documents `zero_nullmapped_v1` as "only safe when
`arena->null_page_mapped` is true" — with `zero_v1` (the default, `%rsp`
pointed into `scratch_page`), this class of self-inflicted fault doesn't
happen at all in ordinary use.

## `#GP` vs. non-boundary `#PF` — an accepted, documented gap

Linux delivers both a privileged-instruction `#GP` and a non-boundary `#PF`
to userspace as `SIGSEGV`, and there is no portable way to tell them apart
from a signal handler alone. `proto.h`'s `FAULT_GP_OR_PF` is deliberately
named to reflect this — it means "exists, but ring 3 can't run it, for one
of these two reasons," not "confirmed `#GP`." This is sufficient for length
analysis (only the boundary case, `FAULT_BOUNDARY_PF`, needs to be told
apart from everything else) and sufficient for existence/privilege
detection (both cases mean "the encoding exists"). It is NOT sufficient for
precise privilege classification — closing that gap is exactly what the
ptrace- or VM-exit-based harness in IMPLEMENTATION_PLAN.md §6–7 (Idea 4) is
for, since a tracer can read the real trap vector.

## Found empirically: `pop fs`/`pop gs` (0f a1 / 0f a9) crashed the injector

The first full two-byte-opcode-map sweep (`orchestrator/tsfuzz/runner.py`,
`corpus.map0f()`) killed the injector subprocess outright at `0f a1`. Root
cause: `blacklist.c` only matched `mov Sreg` (`8e`) and `lss/lfs/lgs`
(`0f b2/b4/b5`) as segment-register loads — it missed that `pop fs`/`pop gs`
(`0f a1`/`0f a9`) are *also* unprivileged segment loads. With the sweep's
all-zero default GPR state, `pop fs` loads FS from the zeroed scratch value,
which breaks the TLS-relative addressing glibc (and this process's own
signal-handler bookkeeping) depends on — the fault that follows doesn't go
through `bx862_signals_install`'s handler cleanly, so the subprocess just
dies, mid-batch, with no diagnostic.

Fixed by adding `0f a1`/`0f a9` to the blacklist (same treatment as
`lfs/lgs`) and added as a regression test (`test_blacklist_refuses_pop_fs_gs_execute`
in `orchestrator/tests/test_ring3.py`). Lesson for extending the blacklist
later: audit by *semantic class* ("does this write a segment selector
register?"), not by copying the specific mnemonics the paper happened to
name — `mov`, `lss/lfs/lgs`, and `pop` all reach the same hazard through
different opcodes, and there may be others (e.g. far `ret`/`iret`, not yet
swept) worth the same treatment before a ring-0 backend makes the blast
radius worse.

## Open item: an uncaught SIGBUS kills the daemon on one kernel, after ~2000 jobs

Found during the second, larger fleet sweep (2,689-candidate corpus × 2
input states). On debian (kernel 7.3.0-rc6+, a pre-release/testing
kernel; same CPU model, i7-1165G7, as `lily`, which never shows this),
the daemon dies deterministically at `48 9d` (REX.W `popfq`) under the
`scratch_v1` state (every GPR, including RSP, aliased to the same
pointer), after ~1999 preceding submissions to that daemon instance.

Characterized, not just observed:
- Reproduces with plain sequential `submit()` — ruling out the pipe/
  writer-thread pipelining as the cause.
- Reproduces on a freshly-started daemon running *only* the `scratch_v1`
  pass — ruling out contamination from the `zero_v1` pass run before it.
- Does **not** reproduce submitting `48 9d` alone with no preceding jobs
  — so it's a real cumulative effect of ~1999 consecutive single-stepped
  executions in one daemon instance, not an unconditional property of
  the instruction/state combination.
- The daemon exits via Python's reported returncode `-7` (killed by
  signal 7, `SIGBUS`) with **no** output from `signals.c`'s own handler
  — neither its normal result path nor the `g_armed == false` "signal
  outside a controlled attempt" diagnostic (confirmed by capturing the
  daemon's stderr directly across the crash: only the ordinary
  NULL-page startup notice). `bx862_signals_install` *does* register a
  `SIGBUS` handler, so this `SIGBUS` bypassed it entirely.
- No kernel-side signal (no segfault/oops in `dmesg`/`journalctl -k`) —
  this is userspace-signal-delivery-level, not a hardware exception
  escaping to the kernel.

Leading suspicion, not yet confirmed: `bx862_run_attempt` escapes its own
signal handler via `siglongjmp()` instead of letting the handler return
normally, which skips the kernel's normal `sigreturn` path. `sigreturn`
is what restores the process's signal mask to what it was before the
handler ran; skipping it on every single one of ~2000 handled signals in
a row, on a kernel whose signal-delivery bookkeeping differs just enough
from `lily`'s (same CPU, older/stable kernel) to expose it, is a
plausible way to end up with `SIGBUS` wrongly blocked at the exact moment
the CPU raises it synchronously — which Linux may resolve by killing the
process outright rather than queuing an undeliverable synchronous fault.
Not yet verified by actually inspecting the process's signal mask at the
point of failure (e.g. via `/proc/<pid>/status`'s `SigBlk` the instant
before it dies) — that's the next concrete step before trusting this
theory.

**Current mitigation, not a fix:** `orchestrator/tsfuzz/runner.py`'s
`run_state_resilient` auto-reconnects to a fresh daemon on this failure
and resumes from the next candidate (recomputing any ASLR-dependent
input state from the new process's own handshake — never reusing a
pointer value from the dead process), logging every occurrence into the
output file. This gets a complete dataset despite the bug; it does not
explain it. If this is ever hit on the sacrificial Xeon with ring-0 work
(Idea 4/5), do not assume the same "just reconnect" mitigation is safe —
re-derive it for that backend specifically.

## Found empirically: `F3 0F AE /2` (UMONITOR) crashed the injector unconditionally

Found during the sweep-3 corpus expansion, specifically the full 256-ModRM
sweep of `0F AE` (Group 15) under the `F3` prefix
(`group15_0fae_prefixed_sweep`). Every ModRM byte with reg field `010`
(`D0`-`D7`, i.e. `UMONITOR`) killed the daemon outright, confirmed on a
*single isolated job submitted to a freshly started daemon with no prior
state at all* — this is not the pop-fs/gs class of bug (not a NULL-deref
consequence of the zeroed default state: it reproduces identically under
`scratch_v1`, which points every GPR at valid mapped memory) and not the
Debian SIGBUS class of bug (not an accumulation effect: it is the very
first job the daemon processes, every time).

Characterized the same way as the Debian SIGBUS finding: the daemon exits
with Python's reported return code `-11` (killed by a raw, uncaught
`SIGSEGV`), despite `signals.c` installing a `SIGSEGV` handler, and with no
diagnostic from that handler's own `g_armed == false` path — the signal
bypasses the handler entirely, the identical failure signature as the
SIGBUS case, just a different signal number and a different trigger
(single-shot here, versus after ~2000 jobs there). Root cause not pinned
down for either; both point at the same suspect (`bx862_run_attempt`'s use
of `siglongjmp()` to escape the handler, skipping the kernel's
`sigreturn` signal-mask restoration), but that is still a hypothesis, not
a confirmed diagnosis — see the SIGBUS section above for the open item.

Fixed, this time, by extending the blacklist rather than only working
around it at the Python layer: `blacklist.c` now tracks whether the `F3`
prefix specifically was present (not just "some legacy prefix"), and
refuses to execute `0F AE` when the ModRM byte selects `mod=11, reg=010`
under that prefix. The unprefixed and `66`-prefixed forms of the same
opcode and ModRM byte are left alone — they were already swept safely
elsewhere (`anomaly_followup`, `group15_0fae_prefixed_sweep(0x66, ...)`)
with no issue, so blacklisting them too would have been over-broad.
Regression-tested (`test_blacklist_refuses_umonitor_execute`), which also
asserts the unprefixed/66 forms are *not* blocked, to catch the opposite
mistake (over-blacklisting) if this is ever "fixed" again carelessly.

This is the third distinct blacklist gap found this way (after `pop
fs`/`pop gs` and, informally, the family of segment-load instructions the
paper named directly). The pattern across all three: a fuzzer that
systematically enumerates ModRM space finds hazards a hand-picked list
of "known dangerous mnemonics" does not, because the hazard is a property
of the *opcode-plus-ModRM-field combination*, not of the mnemonic as
commonly written. A full 256-ModRM sweep of every group-coded opcode
(`0F 00`, `0F 01`, `0F AE`, `0F BA`, `0F C7`, `0F 71-73`) would be the
systematic fix; only `0F AE` has had that treatment under all four prefix
variants so far (none, `66`, `F2`, `F3`), and only after this crash forced
it.

## The blacklist is a best-effort byte matcher, not a decoder

`blacklist.c` skips legacy/REX prefixes and matches a short list of opcode
patterns (segment loads, `int 0x80`/`int 0x0e`, `sysenter`, `syscall`). It
does not parse ModRM/SIB and can be over-broad but must never be
under-broad for the patterns it lists. `length.c`'s sliding-window loop
checks the blacklist *before* probing each candidate length and refuses to
probe further once matched — it will not risk a real single-step execution
of a segment load or syscall entry just to learn its length. Once
`third_party/xed` is wired in, replace this with a real decode-based check.

## Before running on the Xeon (Idea 4/5 — not yet built)

None of the above applies to ring-0/MSR work — that is a different,
higher-risk backend (`BaremetalInjector`, not yet implemented) governed by
IMPLEMENTATION_PLAN.md §7. `scripts/safety_preflight.sh` refuses to run as
root unless `BX862_SACRIFICIAL=1` is explicitly set, specifically so that
Xeon-only, hardware-destructive work can't accidentally run on a machine you
didn't mean to sacrifice.

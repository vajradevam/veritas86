# First cross-silicon result — mid-sem checkpoint

**Date:** 2026-10-14
**Corpus:** 823 candidates (`orchestrator/tsfuzz/corpus.py::full_corpus`) —
all 256 one-byte opcodes, all 256 `0F xx` two-byte opcodes, the
`0f18`-`0f1f` reserved-NOP family under 5 ModRM variants, 10 named
paper-regression seeds, a REX.W-prefixed re-sweep of the one-byte map, and
5 EVEX-encoded AVX-512 seeds extracted via `gcc -mavx512f` + `objdump`
(see corpus.py for the exact bytes/provenance).

**Fleet (4 real machines, 3 Intel microarchitecture generations, over
Tailscale):**

| Host | CPU | µarch | Microcode | OS |
|---|---|---|---|---|
| lily (this laptop) | i7-1165G7 | Tiger Lake | 0xb6 | Arch |
| debian | i7-1165G7 | Tiger Lake | 0xbc | Debian testing |
| fuzzarch | i7-8550U | Kaby Lake-R | 0xf6 | Arch |
| d153-system | i7-9700T | Coffee Lake | 0x104 | Ubuntu 24.04 |

Raw fingerprints: `data/fingerprints/{host}.jsonl`. Diff output:
`data/reports/sweep1_diff.txt`.

## Result 1 — engine correctness (prerequisite for trusting anything below)

`core/tests/smoke.c`'s 5 known-answer cases (IMPLEMENTATION_PLAN.md §3.6)
pass on **all 4 machines**, 16/16 checks each, including the paper's
headline finding reproduced live:

> `66 e9 00 00 00 00` resolves to **length 6** on every machine — the `66`
> operand-size-override prefix is architecturally meaningless on `jmp
> rel32` in 64-bit mode, so silicon decodes a 6-byte jump, not the 2-byte
> jump + 4 stray bytes a naive `66`-honoring disassembler would predict.

`f4` (`hlt`) correctly reports "exists but privileged" (`GP_OR_PF`), not
`#UD`, on every machine — confirms the harness tells "doesn't exist" apart
from "exists, ring 3 can't run it."

## Result 2 — a real safety-harness bug found and fixed via live fuzzing

The first full `0F xx` sweep crashed the injector outright at `0f a1`
(`pop fs`). `blacklist.c` blocked `mov Sreg`/`lss`/`lfs`/`lgs` as
segment-register loads but missed that `pop fs`/`pop gs` are the same
hazard class through a different opcode — loading FS from the sweep's
zeroed GPR state breaks the TLS-relative addressing the process's own
signal-handler recovery path depends on, so the crash happens *before*
`bx862_signals_install`'s handler can run. Fixed (`0f a1`/`0f a9` added to
the blacklist), regression-tested
(`test_blacklist_refuses_pop_fs_gs_execute`), and documented in
`docs/safety.md` with the generalizable lesson: audit the blacklist by
*semantic class* ("does this write a segment selector?"), not by copying
specific mnemonics from the paper.

## Result 3 — the core 1-/2-byte opcode decode surface is identical across all 4 CPUs

818 of 823 encodings (99.4%) agree on length *and* fault class across
**every** machine — 3 microarchitecture generations, 4 microcode
revisions, 3 kernel/distro combinations. This is the expected result (the
core opcode map is the most heavily validated part of x86), and it's the
calibration proof the project needs before any drift claim is credible:
the harness isn't introducing noise, and it isn't missing real
differences when they exist (see Result 4).

## Result 4 — architectural AVX-512 fingerprinting (the headline result)

**All 5 of the 5 divergent encodings** are exactly the 5 AVX-512 EVEX
seeds, and they split **perfectly** along real AVX-512 capability:

| Encoding | Instruction | lily (TGL) | debian (TGL) | fuzzarch (KBL-R) | d153 (CFL) |
|---|---|---|---|---|---|
| `62f17c4858c1` | `vaddps zmm0,zmm0,zmm1` | executes | executes | `#UD` | `#UD` |
| `62f17d48fec1` | `vpaddd zmm0,zmm0,zmm1` | executes | executes | `#UD` | `#UD` |
| `62f1fd4859c1` | `vmulpd zmm0,zmm0,zmm1` | executes | executes | `#UD` | `#UD` |
| `62f17c48c2c100` | `vcmpeqps zmm0,zmm1,k0` | executes | executes | `#UD` | `#UD` |
| `c5f893c0` | `kmovw k0,eax` | executes | executes | `#UD` | `#UD` |

This matches `/proc/cpuinfo`'s `avx512f` flag exactly (present on both
Tiger Lake boxes, absent on Kaby Lake-R and Coffee Lake) — but the
harness never reads `cpuid`/`/proc/cpuinfo` to produce this table, it
derives it purely from black-box `#UD`-vs-executes behavior. That's the
project's Idea 8 (fingerprint → µarch/feature classification) working
end-to-end on real, heterogeneous hardware: **you can tell these four
CPUs apart, and identify which one has AVX-512, from instruction-fault
fingerprints alone, with zero prior knowledge of their model names.**

Lengths agree across all 4 machines even where fault class diverges
(6, 6, 6, 7, 4 bytes respectively, matching the real EVEX encoding
lengths) — confirms `length.c`'s guard-page slide resolves instruction
length correctly independent of whether ring 3 can execute the result.

## Result 5 — the `GP_OR_PF` bucket is 99.8% NULL-pointer faults, not privilege detection (methodology finding)

Digging into the 427 `GP_OR_PF` results past the cross-machine diff: **426
of 427 (99.8%) share one `cr2_off` value**, and decoding it against
`exec_page`'s base shows the real fault address was **0x0 — a NULL
pointer** — on all 4 machines. Only 25 of the 427 are truly opcode-only,
no-ModRM instructions with no memory operand at all (`hlt`, `cli`, `sti`,
`in`/`out`, `ins`/`outs`, `aam`-adjacent group gaps) — real privilege
faults. The other ~400 are two cases the handler can't currently tell
apart, exactly as `docs/safety.md`'s "`#GP` vs. non-boundary `#PF`" gap
predicted, but now quantified:

1. A ModRM-bearing opcode whose filler byte (`0x00`) decodes as `mod=00,
   rm=000` → memory operand `[rax]`, and the harness's default state has
   every GPR zeroed → **every such candidate dereferences NULL** and
   page-faults, regardless of whether the opcode itself is privileged.
2. A genuinely privileged opcode that happens to also carry a ModRM byte.

Linux reports `si_addr == 0` for synthesized `#GP` SIGSEGVs *and* for a
real `#PF` at address 0 — so both land in the same bucket and are
indistinguishable from a signal handler alone. **Concrete implication:**
the current corpus can only make a confident "privileged" claim for the
25 no-ModRM, no-operand opcodes; every ModRM-bearing result in
`GP_OR_PF` needs a non-zero base register (so the memory operand lands in
`scratch_page`, not address 0) or a ptrace/VM-exit backend (Idea 4) that
can read the real trap vector, before "exists but privileged" can be
trusted for that ~400-entry majority. This sharpens Idea 4's justification
with a number instead of a hand-wave.

**One reproducible outlier**, identical on all 4 machines (same low bits
of `cr2_off` relative to `exec_base` on every run): `0f ae` (Group 15 —
`fxsave`/`clflush`/`mfence`/etc., selected by ModRM) does **not** fault at
address 0 like its ModRM-memory siblings; it faults at `exec_base + 0x1ff`
— inside/near the candidate's own page, not at NULL. Deterministic across
4 CPUs and 2 microarchitectures, so it isn't noise, but the cause isn't
pinned down yet (candidate for next sweep: step through the ModRM/SIB
decode for the exact ModRM byte this filler produces and compare against
the SDM's Group 15 table).

---

# Sweep 2 — much larger corpus, 5th machine (z420), results checked for value

**Date:** 2026-10-14 (same day, follow-up). Corpus grew from 823 to
**2,689 candidates** (`corpus.py::full_corpus`): added the full `66/F2/F3`-
prefixed two-byte maps, the `0F 38`/`0F 3A` three-byte maps, a REX.W
two-byte-map re-sweep, ModRM-reg-field sweeps for the group-coded
opcodes (`0f00`, `0f01`, `0fba`, `0f71-73`, `0fc7`, `0f18`), a full
256-ModRM sweep of `0f ae` (to chase Sweep 1's anomaly), and 10 more
named feature seeds (AVX-512 VNNI/BITALG, GFNI, VAES, BMI1, BMI2, SHA-NI,
AVX2, FMA — bytes extracted via `gcc -m<ext>` + `objdump`, same method as
the AVX-512F seeds). Every candidate now also runs under **two named
input states** (`zero_v1` and a new `scratch_v1`), **5,378 submissions
per machine**. **5th machine added: z420** (Xeon E5-1607 0, Sandy
Bridge-EP — the oldest, most primitive part in the fleet, zero AVX2/
BMI/AVX-512). **26,890 total data points** across the fleet.

## Result 6 — `scratch_v1` resolves Sweep 1's methodology gap with hard numbers

Added a second named input state purely in Python (no `core/injector`
change): same handshake-guaranteed scratch pointer, but written into
**every** GPR instead of just RSP, so a `[rax]`-style ModRM memory
operand resolves into real mapped memory instead of NULL. Comparing
`zero_v1` vs `scratch_v1` on the same machine directly tests Result 5's
hypothesis:

- Of the **1,164** `GP_OR_PF` results under `zero_v1` (this run's
  corpus), **1,000 (86%) flip to a different fault class** under
  `scratch_v1` — confirmed NULL-deref artifacts, not privilege faults.
- The **164 that persist** under both states are the real thing: CR/DR
  access (`0f20-23`), `rdmsr`/`wrmsr` (`0f30/32/33`), I/O ports, `hlt`/
  `cli`/`sti`, and — satisfyingly — resolves Sweep 1's `0f ae` anomaly
  exactly as hypothesized by decoding its own ModRM bytes: the forms that
  persist under both states have `rm` field `100` (SIB byte follows;
  under `scratch_v1` the SIB's base+index both equal the same pointer, so
  the effective address becomes `2×scratch_ptr` — genuinely invalid) or
  `rm` field `101` with `mod=00` (RIP-relative — doesn't depend on GPR
  content at all, so of course it doesn't flip). No remaining mystery.

## Result 7 — a three-tier AVX-512 decode-generation split, not just a binary one

Z420 (Sandy Bridge-EP) makes the AVX-512 picture richer than Sweep 1's
binary split:

| Seed | lily/debian (Tiger Lake) | fuzzarch/d153 (Kaby-R/Coffee Lake) | z420 (Sandy Bridge-EP) |
|---|---|---|---|
| `vaddps zmm` (`62f17c4858c1`) | **executes**, length 6 | `#UD`, length **6** | `#UD`, length **2** |
| `vcmpeqps→k0` | executes, length 7 | `#UD`, length **7** | `#UD`, length **2** |

The two non-AVX-512 tiers disagree on *how far the decoder gets* before
giving up, and it's not noise — it's generational silicon archaeology:
Kaby Lake-R/Coffee Lake post-date the EVEX prefix shape being
standardized into the front-end decoder (it recognizes all 6 bytes as
one instruction, then faults only because the AVX-512 execution unit
itself is absent/disabled). Sandy Bridge-EP *predates EVEX existing as a
concept* — its decoder doesn't recognize `62` as an escape prefix at all
and reads it as the legacy (64-bit-mode-invalid) `BOUND` opcode, so it
gives up after only 2 bytes. Same CPUID-level answer ("no AVX-512"), two
mechanistically different silicon reasons, told apart purely from
black-box byte-level behavior.

## Result 8 — a clean Haswell-generation feature wall at z420

`feat_bmi1_andn`, `feat_bmi2_pext`/`pdep`, `feat_fma_vfmadd132ps`,
`feat_avx2_vpaddd_ymm` — all **execute identically** on all 4 post-2013
machines (Kaby Lake-R, Coffee Lake, both Tiger Lakes) and **all `#UD`**
on z420 alone. BMI1/BMI2/AVX2/FMA all shipped in Haswell (2013); Sandy
Bridge-EP (2012) predates every one of them. One of the cleanest possible
confirmations that the harness's feature fingerprint tracks real
silicon history, not instrumentation noise — matches `/proc/cpuinfo`
flags on every machine, derived from none of them.

## Result 9 — detecting UMIP, a security mitigation, by black-box fuzzing alone

The most interesting result of this run. `grp_0f00_reg0`/`reg1`
(`sldt`/`str`) and `grp_0f01_reg4` (`smsw`) — none of which are
architecturally privileged — **execute fine in ring 3** on d153-system,
fuzzarch, and z420, but **`#GP` in ring 3** on lily and debian. The two
machines that fault are the two Tiger Lake boxes; checked against
`/proc/cpuinfo`, lily and debian are the *only* machines in the fleet
with the `umip` flag:

| Host | `umip` flag | `sldt`/`str`/`smsw` in ring 3 |
|---|---|---|
| lily (TGL) | yes | `#GP` |
| debian (TGL) | yes | `#GP` |
| d153-system (CFL) | no | executes |
| fuzzarch (KBL-R) | no | executes |
| z420 (Sandy Bridge-EP) | no | executes |

**UMIP (User-Mode Instruction Prevention)** is a defensive CPU feature:
when `CR4.UMIP=1`, `sgdt`/`sidt`/`sldt`/`str`/`smsw` — none of which
write anything sensitive, but all of which leak kernel-table *addresses*
to ring 3, useful for defeating KASLR — raise `#GP` instead of running.
It's newer silicon than Kaby Lake-R/Coffee Lake (not present there at
all) and Linux enables it by default when present. The harness detected,
purely from `#GP`-vs-executes patterns with zero use of `cpuid`, which
machines in the fleet have a real kernel-enforced anti-information-leak
mitigation turned on. That's a security-relevant result, not just an
ISA-drift curiosity — it's the project demonstrating it could fingerprint
*hardening posture*, not just silicon generation.

## Result 10 — a reproducible harness crash, root-caused as far as it goes, then engineered around

The larger sweep crashed the daemon on debian (kernel 7.3.0-rc6+, a
pre-release/testing kernel) at a specific, deterministic point:
`48 9d` (REX.W `popfq`) under the `scratch_v1` state (every GPR aliased
to the same pointer), after exactly ~1999 preceding submissions to that
daemon process. Investigated rather than hand-waved:

- **Not a pipe/threading race**: reproduces identically with plain
  sequential `submit()` calls, no batching or writer thread at all.
- **Not cross-state accumulation**: reproduces on a *freshly started*
  daemon running only the `scratch_v1` pass from the start — doesn't
  need the `zero_v1` pass before it.
- **Not a kernel-level crash**: no segfault/oops in `journalctl -k` or
  `dmesg`. The process exits with Python's reported returncode `-7` —
  killed by a **raw, uncaught `SIGBUS`** — but `signals.c` *does*
  install a `SIGBUS` handler, and neither the handler's normal recovery
  path nor its `g_armed == false` "signal outside a controlled attempt"
  diagnostic fired (confirmed by capturing the daemon's stderr directly:
  only the usual NULL-page startup notice, nothing else). The signal
  bypassed our handler entirely.
- Isolating the exact candidate alone (`489d`, zero preceding jobs, same
  state) does **not** reproduce it — so it is a real cumulative effect
  of ~1999 consecutive single-stepped executions against one daemon
  instance, specific to this kernel, that ends by killing the process
  with a signal our own `sigaction` should have caught. Root cause not
  fully pinned (plausibly a signal-mask or altstack interaction specific
  to this kernel's handling of `siglongjmp`-based handler exit, which
  skips the normal `sigreturn` path — flagged as a real open item for
  follow-up, not swept under the rug).

**Engineering response** (`orchestrator/tsfuzz/runner.py`'s
`run_state_resilient`): auto-reconnect to a fresh daemon on this failure
and resume from the next candidate, logging every occurrence into the
output file's `_identity.crashes` list rather than silently retrying.
Confirmed on debian: dataset completed (5,378/5,378 rows, one logged
crash entry), identical aggregate fault-class counts to a clean run.
Also fixed a latent bug surfaced while building this: a reconnected
daemon is a **new process with its own ASLR layout**, so the
`scratch_v1` pointer must be recomputed from the new daemon's own
handshake on every reconnect, never reused from a previous process.

## What this sets up for finals

- **Idea 8** (fingerprint classification) has its first real labeled
  signal (AVX-512 split) to build a classifier against, once more feature
  families (AVX-512\_VNNI, SHA-NI, AMX, etc.) are added to the corpus.
- **Idea 1** (microcode drift) is unblocked: the harness is proven stable
  and sensitive on 4 machines; next step is walking microcode revisions
  on one box (`experiments/idea1_microcode_drift/`, not yet built) rather
  than cross-machine diffing.
- **Idea 7** (doc drift) is pure software and can be built independently
  of hardware access.
- The `pop fs/gs` fix is worth a line in the presentation as evidence the
  safety-first design (ring-3 default, blacklist, checkpointed sweeps)
  is pulling its weight before any ring-0 work is attempted.

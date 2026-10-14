# Sweep 3 — expanded corpus, 6th machine, security/crypto-focused groups

**Corpus:** 4,996 candidates (up from 2,689), 2 input states, 6 machines
(lily, debian, fuzzarch, d153-system, z420, **imac** — new), 9,992 rows/
machine, 59,952 total data points. New in this sweep: full 256-ModRM
sweeps of Group 7 (`0F 01`: PKU/TSX/SMAP/VMX/SERIALIZE), Group 9 (`0F C7`:
CMPXCHG8B/16B/RDRAND/RDSEED), Group 15 (`0F AE`) under `66`/`F2`/`F3`
prefixes (CLWB/CLFLUSHOPT/TPAUSE/UMWAIT/UMONITOR); `66`-prefixed full
three-byte-map sweeps (`0F 38`, `0F 3A` — scalar AES-NI, PCLMULQDQ);
VEX.256.66-prefixed full three-byte-map sweeps (VAES, VPCLMULQDQ); named
seeds for AVX2/AVX-512 gather (Downfall-relevant) and RDPID.

New machine: **imac**, Intel Core i5-4570R, **Haswell** (2013), microcode
0x1c. Fills the exact generational gap the Haswell-wall result needed: a
real Haswell box, not just inferred from the Sandy Bridge-EP boundary.

## New engineering finding: third blacklist gap (UMONITOR)

`F3 0F AE` with ModRM `reg=010` (`D0`-`D7`, i.e. `UMONITOR`) killed the
daemon on a **single isolated submission to a fresh daemon**, under either
input state — not the pop-fs/gs class (not NULL-deref: reproduces under
`scratch_v1`) and not the Debian-SIGBUS class (not accumulation: it's the
very first job). Same failure signature as both prior bugs though: raw,
uncaught signal (`SIGSEGV` this time, return code `-11`) that bypasses
`signals.c`'s own handler entirely. Fixed in `blacklist.c` by tracking
whether `F3` specifically was the prefix seen (not just "some legacy
prefix") and refusing `mod=11, reg=010` under it; the unprefixed and
`66`-prefixed forms of the same ModRM byte are left alone (already swept
safely). Regression-tested both directions
(`test_blacklist_refuses_umonitor_execute`). Full writeup in
`docs/safety.md`.

## Confirmed: scalar AES-NI and PCLMULQDQ are universal across the fleet

`AESENC`/`AESDEC`/`AESENCLAST`/`AESDECLAST`/`AESIMC` (`66 0F 38
DB`-`DF`) and `PCLMULQDQ` (`66 0F 3A 44`) show `GP_OR_PF` under
`zero_v1` on **all six machines** — and flip to clean execution (`NONE`)
under `scratch_v1` on all six, confirming this was the familiar
NULL-deref artifact, not a feature gap. Scalar AES-NI and PCLMULQDQ have
been present on every machine in this fleet since 2012 (Sandy Bridge-EP).
This is the universal baseline the next result contrasts against.

## New: vectorized AES-NI/PCLMULQDQ (VAES/VPCLMULQDQ) is Tiger-Lake-only, confirmed two ways

`VAESENC` at VEX.256 width (`C4 E2 7D DC`, prefix bytes extracted via
`gcc -mavx2`) and `VPCLMULQDQ` at VEX.256 (`C4 E3 7D 44`): `GP_OR_PF`
under `zero_v1` on lily/debian, flipping to `NONE` under `scratch_v1` on
exactly those two; `UD` under both states on the other four, confirming
real feature absence, not NULL-deref, on those four. This reproduces the
EVEX/AVX-512 `vaesenc zmm` result (already in the report) through an
entirely different encoding path (VEX, not EVEX), on the same two
machines. A workload assuming wide AES-GCM throughput from "AES-NI is
present" (true on 6/6 machines) would be silently wrong about 4/6
machines the moment it tries the vectorized path, and the SDM alone
cannot tell a program which 2 it's running on.

## New: RDRAND/RDSEED generational boundary pinned exactly, with imac as the dividing machine

Full Group 9 (`0F C7`) sweep: RDRAND (`reg=6`) is `NONE` on 5/6 machines,
`UD` only on z420 (Sandy Bridge-EP, 2012 — RDRAND shipped in Ivy Bridge,
2012, just after). RDSEED (`reg=7`) is `NONE` on 4/6, `UD` on z420 **and
imac** (Haswell, 2013 — RDSEED shipped in Broadwell, 2014). imac has
RDRAND but not RDSEED, landing exactly between the two features'
real introduction dates. Directly security-relevant: both instructions
feed cryptographic key and nonce generation, and this is the clearest
single result in the sweep for showing a *fine-grained*, dated
generational boundary rather than a single binary split.

## New: PKU (RDPKRU/WRPKRU) detected, and the method validates its own correctness in the process

Full Group 7 sweep: `RDPKRU`/`WRPKRU` (`0F 01 EE`/`EF`) execute cleanly
under `zero_v1` (`ECX=0`) on lily/debian only (`UD` on the other four) —
Memory Protection Keys, present only on the two Tiger Lake machines,
matching `/proc/cpuinfo`'s `pku`/`ospke` flags exactly. Under
`scratch_v1`, the *same* instructions on lily/debian flip to `GP_OR_PF`
— not a bug: the SDM requires `ECX=0` for `RDPKRU`/`WRPKRU` or `#GP(0)`,
and `scratch_v1` deliberately sets every GPR, including `RCX`, to a
non-zero pointer. The dual-state design built to resolve Sweep 1's
`GP_OR_PF` ambiguity turns out to double as a check that the harness
reproduces a documented operand-validity rule correctly, not just
feature presence.

## New: a generational CLFLUSHOPT/CLWB-adjacent split, and a clean negative control (WAITPKG)

The `66`-prefixed Group 15 sweep shows one ModRM region (`B8`/`B9`)
present on lily/debian/fuzzarch/d153-system (Kaby Lake-R and newer) and
`UD` on z420/imac (Haswell and older) — consistent with CLFLUSHOPT's real
Broadwell-era introduction. By contrast, the `F2`-prefixed sweep
(UMWAIT/TPAUSE/WAITPKG territory) is `UD` on **all six machines without
exception**, including both Tiger Lake boxes — a clean universal-absence
result that shows the method isn't manufacturing a split out of every
instruction it touches; WAITPKG genuinely isn't present anywhere in this
fleet.

## New: a broad decoder-permissiveness shift in Group 7's reserved space

213 of Group 7's 256 ModRM forms are `GP_OR_PF` on all five newer
machines and `UD` on z420 alone. This is reported at the aggregate level,
not opcode-by-opcode: it indicates Sandy Bridge-EP's decoder treats most
of this group's undefined encodings as non-existent, where every newer
machine treats the same bytes as existing-but-protected. Not
individually attributed to specific VMX/reserved mnemonics in this pass;
flagged as a concrete follow-up (cross-reference against XED once wired
in, per the report's existing limitations section).

## Confirmed again: gather instructions (Downfall-relevant)

AVX2 legacy-VEX gather (`vpgatherdd`, bytes extracted via `gcc -mavx2`)
executes on every machine with AVX2 (5/6, all but z420); AVX-512 EVEX
gather follows the identical three-tier pattern as every other EVEX
AVX-512 instruction in this report (executes on Tiger Lake, full-length
`#UD` on Kaby Lake-R/Coffee Lake, 2-byte-truncated `#UD` on
pre-EVEX-recognition silicon — now confirmed to include Haswell, not just
Sandy Bridge-EP, via imac).

## Confirmed again: EVEX-recognition boundary postdates Haswell

imac (Haswell) truncates every EVEX-prefixed AVX-512 seed to length 2,
identically to z420 (Sandy Bridge-EP) — the front-end-decoder-level EVEX
recognition gap reported for z420 alone in Sweep 2 is now confirmed on a
second, independent, later (2013 vs 2012) machine, ruling out that it was
a Sandy-Bridge-EP-specific oddity rather than a real pre-EVEX-generation
property.

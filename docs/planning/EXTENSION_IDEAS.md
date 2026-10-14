# Do We Trust Silicon? — Research Plan & Extension Ideas

**Basis:** Christopher Domas, *Breaking the x86 ISA* (Black Hat USA 2017 / DEF CON 25), whitepaper
`31dd6431a3dd0d26814b4ff4d453c20e8d1292eef2f3ec1f777b8e4ee1852d08_domas_breaking_the_x86_isa_wp.pdf`
plus the 2018–2025 follow-on literature.

**Thesis being pursued:** a processor is not a trusted black box. We need systematic,
reproducible tooling to audit silicon the way we audit software.

**Date:** 2026-10-01

---

## Part 0 — What the source paper actually established

Read this section before designing anything; every extension below is defined
relative to a specific limitation of the original method.

### 0.1 The two core techniques

**Tunneling (depth-first search driven by length changes).**
A 15-byte buffer is treated as a candidate instruction. Execute it, observe its
length, then increment the byte *at the observed end* of the instruction. If the
increment changes the observed length or the exception class, re-anchor and
continue from the new end. After a byte position has been incremented 256 times,
back off to the previous byte position.

The effect is that semantically inert bytes — immediates, displacements — are
skipped, because they never change length or fault behavior. The search
concentrates on prefixes, opcodes, and ModRM/operand-selection bytes. This
reduces a worst-case space of **1.3×10^36** 15-byte strings to roughly
**10^8** meaningfully distinct candidates (observed in the paper's scans).

**Page-fault length analysis (the length oracle).**
You cannot disassemble an instruction you do not know, and the naive trap-flag
approach (step, diff RIP) fails on faulting instructions because a faulting
instruction never advances RIP. Domas's solution:

1. Place the candidate so byte 0 sits on the last byte of an **executable** page
   and the remaining bytes lie in a **non-executable** page.
2. Execute. If a `#PF` fires with `CR2` == the page-boundary address, part of the
   instruction still lies in the non-executable page.
3. Slide the instruction back one byte (two bytes now in the executable page) and
   repeat.
4. The first time you *don't* get a boundary `#PF`, the number of bytes resident
   in the executable page **is** the instruction length.

Two properties make this powerful:

- It resolves the length of **non-existent** instructions. `9a13065b8000d7` is
  illegal, but it is 7 bytes long, because that is where the decoder gives up.
  This leaks information about the decoder/pipeline structure and about the shape
  of *future* encodings.
- It resolves the existence of **privileged** instructions from ring 3.
  `#UD` = does not exist. `#GP` = exists, but you lack the privilege. So a
  ring-3 process can enumerate ring 0, hypervisor (ring -1), and SMM (ring -2)
  instruction space without being able to execute any of it.

### 0.2 The survival engineering (underrated)

The fuzzer is fuzzing the CPU it runs on, so most of the work is not finding
instructions, it's not dying:

- **Ring 3 only.** Avoids catastrophic system failure except on genuine hardware bugs.
- **Hook every exception** a generated instruction might raise — on Linux:
  `SIGSEGV`, `SIGILL`, `SIGFPE`, `SIGBUS`, `SIGTRAP`. The handler restores a
  known-good register set and resumes the search where it left off.
- **Zero all registers and map the NULL page.** Zeroed registers make computed
  addresses like `[eax + 4*ecx]` resolve to 0 rather than into live process
  memory. Mapping page 0 is not strictly required, but it lets the injector
  *distinguish* an unprivileged memory access from a privileged register access:
  without it, `mov eax,[ecx+8*edx]` and `mov cr0,eax` both raise `#GP` and look
  identical. With page 0 mapped, the former succeeds and the latter still faults.
- **Displacement safety falls out of tunneling.** Because tunneling only
  perturbs one byte at a time, it explores `inc [0x0000000c]`,
  `inc [0x0000a100]`, `inc [0x00040000]`, `inc [0x08000000]` — but never
  `inc [0x0804a10c]`. It structurally avoids the addresses that would actually
  land in its own `.data`. (The alternative random-generation mode *can* corrupt
  itself; measured at roughly 1 in 4 million for a 32-bit process with 1 KB of
  critical writable data, and only for encodings with a 4-byte displacement.)
- **Blacklist the unrecoverable.** Segment-register loads (`lds`, `les`, `lfs`,
  `lgs`, `lss`, `mov seg`) and syscall entries (`int 0x80`, `int 0x0e`,
  `sysenter`, `syscall`) can corrupt state past what the signal handlers can
  restore.
- **Trap flag for control-flow recovery.** Set TF immediately before executing
  the candidate; the single-step exception hands control back regardless of
  whether the instruction fell through or branched somewhere arbitrary.

### 0.3 Architecture

- **injector** — generates and executes candidates, resolves lengths and faults.
- **sifter** — wraps one or more injectors, uses a disassembler (Capstone, with
  objdump/ndisasm swappable) to *predict* length, and logs divergence.
  - observed length != predicted length → usually a **software** bug (the
    disassembler and the silicon disagree)
  - instruction exists but disassembler doesn't recognize it → usually an
    **undocumented instruction**
  - Classification into software / hardware / hypervisor still requires manual
    analysis.

### 0.4 Results, categorized

**Undocumented instructions.** Tested: Intel Core i7-4650U, Intel Quark SoC
X1000, Intel Pentium, AMD Geode NX1500, AMD C-50, VIA Nano U3500, VIA C7-M,
Transmeta TM5700, plus one undisclosed part.

- i7-4650U (64-bit): `0f0dxx` for reg fields other than `/1` (documented only as
  `prefetchw` for `/1`); `0f18xx` and `0f{1a-1f}xx` (roughly half undocumented
  until SDM revision -061, Dec 2016, though executing since at least Ivy
  Bridge — now spec'd as reserved NOPs); `0fae{e9-ef, f1-f7, f9-ff}`
  (undocumented until -051, June 2014, for nonzero r/m); `dbe0`, `dbe1`;
  `df{c0-c7}`; `f1`; `{c0-c1, d0-d1, d2-d3}{30-37, 70-77, b0-b7, f0-f7}`
  (suspected SAL aliases); `f6 /1`, `f7 /1` (suspected `/0` aliases).
- AMD Geode NX1500: `0f0f{40-7f}{80-ff}xx` in the 3DNow! range; `dbe0`, `dbe1`;
  `df{c0-c7}`.
- VIA Nano U3500 / C7-M: `0fa7{c1-c7}` in the PadLock range but absent from the
  PadLock reference; the Intel-undocumented set above; `dbe0`/`dbe1` and
  `df{c0-c7}` absent from *all* Intel, AMD and VIA documentation.

**The best software bug.** In 64-bit mode, `66 e9` (`jmp`) and `66 e8` (`call`):
Intel silicon **ignores** the `66` operand-size override and consumes a 4-byte
operand. IDA, QEMU, gdb, objdump, valgrind, Visual Studio and Capstone all
parse it differently than it executes. AMD honors the prefix (2-byte operand),
which is the likely origin of the confusion. The practical consequence Domas
highlights: when a tool mis-measures an instruction's length, its parse of the
entire following instruction stream desynchronizes from what the CPU executes.
Any analysis engine (AV, sandbox, emulator) that cannot faithfully reproduce the
ISA can therefore be shown a different program than the one that actually runs —
which is exactly why faithful, testable ISA models matter.

**Hypervisor flaw.** On a rented 20-core Azure instance: if TF is set across a
`cpuid`, the hypervisor emulates the (vmexit-causing) `cpuid` but forgets to
re-check TF, so the single-step exception is never delivered to the guest. Not a
security issue; a good illustration of how hard faithful x86 emulation is.

**Hardware errata.**
- Intel Pentium: rediscovered **f00f** (`lock cmpxchg8b eax` → total lock).
- AMD: some parts deliver `#UD` *before* completing the instruction fetch, though
  the spec says a fetch `#PF` supersedes `#UD`. AMD relaxed the March 2017
  APM to permit this — apparently concurrently with this research.
- Transmeta TM5700: 4-byte forms of `0f71`/`0f72`/`0f73` deliver `#MF` after only
  3 bytes are fetched when an FP exception is pending, even though the 4th byte
  is on an unmapped page (`#PF` would be correct).
- Undisclosed part: a **halt-and-catch-fire** instruction, executable from an
  unprivileged ring-3 process, locking the processor completely. Verified across
  three Linux and two Windows kernels, corroborated with serial kernel debugging
  and interrupt hooks. Unnamed at publication pending disclosure. This is the
  real risk class: unprivileged local denial-of-service against any
  shared/multi-tenant system.

---

## Part 1 — State of the art since 2017

What has already been done. Do not re-do these.

| Year | Work | Contribution | Why it matters to us |
|---|---|---|---|
| 2018 | Domas, *Continuing to Break the x86 Instruction Set* (Shakacon X) | extended scans, sandsifter follow-up | the direct sequel; check what he already covered |
| 2018 | Domas, **project:rosenbridge** (BH USA) | `0f 3f` on VIA C3 launches a hidden RISC coprocessor executing at ring 0 → ring-3→ring-0 escalation | the **only** demonstrated x86 hardware backdoor; and it was *not* found by opcode scanning. Disputed (referenced in VIA docs since 2004). Removed after C3. |
| 2018 | Cattius (Bristol), *Undocumented CPU Behavior* + **opcodetester** | moves past *existence* into *behavior*; kernel-mode testing; semantic triage; later RISC-V + SiFive Freedom Metal | the first attack on sandsifter's central weakness |
| 2019 | **UISFuzz** (IEEE Access) | ~5× faster than sandsifter: automatic instruction-format recognition, expert-knowledge DB for false-positive suppression, better result analysis | search-efficiency ceiling |
| 2020 | **iScanU** | ports the approach to ARMv8 and RISC-V; full 32-bit ISA scan in under a day; found QEMU/disassembler inconsistencies and an undocumented RISC-V instruction | cross-ISA generalization is taken |
| 2021 | **SiliFuzz** (Google) | fleet-scale fuzzing via proxy to find *individual defective cores* | reframes the target: not the ISA, the specific die |
| 2023 | Ermolov / Sklyarov / Goryachy (J. Comp. Virol. Hacking Tech.) | Red Unlock on Intel Atom → undocumented `udbgrd` / `udbgwr`, giving software read/write of CRBUS and LDAT, incl. microcode RAM | hidden instructions that *actually* grant microarchitectural god-mode |
| 2023 | **CustomProcessingUnit** (WOOT) | Intel microcode reverse engineering and patching (Goldmont) | makes the microcode layer a tractable research surface |
| 2024 | **libLISA** (OOPSLA) | no human disassembler in the loop at all: discovers instructions **and synthesizes their semantics**, per-CPU, including behavior the SDM calls "undefined". 118,000+ instruction groups; largest formal x86-64 model to date; exposed bugs in hand-written models. Rust, maintained. | **this is the new baseline. Build on it, not on sandsifter.** |
| 2025 | **Fuzzilicon** | post-silicon x86 fuzzing with µcode-patch instrumentation for genuine internal coverage feedback; 2 new µcode-level speculative-execution bugs on Goldmont (N3350) | shows the microcode layer yields real vulnerabilities |

Adjacent tooling worth adopting: **uops.info** and **nanoBench** (port
assignment, latency, µop decomposition — semantics below the ISA), and
**Intel XED** as ground truth in place of Capstone.

---

## Part 2 — Calibrating the original idea

The framing — *audit the x86 ISA across Intel generations for instructions the
silicon has but the manual doesn't* — is the paper's own thesis, and is the
right instinct. But as a standalone project in 2026 it is the weakest link in
the chain, for four reasons:

1. **"Undocumented" is empirically boring.** Nearly every find is a redundant
   ModRM alias, a reserved NOP placeholding a future extension, an ignored
   prefix bit, or a vendor extension documented elsewhere (3DNow!, PadLock).
   Zero backdoors were found on Intel. The one real backdoor in a decade was on
   a 2001-era VIA part and was found by analyzing MSR-gated coprocessor state,
   not by scanning opcode space.
2. **The oracle is length + fault class, and nothing else.** It is structurally
   blind to any hidden instruction whose length and exception signature matches
   its neighbors — which is most of them. And "it exists" says nothing about
   what it *does*. libLISA exists precisely because this ceiling is low.
3. **Intel already ran this play.** SDM -051 and -061 documented several of
   Domas's finds, and post-2017 Intel treats reserved-NOP space as a spec'd
   concept. Rescanning Haswell→Raptor Lake for `#UD`-vs-Capstone divergence
   will mostly regenerate his table.
4. **Practical friction.** sandsifter is Python 2 and unmaintained. You would
   spend the first month porting rather than researching.

**Reframe, keep the thesis.** The interesting question is no longer *"is there
an instruction at these bytes?"* It is:

> Does this silicon do what the spec, its sibling core, its previous microcode
> revision, or its emulator says it does?

Move the **oracle** (from length/fault to semantics) and move the **axis of
comparison** (from silicon-vs-manual to silicon-vs-silicon,
silicon-vs-itself-after-µcode-update, and silicon-vs-emulator). Those axes did
not exist, or were not reachable, in 2017.

---

## Part 3 — Extension ideas

Each idea: the gap, the method, the deliverable, cost, and risk.

### Tier 1 — genuinely open, and cheap enough to start now

---

#### Idea 1 — The microcode axis: does a µcode update silently change the ISA?

**Gap.** Nobody has systematically asked whether a microcode update alters the
*decode or fault behavior* of the instruction set. We know µcode has removed
features (TSX deprecation, SGX deprecation on client parts) and changed
instruction behavior (the Downfall/GDS mitigation altering `gather`; LFENCE
serialization changes). No one has measured the full-ISA delta across revisions.

**Method.**
1. Define a **behavioral fingerprint**: for a fixed corpus of encodings (from
   libLISA's instruction-group enumeration), record observed length, fault
   class, and — where safely executable — output register/flag/memory state
   from a fixed input state.
2. Collect every public µcode revision for one target part (Intel's
   `microcode-20xx` releases; use `iucode-tool` to extract per-revision blobs).
3. Use **late loading** (`/sys/devices/system/cpu/microcode/reload`) to iterate
   revisions without a reboot; fall back to an early-load initrd where late
   loading is refused (it often is, for revisions that change feature bits — so
   budget for reboot-per-revision on at least some).
4. Diff fingerprints pairwise across the revision chain.

**Deliverables.**
- An **ISA-drift-by-microcode-revision** database: which encodings changed
  behavior, when, and whether the change is documented in any errata sheet.
- A corollary defensive tool: **µcode tamper / provenance detection** — a
  behavioral fingerprint that can say *"this CPU's microcode does not behave
  like the revision it reports."* That is the "do we trust silicon" thesis with
  a directly defensive payoff, and it does not require breaking Red Unlock.

**Cost.** Low. One or two machines, a scriptable µcode reload loop, patience.
**Risk.** Low. Watch for bricking via early-load misconfiguration — keep a
known-good initrd and a recovery USB. Some revisions will refuse late load;
treat that as data, not failure.
**Novelty.** High. Everyone studies µcode *contents* (CustomProcessingUnit,
Fuzzilicon); nobody studies µcode-induced *ISA-surface drift* systematically.

---

#### Idea 2 — Hybrid-core asymmetry: do P-cores and E-cores agree on the ISA?

**Gap.** From Alder Lake onward Intel ships two microarchitectures in one
package with genuinely different internal ISA support — the canonical case
being AVX-512 present but fused off on early ADL P-cores, because the E-cores
lack it and the scheduler cannot migrate a thread mid-`zmm`. This axis simply
did not exist in 2017. Nobody has published a full-ISA differential between
core types on the same die.

**Method.**
1. Pin the injector to a specific core with `sched_setaffinity` / `taskset`,
   and verify core type via `CPUID.1A` (hybrid leaf: Core vs Atom) rather than
   trusting the CPU number.
2. Run the identical corpus on each core type; diff length, fault class, fault
   *precedence*, undefined-flag results, and reserved-bit handling.
3. Extend across generations: Alder Lake, Raptor Lake, Meteor Lake (which adds
   the low-power-island E-cores — a *third* class), Arrow Lake / Lunar Lake.
   Include AMD's analogous Zen4c / Zen5c dense cores for a second vendor.

**Questions worth answering.**
- Do the two decoders agree on reserved prefix / EVEX-bit handling?
- Do they agree on exception *precedence* (the class of bug Domas found on AMD
  and Transmeta)?
- Do "undefined" flag results after e.g. `bsf` / `bsr` / shifts with zero count
  differ? If so, any program that observes them is non-deterministic under
  migration.
- Can a difference serve as a **core-identity oracle** — letting userspace
  determine which core type it is on, or detect a migration, without CPUID?

**Deliverables.** A P/E-core ISA divergence report; any find is simultaneously
an OS/scheduler correctness concern and a fingerprinting oracle. Plus a small
`core_type_oracle` proof of concept.

**Cost.** Low — one modern hybrid laptop/desktop.
**Risk.** Low.
**Novelty.** High, and it is the most defensible "new since the paper" angle.

---

#### Idea 3 — Emulator/translator fidelity: silicon-vs-emulation divergence

**Gap.** The paper's most impactful result was a disassembler/emulator
*divergence* — the silicon and the tool disagreed about an instruction. Since
2017, x86 emulation and binary translation have become load-bearing production
infrastructure: **Apple Rosetta 2**, **Microsoft Prism** (Windows on ARM),
**FEX-Emu**, **box64**, and QEMU TCG. Each is a large, under-audited x86
implementation, and any place one disagrees with real silicon is a correctness
bug with the same security significance Domas described for disassemblers.

**Method.**
1. Build a differential-testing harness: the same encoding corpus, executed on
   (a) real Intel silicon, (b) real AMD silicon, (c) each emulator/translator.
2. Oracles, in increasing strength:
   - observed instruction length (sandsifter's oracle — still catches the
     `66 e9` class);
   - fault class and fault ordering;
   - full output-state diff from a fixed input state (libLISA-style).
3. Record every point of disagreement as a correctness finding, with a minimal
   reproducer, and report it to the relevant project.

**Framing / scope.** This is a *fidelity-testing* project: the deliverable is a
divergence catalogue and upstream bug reports, not a toolkit for defeating any
particular sandbox. Divergences do have security implications (the paper spells
them out for AV and sandboxing), and those implications are worth stating in the
write-up — but the work product is the differential test suite and the fixes it
drives.

**Deliverables.** A cross-emulator x86 fidelity report; a reusable differential
harness; upstream bug reports to FEX/box64/QEMU (and responsible disclosure to
Apple/Microsoft for the closed translators).

**Cost.** Low–medium — one x86 box plus one Apple-silicon and/or Windows-on-ARM
machine.
**Risk.** Low. Handle closed-vendor findings via coordinated disclosure.
**Novelty.** High for the modern translators; QEMU has been fuzzed before, the
ARM-translation layers much less so.

---

### Tier 2 — high value, higher cost

---

#### Idea 4 — Escape ring 3: actually execute the privileged space

**Gap.** The paper *infers* ring-0 / hypervisor / SMM instructions from `#GP`
vs `#UD`, but can never execute them, so it can never say what they *do*.

**Method.**
1. Run the injector inside a minimal kernel module / unikernel, or as a
   bare-metal-style KVM guest, so privileged and VMX-context instructions
   actually execute and MSR / CR side effects can be observed.
2. Add a **dual-machine watchdog**: an external board (or a second host driving
   power/serial) that detects a lockup and triggers PXE auto-reboot, so
   HCF-class hangs are caught and catalogued automatically rather than by hand.
3. Snapshot-and-restore full architectural state around each candidate.

**Deliverables.** Behavioral characterization of privileged/undocumented
encodings the 2017 method could only *detect*; an automated HCF/lockup harness.

**Cost.** Medium–high (hardware watchdog, sacrificial machines, careful kernel
work).
**Risk.** Medium. Real chance of hangs, filesystem corruption, and hardware
wear. Isolate the lab; expect to lose machines.

---

#### Idea 5 — State-gated decode search (Rosenbridge, generalized)

**Gap.** A hidden instruction may not exist unconditionally — it may only decode
*after* some MSR / control-register / µcode state is set (this is exactly the
shape of the VIA C3 backdoor and of Red Unlock). Pure opcode scanning cannot
find these, because in the default state they are just `#UD`.

**Method.** Search the **cross product** of (state-change space × instruction
space): systematically set candidate MSRs / control bits, then re-run a
reference opcode sweep and look for encodings whose `#UD` map *changed*. In
other words, hunt for **feature-unlock state** rather than for opcodes directly.
Seed the MSR search with known debug/unlock MSRs from the Ermolov et al. and
CustomProcessingUnit work.

**Deliverables.** An automated hunt for state-gated / unlockable instruction
surface — the only method class that has ever found a real x86 backdoor, and one
that has never been automated or run at scale.

**Cost.** High. Requires the ring-0 harness from Idea 4; writing arbitrary MSRs
is itself dangerous.
**Risk.** High — arbitrary MSR writes can brick or hang parts. Strong candidate
for the most *interesting* result and the most *destroyed hardware*.
**Novelty.** Very high. This is the most faithful realization of your
"do we trust silicon / find the backdoor" instinct.

---

#### Idea 6 — Measure the false-negative rate (ground-truth evaluation)

**Gap.** A genuine hole in this entire literature: nobody knows what *fraction*
of a real ISA these scanners miss, because there is no ground truth for Intel
silicon. Every paper reports what it found, none report recall.

**Method.** Run the scanners against cores where RTL/ground truth *does* exist —
open RISC-V cores (CVA6, Rocket, XuanTie) and the open x86-compatible `ao486` —
and compute the actual recall of tunneling vs. libLISA vs. random generation
against the known decode table.

**Deliverables.** A methodology/evaluation paper quantifying scanner recall and
where each technique is blind. Unglamorous; would be cited by everyone in the
Part 1 table.

**Cost.** Medium (FPGA or simulation of the open cores).
**Risk.** Low.
**Novelty.** High — it is the missing rigor in the field.

---

### Tier 3 — good side deliverables

---

#### Idea 7 — Automated documentation-drift tracker

Diff a machine-readable ISA model (libLISA output + Intel XED tables) against
each new SDM / APM release, and publish a running changelog of "silently
documented" and "silently removed" encodings — the phenomenon Domas noted with
SDM -051 and -061. Low effort, permanently useful, builds credibility, and it
directly documents the manual-vs-silicon gap that motivates the whole project.

**Cost.** Low. **Risk.** None. **Novelty.** Medium (useful more than novel).

---

#### Idea 8 — Behavioral CPU fingerprinting for provenance

Use behavioral ISA fingerprints (from Ideas 1–2's machinery) to identify a part
independent of what it *claims* to be: catch remarked/counterfeit CPUs,
distinguish Zhaoxin/VIA/Intel lineage, or detect a cloud VM whose CPUID
misrepresents the underlying silicon. A straightforward supply-chain /
trusted-computing story that reuses infrastructure you already built.

**Cost.** Low (piggybacks on Ideas 1–2). **Risk.** Low. **Novelty.** Medium–high.

---

## Part 4 — Recommendation

- **Do not start from sandsifter.** Port nothing. **Start from libLISA**
  (maintained, Rust, gives you semantics for free) and use **Intel XED** as
  ground truth instead of Capstone.
- **Near-term paper:** Idea 1 (microcode-revision drift) + Idea 3 (emulator
  fidelity). Both are measurable on hardware you already own, both are new since
  2017, both have clean defensive framings.
- **Ambitious thread underneath:** Idea 5 (state-gated decode search) — the
  honest realization of the "find the silicon backdoor" idea — supported by the
  ring-0 harness from Idea 4.
- **Free credibility builders:** Ideas 6 and 7.

### Cautions

- HCF- and DoS-class findings, and any closed-vendor emulator/silicon bugs,
  require **coordinated disclosure**. Build the disclosure plan before you scan.
- Fleet-scale scanning on rented cloud instances can brush against provider
  terms of service — note that Domas found the Azure hypervisor bug doing
  exactly that. Prefer owned hardware for the aggressive work.
- Ideas 4 and 5 will damage hardware. Budget sacrificial machines and isolate
  the lab.

---

## Part 5 — Feasibility with available hardware

**Inventory (as of 2026-10):**

| Machine | CPU | µarch / gen | Year | Notes |
|---|---|---|---|---|
| HP ProBook 450 G5 (Arch, k6.18-lts) | i7-8550U | Kaby Lake-R, 8th gen | 2017 | 4C/8T, 16 GB, **no AVX-512**; 916 GB `/mnt/fuzzdata` scratch disk |
| Dell Latitude 3420 (Debian 13) | i7-1165G7 | Tiger Lake, 11th gen | 2020 | 4C/8T, 16 GB, **has AVX-512** |
| Old Xeon, 32 GB ECC | ~E5 v1/v2 (Sandy/Ivy Bridge-EP) | ~2013 | dedicable; **sacrificial ring-0 / MSR box**; check for IPMI/BMC |

**Two structural advantages of this fleet:**
- A **3-generation Intel spread (2013 → 2017 → 2020)** plus an **AVX-512 vs.
  no-AVX-512** pair — a real cross-generation / cross-feature test bed for the
  original Domas framing and for fingerprinting (Idea 8).
- If the Xeon board has **IPMI/BMC**, remote power-cycle turns HCF/lockup hunting
  (Ideas 4–5) into an *automated* reboot loop. Verify this first; it is the most
  valuable single feature available.

**Built-in calibration target:** both laptops are affected by **Downfall / GDS
(CVE-2022-40982)**, whose Aug-2023 microcode mitigation changes `gather`
behavior. This is a known-answer test for the Idea 1 harness — detect the
documented delta first to prove the harness works, then hunt undocumented side
effects.

**Feasibility map:**

| Idea | Status here | Where / how |
|---|---|---|
| 1 — microcode drift | ✅ **best fit, start here** | ProBook + Latitude; calibrate on Downfall gather delta; `iucode-tool` + `/sys/.../microcode/reload` |
| 2 — hybrid P/E asymmetry | ❌ **blocked** | needs Alder Lake+ (12th gen+); no hybrid CPU in inventory — candidate future purchase |
| 3 — emulator fidelity | ⚠️ **partial** | silicon-vs-QEMU-TCG only; no ARM host → Rosetta 2 / WoA Prism out of scope |
| 4 — ring-0 execution | ✅ | the Xeon is the ideal sacrificial bare-metal box; IPMI = free watchdog |
| 5 — state-gated MSR search | ✅ (Xeon only) | high risk; requires Idea 4 harness; only on the disposable Xeon |
| 6 — false-negative / ground truth | ✅ **simulation-only** | no FPGA; run ao486 / RISC-V under Verilator, Xeon as sim host |
| 7 — doc-drift tracker | ✅ | pure software; any machine |
| 8 — cross-µarch fingerprinting | ✅ | 3 distinct µarches are enough to build + validate fingerprints |

**Summary:** 6 doable (1, 4, 5, 6-sim, 7, 8), 1 partial (3), 1 blocked (2).

**Recommended sequence:**
1. **Now** — Idea 1 on the ProBook, calibrated against the Downfall gather delta
   (also stands up the fingerprint corpus reused by Ideas 7–8).
2. **Parallel** — bring up the Xeon as the bare-metal box (check IPMI) → Idea 4.
3. **Then** — Idea 5 on the Xeon once the ring-0 harness is solid.
4. **Fill / credibility** — Ideas 7, 8, and simulation-only Idea 6.

---

## Appendix — Sources

- Domas, *Breaking the x86 ISA*, whitepaper (BH US-17):
  https://blackhat.com/docs/us-17/thursday/us-17-Domas-Breaking-The-x86-Instruction-Set-wp.pdf
- DEF CON 25 slides:
  https://media.defcon.org/DEF%20CON%2025/DEF%20CON%2025%20presentations/DEF%20CON%2025%20-%20Christopher-Domas-Breaking-The-x86-ISA.pdf
- sandsifter: https://github.com/xoreaxeaxeax/sandsifter
- project:rosenbridge (BH US-18):
  https://i.blackhat.com/us-18/Thu-August-9/us-18-Domas-God-Mode-Unlocked-Hardware-Backdoors-In-x86-CPUs-wp.pdf
- libLISA (OOPSLA'24): https://ssrg.ece.vt.edu/papers/oopsla24.pdf — site: https://liblisa.nl/publications/
- UISFuzz (IEEE Access): https://ieeexplore.ieee.org/document/8863327/
- iScanU: https://scholarlypublications.universiteitleiden.nl/access/item:3620482/download
- opcodetester: https://github.com/cattius/opcodetester
- Undocumented CPU Behaviour on x86 and RISC-V (Cattius thesis): https://www.cattius.com/images/thesis-unsigned.pdf
- Ermolov/Sklyarov/Goryachy, udbgrd/udbgwr: https://link.springer.com/article/10.1007/s11416-022-00438-x
- CustomProcessingUnit (WOOT'23): https://pietroborrello.com/publication/woot23/woot23.pdf
- SiliFuzz: https://arxiv.org/pdf/2110.11519
- Fuzzilicon: https://arxiv.org/pdf/2512.23438
- dustri paper notes: https://dustri.org/b/paper-notes-breaking-the-x86-isa.html

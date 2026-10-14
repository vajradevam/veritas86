# Implementation Plan — "Do We Trust Silicon?"

Companion to `EXTENSION_IDEAS.md`. This is the buildable plan: repo layout,
component designs, data schemas, wire protocols, and a phased build order sized
to the available fleet (ProBook i7-8550U / Latitude i7-1165G7 / sacrificial
Xeon E5).

**Guiding decisions**
- **Build on libLISA + Intel XED, not sandsifter.** sandsifter is Python 2 and
  unmaintained; we reimplement its *injector idea* in modern C and take our
  encoding corpus and semantics from libLISA/XED.
- **One shared spine, many backends.** Every experiment drives the same
  `Injector` interface (submit candidate encoding + input state → result). The
  only thing that changes per experiment is *which backend* executes and *what
  we diff*.
- **Fingerprint is the universal record.** Ideas 1, 2, 6, 8 are all "collect
  fingerprints under condition X, diff against condition Y."
- **Safety is a first-class module,** not an afterthought (ring-3 default,
  blacklist, state restore, sacrificial-only for ring-0/MSR work).

---

## 1. Repository layout

Root stays the current project dir (`break-x862/`). Big/volatile data lives on
the ProBook's `/mnt/fuzzdata` and is git-ignored.

```
break-x862/
├── README.md
├── EXTENSION_IDEAS.md              # (exists) the research rationale
├── IMPLEMENTATION_PLAN.md          # (this file)
├── justfile                        # top-level build/run targets (or Makefile)
├── .gitignore                      # ignores data/, third_party build output
│
├── docs/
│   ├── architecture.md             # the Injector spine + backend model
│   ├── fingerprint-schema.md       # canonical record schema (mirrors §4)
│   ├── injector-protocol.md        # host<->injector wire format (mirrors §3.2)
│   ├── safety.md                   # blacklist, ring rules, preflight
│   └── disclosure-policy.md        # coordinated disclosure before any scan
│
├── core/                           # the shared C engine (the hard part)
│   ├── injector/
│   │   ├── main.c                  # CLI/daemon: read jobs, emit results
│   │   ├── inject.c  inject.h      # execute-one-candidate sandbox
│   │   ├── length.c  length.h      # page-fault length analysis
│   │   ├── state.c   state.h       # arch-state load/capture (GPR/flags/xsave)
│   │   ├── signals.c signals.h     # #DB/#UD/#GP/#PF handlers + recovery
│   │   ├── memmap.c  memmap.h      # exec/guard/scratch/null page layout
│   │   ├── blacklist.c blacklist.h # unrecoverable-encoding filter
│   │   └── proto.h                 # shared job/result structs (see §3.2)
│   ├── libfp/                      # fingerprint (de)serialization, C side
│   │   ├── fp.c  fp.h
│   │   └── json.c  json.h          # or link a vendored json lib
│   └── tests/
│       ├── smoke.c                 # nop / ud2 / rex / 66e9 known-answer tests
│       └── fixtures/
│
├── corpus/                         # candidate-encoding generation
│   ├── tunneling/                  # DFS length-change search (the Domas walk)
│   │   └── tunnel.py
│   ├── xed_enum/                   # XED-driven exhaustive enumeration
│   │   └── enumerate.py
│   ├── liblisa_import/             # pull liblisa instruction groups → corpus
│   │   └── import_groups.py
│   └── seeds/                      # curated encodings for targeted studies
│       ├── gather_family.txt       # vpgather*/vgather* for Idea 1 calibration
│       ├── reserved_nop.txt        # 0f18..0f1f etc.
│       └── paper_regressions.txt   # 66e9, 0f0d, dbe0/dbe1, df c0-c7, ...
│
├── orchestrator/                   # Python driver + analysis
│   ├── pyproject.toml
│   └── tsfuzz/
│       ├── __init__.py
│       ├── backends/
│       │   ├── base.py             # Injector ABC (submit → Result)
│       │   ├── ring3.py            # talks to core/injector binary
│       │   ├── kvm.py              # Idea 4 ring-0-in-guest
│       │   ├── baremetal.py        # Idea 4/5 serial-attached Xeon injector
│       │   ├── qemu.py             # Idea 3 qemu-tcg backend
│       │   └── sim.py              # Idea 6 verilator backend
│       ├── runner.py               # drive a backend over a corpus → store
│       ├── fingerprint.py          # Result → canonical fingerprint record
│       ├── store.py                # parquet + sqlite index
│       ├── diff.py                 # fingerprint-set diff (the core comparison)
│       ├── identity.py             # cpuid / microcode-rev / core-type probe
│       ├── xed.py                  # XED bindings: predicted length + decode
│       └── report.py               # tables + plots
│
├── experiments/                    # one runnable dir per idea
│   ├── idea1_microcode_drift/
│   │   ├── README.md
│   │   ├── fetch_microcode.sh      # clone intel-ucode, iucode-tool extract
│   │   ├── walk_revisions.sh       # reload loop (late) / reboot list (early)
│   │   ├── collect.py              # fingerprint at each revision
│   │   ├── calibrate.py            # KNOWN-ANSWER: cpuid + ARCH_CAP + MCU_OPT_CTRL
│   │   └── analyze.py              # drift diff + report
│   ├── idea3_emulator_fidelity/
│   │   ├── README.md
│   │   └── run_diff.py             # silicon (ring3) vs qemu backend
│   ├── idea4_ring0/
│   │   ├── README.md
│   │   ├── kvm/                    # ring-0 guest injector (see §6)
│   │   └── baremetal/              # bootable Xeon injector (see §7)
│   ├── idea5_state_gated/          # XEON ONLY — MSR-unlock search (see §7)
│   │   ├── README.md
│   │   └── msr_search.py
│   ├── idea6_ground_truth/
│   │   ├── README.md
│   │   ├── cores/                  # ao486 / rocket / cva6 submodule wiring
│   │   ├── verilator_top.cpp
│   │   └── recall.py               # scanner recall vs RTL decode table
│   ├── idea7_doc_drift/            # pure software, no hardware
│   │   ├── README.md
│   │   └── track.py                # diff XED/SDM opcode maps across releases
│   └── idea8_fingerprint/
│       ├── README.md
│       └── classify.py             # µarch identification from fingerprints
│
├── scripts/
│   ├── setup_arch.sh               # ProBook deps
│   ├── setup_debian.sh             # Latitude deps
│   ├── safety_preflight.sh         # asserts environment is safe to scan
│   ├── pin.sh                      # taskset wrapper (core consistency)
│   └── env_probe.sh               # dump cpuid/microcode/msr allowlist state
│
├── third_party/                    # git submodules
│   ├── liblisa/                    # https://github.com/... (rust)
│   ├── xed/                        # intel/xed
│   └── sandsifter/                 # reference only, not built
│
└── data/                           # GIT-IGNORED, symlink → /mnt/fuzzdata
    ├── microcode/                  # extracted per-revision blobs
    ├── fingerprints/{machine}/{ucode_rev}/*.parquet
    ├── corpus/                     # generated candidate sets
    └── reports/
```

---

## 2. The spine: the `Injector` abstraction

Everything routes through one interface. Define it once (Python ABC in
`backends/base.py`, mirrored by the C struct in `core/injector/proto.h`).

```
class Injector(ABC):
    def submit(self, job: Job) -> Result: ...
    def submit_batch(self, jobs: list[Job]) -> list[Result]: ...
    def identity(self) -> Identity: ...     # machine/cpuid/ucode/core
    def close(self): ...
```

- **Job**: `{ encoding: bytes, input_state: State, mode: LENGTH|EXECUTE|BOTH }`
- **Result**: `{ length_observed, fault, cr2_offset, output_state, notes }`
- **State**: 16 GPRs, RFLAGS, and (optional) XMM/YMM/ZMM + mask regs.

Backends:

| Backend | Executes on | Used by | Risk |
|---|---|---|---|
| `Ring3Injector` | native, ring 3 | Ideas 1, 3, 8 (and dev of all) | low |
| `QemuInjector` | qemu-x86_64 TCG | Idea 3 | none |
| `KvmInjector` | ring 0 inside KVM guest | Idea 4 | medium |
| `BaremetalInjector` | ring 0 on the Xeon, serial | Idea 4, 5 | high |
| `SimInjector` | Verilator RTL | Idea 6 | none |

The wins from this design: the tunneling search, the fingerprint store, and the
diff engine are written **once** and reused by every backend. Idea 6's "recall
vs ground truth" is literally `diff(Ring3Injector results, SimInjector results)`.

---

## 3. `core/injector` — the ring-3 engine (Phase 1, the critical path)

Language: **C** (needs precise register control, inline asm, signal/`ucontext`
recovery, `mmap`). ~1500 LOC. This is a modern reimplementation of the
sandsifter injector with **output-state capture added**.

### 3.1 Memory layout (`memmap.c`)

```
mmap a 4-page region (MAP_ANON|MAP_PRIVATE), then mprotect:
  [ exec_page  RWX ]  <- candidate copied here
  [ guard_page NONE]  <- PROT_NONE, forces #PF for length analysis
  [ scratch    RW  ]  <- zeroed target for benign memory ops
optionally map the NULL page (page 0, RW):
  requires `sysctl vm.mmap_min_addr=0`; lets us distinguish an unprivileged
  memory access (succeeds) from a privileged reg access (#GP) — the exact
  disambiguation the paper needs. Degrade gracefully if unavailable.
```

Guarantee `exec_page` and `guard_page` are adjacent (single mmap + split
mprotect). Keep the region far from the injector's own `.data`.

### 3.2 Job/result wire protocol (`proto.h`, mirrored in `docs/injector-protocol.md`)

The injector runs as a long-lived child; the Python `Ring3Injector` speaks a
fixed-size binary struct over a pipe (fast, no per-instruction fork):

```
struct job {
  uint8_t  enc[15]; uint8_t enc_len;
  uint8_t  mode;              // 1=length 2=execute 3=both
  uint64_t gpr[16]; uint64_t rflags;
  uint8_t  xsave[XSAVE_SZ];   // optional, when vector state matters
};
struct result {
  uint8_t  length; uint8_t valid_length;
  uint32_t fault;            // 0=none, else signo | (si_code<<8)
  uint64_t cr2_off;          // fault addr - exec_page base
  uint64_t gpr[16]; uint64_t rflags;
  uint8_t  xsave[XSAVE_SZ];
  uint64_t changed_mask;     // which GPRs changed (fast diff)
};
```

### 3.3 Execute-one-candidate (`inject.c` + `signals.c`)

Per job:
1. Install handlers for `SIGTRAP` (single-step OK), `SIGSEGV`, `SIGILL`,
   `SIGFPE`, `SIGBUS` on an `altstack` (`sigaltstack`, so a faulting `%rsp`
   can't break the handler).
2. Copy `enc` into place (straddling the guard boundary in LENGTH mode; fully in
   exec_page in EXECUTE mode).
3. Load `input_state` into registers; set **TF** in RFLAGS.
4. `jmp` to the instruction.
5. Handler fires: read `signo` + `si_addr` (→ `cr2_off`) + the **saved register
   file from `ucontext_t->uc_mcontext`** (this is the post-execution state for a
   successful single-step, or the faulting state otherwise). Copy out to
   `result`. Restore known-good state. `setcontext`/`siglongjmp` back to the
   loop.

Fault classification:
- `SIGILL` → `#UD` → *encoding does not exist here*.
- `SIGSEGV` with `si_addr == guard boundary` → fetch crossed into guard page
  (length signal).
- `SIGSEGV`/`si_code` else, `SIGBUS`, `SIGFPE` → *exists, faulted for another
  reason* (privilege / alignment / FP).
- `SIGTRAP` → *executed successfully*; `output_state` is meaningful.

### 3.4 Length analysis (`length.c`)

The page-fault slide from the paper: start with `enc[0]` on the last byte of
`exec_page`; execute; if `#PF` at boundary, shift the copy back one byte and
retry; first non-boundary result → length = bytes resident in `exec_page`.
Works for non-existent and privileged encodings alike.

### 3.5 Safety (`blacklist.c`, `docs/safety.md`)

- Refuse to *execute* (still allow length analysis of) the unrecoverable set:
  segment loads `lds/les/lfs/lgs/lss/mov Sreg`, and `int 0x80/int 0x0e/
  sysenter/syscall`. Match on decoded form via XED before EXECUTE mode.
- Zero all registers by default so `[base+scale*idx]` resolves into scratch/NULL.
- Ring 3 only in this engine. Ring-0 work is a *separate* backend on the
  sacrificial box only.

### 3.6 Milestone / known-answer smoke test (`core/tests/smoke.c`)

Ship these before trusting any scan. Assert against XED:
- `90` → len 1, executes, no state change.
- `0f0b` (ud2) → len 2, `#UD`.
- `40` (REX) alone → decoder behavior matches XED.
- **`66 e9 00 00 00 00`** → observed length **6** on Intel (prefix ignored),
  reproducing the paper's headline divergence vs a `66`-honoring disassembler.
- `f4` (hlt) from ring 3 → `#GP`, not `#UD` (privileged-detection check).

If these five pass, the engine is trustworthy enough to scan.

---

## 4. Fingerprint record & store (Phase 2)

Canonical record (`fingerprint.py`, schema doc in `docs/fingerprint-schema.md`).
One row per (encoding, input-state-id):

```jsonc
{
  "enc": "0f0dc0",
  "input_state_id": "zero_v1",     // named, reproducible input state
  "length": 3,
  "valid_length": true,
  "fault": "UD|GP|PF|FP|BP|none",
  "cr2_off": null,
  "out_gpr_delta": {"rax": "0x0"},  // only changed regs
  "out_flags_delta": "0x44",
  "xed_len": 3,                     // predicted, for divergence flagging
  "xed_iform": "PREFETCHW_...",     // or null if XED rejects
  "diverges": false                 // length/existence mismatch vs XED
}
```

Environment/identity is stored **once per collection run** (not per row) via
`identity.py`:

```jsonc
{
  "machine": "probook-8550u",
  "cpuid_sig": "0x806ea", "cpuid_leaves_hash": "...",
  "microcode_rev": "0xf4",          // MSR 0x8B / /sys .../microcode/version
  "arch_capabilities": "0x...",     // MSR 0x10A
  "mcu_opt_ctrl": "0x...",          // MSR 0x123 (may be #GP pre-update)
  "core_type": "core",              // "core"/"atom" via CPUID.1A (all "core" here)
  "core_id": 2, "ts": "..."
}
```

Store: **parquet** files under `data/fingerprints/{machine}/{ucode_rev}/`, plus
a **sqlite** index of runs for quick selection. `diff.py` loads two runs and
emits: encodings that changed length, changed fault class, appeared/disappeared,
or changed output-state — the atom every comparison experiment consumes.

---

## 5. Idea 1 — microcode drift (Phase 3, first real result)

Runnable in `experiments/idea1_microcode_drift/`.

**Known-answer calibration first (`calibrate.py`).** The architectural signal of
a microcode update is *not* a change in `gather`'s register output (GDS/Downfall
is a transient-execution fix). It is the **feature/MSR surface**:
- `cpuid` leaf deltas,
- `IA32_ARCH_CAPABILITIES` (MSR `0x10A`) new bits,
- new controls such as `IA32_MCU_OPT_CTRL` (`0x123`) — may `#GP` before the
  update and read cleanly after,
- `microcode_rev` (MSR `0x8B` / sysfs).

Detect that delta across the pre-/post-Downfall revision on the 8550U to prove
the harness sees a real, documented change. *Then* the research question:

**Research scan (`collect.py` + `analyze.py`).** Does the microcode update change
**decode length or fault class** for any encoding? Run the full corpus
fingerprint at each revision and `diff.py` consecutive revisions.

**Revision walk (`walk_revisions.sh`).**
- `fetch_microcode.sh`: clone `intel-ucode`, `iucode_tool -l` to list, extract
  per-revision blobs for this CPUID into `data/microcode/`.
- **Late load** (no reboot): `echo 1 > /sys/devices/system/cpu/microcode/reload`
  after staging a blob — works for *forward* steps the kernel accepts.
- **Backward / feature-changing** revisions: kernel refuses late load; fall back
  to early-load via initramfs + reboot. `walk_revisions.sh` emits the reboot
  schedule and resumes collection after each boot (checkpoint in sqlite).

Deliverable: an ISA-drift-by-µcode-revision table + the µcode-provenance
detector corollary (a fingerprint that flags "this CPU doesn't behave like the
revision it reports").

**Hardware:** ProBook + Latitude. No risk beyond keeping a known-good initramfs.

---

## 6. Idea 4 — ring-0 execution, KVM first (Phase 5)

`experiments/idea4_ring0/kvm/`. Run the injector as **ring-0 code inside a KVM
guest** so privileged encodings actually execute while the host stays safe.

- A minimal guest image: injector compiled freestanding, entered at ring 0, no
  OS. Host uses `/dev/kvm` (or a small rust/C VMM) to set up the vCPU, map the
  guest exec/guard pages, and single-step.
- Faults become **vmexits**; the host reads exit reason + guest register file —
  same `Result` struct, new backend (`KvmInjector`).
- Hangs → host kills the vCPU after a timeout (the watchdog KVM gives you for
  free). This is the automated recovery the paper lacked.

Caveat to document: VT-x virtualizes/synthesizes some behavior, so KVM results
are ring-0-under-virtualization, not identical to bare metal. That's why §7
exists.

**Hardware:** any of the three (do it on the Latitude/ProBook; keep the Xeon for
§7).

---

## 7. Ideas 4 (bare metal) + 5 (MSR search) — the Xeon (Phases 6–7)

`experiments/idea4_ring0/baremetal/` and `experiments/idea5_state_gated/`.
**Sacrificial Xeon only.**

**Bootable injector.** A tiny bootable image (Limine/multiboot) that runs the
injector at ring 0 on bare metal and logs `Result`s over **serial**; the
controller (ProBook) reads the serial log = `BaremetalInjector` backend. On
lockup/HCF, **IPMI** (if the board has a BMC — check first, `ipmitool`) power-
cycles automatically; without IPMI, a hardware watchdog timer + auto-boot, else
manual reboot with sqlite checkpointing.

**Idea 5 — state-gated / MSR-unlock search (`msr_search.py`).** The honest
"is there hidden unlockable surface?" experiment: iterate candidate MSR writes,
re-run a reference opcode sweep after each, and flag any encoding whose `#UD`
map *changed* — i.e. hunt for feature-unlock **state**, not opcodes. Seed the
MSR list from the Ermolov et al. debug MSRs and CustomProcessingUnit. This is
the most destructive experiment (arbitrary MSR writes brick/hang parts) — hence
Xeon-only, checkpoint every write, expect to lose the board.

**Prerequisite:** the KVM harness (§6) must be solid first; the bare-metal
injector is the same code without the VMM safety net.

---

## 8. Ideas 3, 6, 7, 8 — the cheaper tracks

- **Idea 3 (`QemuInjector`, Phase 7).** Same corpus through `qemu-x86_64` TCG
  vs `Ring3Injector` on silicon; `diff.py` flags divergences (length, fault,
  output-state). Deliverable = divergence catalogue + upstream bug reports to
  QEMU/FEX/box64. (No ARM host → Rosetta/Prism out of scope, as noted in
  `EXTENSION_IDEAS.md` Part 5.)
- **Idea 6 (`SimInjector`, Phase 7).** Wrap `ao486` / a RISC-V core (Rocket or
  CVA6) in Verilator behind the `Injector` interface; `recall.py` computes what
  fraction of the RTL's real decode table each scanner (tunneling / XED-enum /
  random) recovers. The Xeon's cores + ECC make it the sim host. No hardware
  risk.
- **Idea 7 (`track.py`, Phase 4, do anytime).** Pure software: diff XED tables /
  SDM-derived opcode maps across releases → changelog of silently
  added/removed encodings. No injector, no hardware.
- **Idea 8 (`classify.py`, falls out of Phase 2).** Train/validate a µarch
  identifier on fingerprints from all three machines; also the counterfeit /
  provenance detector. Pure analysis over collected fingerprint data.

---

## 9. Build order (code, not experiments)

| Phase | Build | Unlocks | Machine |
|---|---|---|---|
| 0 | repo scaffold, submodules (liblisa/xed), `justfile`, `safety_preflight.sh` | everything | any |
| 1 | `core/injector` + `smoke.c` (§3.6 must pass) | the spine | ProBook |
| 2 | `orchestrator` runner + fingerprint + store + diff + xed + identity | Ideas 8, and corpus infra | ProBook |
| 3 | `corpus/` (tunneling + xed_enum + liblisa_import) + Idea 1 | **first result** | ProBook + Latitude |
| 4 | Idea 7 doc-drift (independent, easy win) | credibility builder | any |
| 5 | `KvmInjector` + Idea 4 (KVM) | ring-0, safely | Latitude/ProBook |
| 6 | `BaremetalInjector` on the Xeon (IPMI/serial) | true ring-0 | Xeon |
| 7 | Idea 5 (MSR search), `QemuInjector` (Idea 3), `SimInjector` (Idea 6) | ambitious + cheap tracks | Xeon / any |

**Idea 2 (hybrid P/E) is not in this plan** — no hybrid silicon in the fleet;
revisit if a 12th-gen-or-later box is acquired.

---

## 10. First week, concretely

1. `scripts/setup_arch.sh` on the ProBook: `base-devel`, `nasm`, `python`,
   `iucode-tool`, `msr-tools`, XED build deps; `modprobe msr`; note whether
   `vm.mmap_min_addr=0` is acceptable on this box.
2. Wire `third_party/xed` and `third_party/liblisa` as submodules; get XED
   building and Python-callable (`orchestrator/tsfuzz/xed.py`).
3. Write `core/injector` LENGTH+EXECUTE modes for GPR/flags only (defer vector
   XSAVE to v2). Make the five smoke tests (§3.6) pass — especially `66 e9`.
4. `experiments/idea1_microcode_drift/calibrate.py`: read `cpuid` +
   `IA32_ARCH_CAPABILITIES` + `microcode_rev`, `iucode_tool` to stage the
   pre-/post-Downfall blob, `reload`, re-read. Confirm the known-answer delta.

That sequence produces a working injector and a proven microcode-diff harness —
the foundation for every other experiment — in a self-contained first push.

---

## 11. Cross-cutting: safety & disclosure (do not skip)

- `docs/disclosure-policy.md` before any scan: HCF/DoS-class finds and any
  closed-source emulator or silicon bug go through **coordinated disclosure**.
- Prefer owned hardware for aggressive work; fleet-scale scanning on rented
  cloud can violate provider ToS (the Azure hypervisor bug in the paper came
  from exactly that).
- Ring-0 / MSR experiments: **Xeon only**, checkpoint constantly, assume
  hardware loss.
- `scripts/safety_preflight.sh` gates every run: asserts ring-3 backend unless
  `--sacrificial` is explicitly set, verifies blacklist is loaded, verifies a
  known-good recovery path exists.
```

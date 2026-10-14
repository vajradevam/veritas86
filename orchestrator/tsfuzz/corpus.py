"""
corpus.py — candidate-encoding generators for a first real sweep.

third_party/xed and third_party/liblisa are not wired in yet (see
IMPLEMENTATION_PLAN.md §10 item 2), so this is NOT the exhaustive
XED-driven enumeration the plan eventually wants. It's the cheap,
dependency-free sweep that's enough for a first cross-machine result:

  - map0:  every one-byte opcode 0x00..0xFF, unprefixed.
  - map0f: every 0x0F xx two-byte opcode.
  - seeds: a handful of encodings called out by name in the paper /
    IMPLEMENTATION_PLAN.md as known-interesting (66 e9 prefix-ignored
    jmp, the reserved-NOP family 0f18-0f1f, x87 opcode groups).

Each candidate is padded to MAX_ENC_LEN (15) bytes with 0x00 filler so
core/injector's length.c can slide the guard boundary and resolve the
*true* consumed length regardless of how long the real instruction is.
"""
from __future__ import annotations

from dataclasses import dataclass

from .proto import MAX_ENC_LEN


@dataclass
class Candidate:
    label: str
    prefix: bytes  # the bytes we actually care about; rest is filler

    def padded(self) -> bytes:
        if len(self.prefix) > MAX_ENC_LEN:
            raise ValueError(f"{self.label}: prefix too long")
        return self.prefix.ljust(MAX_ENC_LEN, b"\x00")


def map0() -> list[Candidate]:
    """Every one-byte opcode, no prefixes."""
    return [Candidate(f"map0_{b:02x}", bytes([b])) for b in range(256)]


def map0f() -> list[Candidate]:
    """Every 0x0F xx two-byte opcode."""
    return [Candidate(f"map0f_{b:02x}", bytes([0x0F, b])) for b in range(256)]


def reserved_nop_family() -> list[Candidate]:
    """0f18..0f1f (Group 16 — HINT_NOP / prefetch space) against a spread
    of ModRM bytes, since the interesting behavior there is ModRM-gated."""
    out = []
    for op in range(0x18, 0x20):
        for modrm in (0x00, 0x05, 0xC0, 0xC7, 0xF8):
            out.append(Candidate(f"resnop_{op:02x}_{modrm:02x}",
                                  bytes([0x0F, op, modrm])))
    return out


def paper_regressions() -> list[Candidate]:
    """Named encodings from the Domas paper / IMPLEMENTATION_PLAN.md §1
    seeds/paper_regressions.txt — spot-checked individually, not just
    swept as part of a map."""
    return [
        Candidate("paper_66e9_prefix_ignored_jmp", bytes.fromhex("66e9000000 00".replace(" ", ""))),
        Candidate("paper_0f0d_nop_group", bytes.fromhex("0f0dc0")),
        Candidate("paper_dbe0_fninit", bytes.fromhex("dbe0")),
        Candidate("paper_dbe1_fnop_adjacent", bytes.fromhex("dbe1")),
        Candidate("paper_dfc0_ffree_group", bytes.fromhex("dfc0")),
        Candidate("paper_dfc7_ffree_group", bytes.fromhex("dfc7")),
        Candidate("paper_f1_icebp", bytes.fromhex("f1")),
        Candidate("paper_0f3f_reserved", bytes.fromhex("0f3f")),
        Candidate("paper_0fff_reserved", bytes.fromhex("0fff")),
        Candidate("paper_d6_salc", bytes.fromhex("d6")),
    ]


def rex_prefixed_map0(subset: range | None = None) -> list[Candidate]:
    """One-byte opcode map again, but with a REX.W prefix (0x48) in
    front -- cheap way to see which one-byte entries change meaning
    under REX without a full 2-byte-prefix x 256 sweep."""
    rng = subset if subset is not None else range(256)
    return [Candidate(f"rexmap0_{b:02x}", bytes([0x48, b])) for b in rng]


def map_prefixed(prefix: int, name: str) -> list[Candidate]:
    """Every 0x0F xx two-byte opcode under a single legacy prefix byte --
    reused for 66 (operand-size/SSE packed-double), F2 (repne/SSE scalar-
    double), F3 (rep/SSE scalar-single)."""
    return [Candidate(f"{name}_{b:02x}", bytes([prefix, 0x0F, b])) for b in range(256)]


def map1_38() -> list[Candidate]:
    """0F 38 xx -- three-byte opcode map 1 (SSSE3/SSE4/AVX2 territory)."""
    return [Candidate(f"map38_{b:02x}", bytes([0x0F, 0x38, b])) for b in range(256)]


def map1_3a() -> list[Candidate]:
    """0F 3A xx -- three-byte opcode map 2 (imm8-bearing SSE4/AVX forms)."""
    return [Candidate(f"map3a_{b:02x}", bytes([0x0F, 0x3A, b])) for b in range(256)]


def rex_prefixed_map0f() -> list[Candidate]:
    """0x0F xx two-byte map again, with REX.W (0x48) in front."""
    return [Candidate(f"rexmap0f_{b:02x}", bytes([0x48, 0x0F, b])) for b in range(256)]


def modrm_reg_sweep(opcode: bytes, label: str) -> list[Candidate]:
    """Group-coded opcodes (0f00/0f01/0fae/0fba/0f71-73/...) select their
    real operation from the ModRM reg field, not the opcode byte alone.
    mod=11 (register-direct, rm=0) with reg=0..7 enumerates all 8
    sub-opcodes of a group without the cost of a full 256-byte ModRM
    sweep."""
    out = []
    for reg in range(8):
        modrm = 0xC0 | (reg << 3)  # mod=11, reg=reg, rm=000
        out.append(Candidate(f"{label}_reg{reg}", opcode + bytes([modrm])))
    return out


def modrm_full_sweep(opcode: bytes, label: str) -> list[Candidate]:
    """All 256 ModRM byte values for one opcode -- used to pin down a
    specific anomaly (e.g. Result 5's 0f ae outlier) rather than swept
    broadly (256 candidates per opcode adds up fast)."""
    return [Candidate(f"{label}_modrm{m:02x}", opcode + bytes([m])) for m in range(256)]


def group_modrm_sweeps() -> list[Candidate]:
    """modrm_reg_sweep over the well-known ModRM-reg-selected group
    opcodes, so the three-byte-map and two-byte-map coverage above
    actually exercises their sub-forms instead of just reg=0 (which is
    all the filler-byte-only maps above implicitly test)."""
    groups = [
        (bytes.fromhex("0f00"), "grp_0f00"),  # sldt/str/lldt/ltr/verr/verw
        (bytes.fromhex("0f01"), "grp_0f01"),  # sgdt/sidt/lgdt/lidt/smsw/lmsw/invlpg
        (bytes.fromhex("0fba"), "grp_0fba"),  # bt/bts/btr/btc imm8 group
        (bytes.fromhex("0f71"), "grp_0f71"),  # psrlw/psraw/psllw (MMX/SSE shift group)
        (bytes.fromhex("0f72"), "grp_0f72"),
        (bytes.fromhex("0f73"), "grp_0f73"),
        (bytes.fromhex("0fc7"), "grp_0fc7"),  # cmpxchg8b/rdrand/rdseed group
        (bytes.fromhex("0f18"), "grp_0f18"),  # prefetch hints (reserved nop space)
    ]
    out = []
    for opcode, label in groups:
        out += modrm_reg_sweep(opcode, label)
    return out


def anomaly_followup() -> list[Candidate]:
    """Full ModRM sweep of 0f ae (Group 15), the one reproducible,
    cross-machine-identical oddity from sweep1 (data/reports/
    sweep1_results.md Result 5): it faulted at exec_base+0x1ff instead of
    NULL like its ModRM-memory siblings. Sweeping every ModRM byte here
    should localize exactly which sub-form (fxsave/ldmxcsr/mfence/
    clflush/...) causes it."""
    return modrm_full_sweep(bytes.fromhex("0fae"), "anomaly_0fae")


def avx512_seeds() -> list[Candidate]:
    """EVEX-encoded AVX-512 instructions, bytes extracted with
    `gcc -mavx512f -mavx512dq -mavx512bw` + objdump (not hand-encoded --
    EVEX is error-prone to assemble by hand). The fleet has mixed AVX-512
    support (Tiger Lake i7-1165G7: yes; Kaby-Lake-R i7-8550U, Coffee Lake
    i7-9700T: no), so this is the corpus entry expected to actually
    diverge across machines -- an architectural AVX-512-capability
    fingerprint, cross-checked against /proc/cpuinfo flags in the report."""
    return [
        Candidate("avx512_vaddps_zmm", bytes.fromhex("62f17c4858c1")),
        Candidate("avx512_vpaddd_zmm", bytes.fromhex("62f17d48fec1")),
        Candidate("avx512_vmulpd_zmm", bytes.fromhex("62f1fd4859c1")),
        Candidate("avx512_vcmpeqps_k0", bytes.fromhex("62f17c48c2c100")),
        Candidate("avx512_kmovw_k0_eax", bytes.fromhex("c5f893c0")),
    ]


def feature_seeds() -> list[Candidate]:
    """More named feature probes, bytes extracted the same way (gcc -m<ext>
    + objdump, see corpus.py history / data/reports for the exact
    commands) -- widens the capability ladder beyond plain AVX-512F so a
    fleet spanning Sandy Bridge-EP -> Tiger Lake should show several
    distinct tiers, not just a binary split."""
    return [
        Candidate("feat_avx512vnni_vpdpbusd", bytes.fromhex("62f27548 50c2")),
        Candidate("feat_avx512bitalg_vpopcntb", bytes.fromhex("62f27d48 54c0")),
        Candidate("feat_gfni_vgf2p8affineqb", bytes.fromhex("c4e3f9 cec100")),
        Candidate("feat_vaes_vaesenc_zmm", bytes.fromhex("62f27d48 dcc1")),
        Candidate("feat_bmi2_pext", bytes.fromhex("c4e2c2 f5c6")),
        Candidate("feat_bmi2_pdep", bytes.fromhex("c4e2c3 f5c6")),
        Candidate("feat_bmi1_andn", bytes.fromhex("c4e2c0 f2c6")),
        Candidate("feat_shani_sha256rnds2", bytes.fromhex("0f38 cbc1")),
        Candidate("feat_avx2_vpaddd_ymm", bytes.fromhex("c5fd feC1")),
        Candidate("feat_fma_vfmadd132ps", bytes.fromhex("c4e26d 98c1")),
    ]


def map1_38_prefixed(prefix: int, name: str) -> list[Candidate]:
    """0F 38 xx (three-byte map 1) under a single legacy prefix byte.
    The 66-prefixed form is where the scalar AES-NI family lives:
    AESIMC (0xDB), AESENC (0xDC), AESENCLAST (0xDD), AESDEC (0xDE),
    AESDECLAST (0xDF) all require 66 0F 38 /r exactly -- map1_38()
    (no prefix) does not reach them."""
    return [Candidate(f"{name}_{b:02x}", bytes([prefix, 0x0F, 0x38, b])) for b in range(256)]


def map1_3a_prefixed(prefix: int, name: str) -> list[Candidate]:
    """0F 3A xx (three-byte map 2) under a single legacy prefix byte.
    The 66-prefixed form carries PCLMULQDQ (0x44, carry-less multiply --
    the GHASH primitive behind AES-GCM) and AESKEYGENASSIST (0xDF)."""
    return [Candidate(f"{name}_{b:02x}", bytes([prefix, 0x0F, 0x3A, b])) for b in range(256)]


def vex256_66_0f38_sweep() -> list[Candidate]:
    """VEX.256.66.0F38 xx, full opcode byte sweep. Prefix bytes (C4 E2 7D)
    extracted empirically via `gcc -mavx2` + objdump against vpshufb, not
    hand-derived -- see the sweep-3 experiment notes. Reaches the
    VEX-encoded AES-NI forms (VAESENC/VAESENCLAST/VAESDEC/VAESDECLAST at
    the same DC-DF opcode bytes as their legacy counterparts) and the
    general AVX2 integer/shuffle space beyond the named feature seeds."""
    return [Candidate(f"vex38_{b:02x}", bytes([0xC4, 0xE2, 0x7D, b])) for b in range(256)]


def vex256_66_0f3a_sweep() -> list[Candidate]:
    """VEX.256.66.0F3A xx, full opcode byte sweep. Prefix bytes (C4 E3 7D)
    extracted empirically via `gcc -mavx2` + objdump against vpblendd.
    Reaches VPCLMULQDQ at opcode 0x44, the vectorized GHASH primitive."""
    return [Candidate(f"vex3a_{b:02x}", bytes([0xC4, 0xE3, 0x7D, b])) for b in range(256)]


def group7_0f01_full_sweep() -> list[Candidate]:
    """Full 256-ModRM sweep of 0F 01 (Group 7). This single sweep reaches,
    by exact byte position verified empirically via `gcc -mpku -mserialize
    -mrtm` + objdump: RDPKRU/WRPKRU (0xEE/0xEF, memory protection keys),
    XTEST (0xD6, TSX query), CLAC/STAC (0xCA/0xCB, SMAP toggle --
    Supervisor Mode Access Prevention), SERIALIZE (0xE8), MONITOR/MWAIT
    (0xC8/0xC9), and the VMX group (VMCALL/VMLAUNCH/VMRESUME/VMXOFF,
    0xC1-0xC4) among the reserved/undocumented space of the same map."""
    return modrm_full_sweep(bytes.fromhex("0f01"), "grp0f01full")


def group9_0fc7_full_sweep() -> list[Candidate]:
    """Full 256-ModRM sweep of 0F C7 (Group 9): CMPXCHG8B/16B, and at
    ModRM reg field 6/7 (mod=11), RDRAND/RDSEED -- the hardware RNG
    instructions group_modrm_sweeps() already samples narrowly (reg
    field only); this is the same group swept exhaustively."""
    return modrm_full_sweep(bytes.fromhex("0fc7"), "grp0fc7full")


def group15_0fae_prefixed_sweep(prefix: int, name: str) -> list[Candidate]:
    """Full 256-ModRM sweep of 0F AE (Group 15) under one legacy prefix.
    anomaly_followup() already swept the unprefixed form (FXSAVE/CLFLUSH/
    MFENCE/etc., and the Result-5/6 anomaly). The 66-prefixed form adds
    CLFLUSHOPT and CLWB; the F2-prefixed and F3-prefixed forms add
    UMWAIT and UMONITOR (WAITPKG), timing-adjacent instructions directly
    relevant to the covert-channel/timing-attack literature this report
    cites."""
    return [Candidate(f"{name}_{m:02x}", bytes([prefix, 0x0F, 0xAE, m])) for m in range(256)]


def crypto_relevant_seeds() -> list[Candidate]:
    """Named seeds that don't fit a systematic sweep above: AVX2 and
    AVX-512 gather (the instruction class at the center of the Downfall/
    GDS disclosure \\cite{moghimi2023downfall}, since masked-gather
    feature presence, not the gathered values, is what's being tested
    here) and RDPID (F3 0F C7 /7 -- shares its reg-field position with
    RDSEED but needs the F3 prefix, so group9_0fc7_full_sweep()'s
    unprefixed sweep does not reach it)."""
    return [
        # AVX2 legacy-VEX gather: vpgatherdd ymm1, [rdi+ymm2*4], ymm0 (mask).
        # Bytes extracted via gcc -mavx2 + objdump, not hand-encoded.
        Candidate("crypto_gather_avx2_vpgatherdd", bytes.fromhex("c4e27d900c97")),
        # AVX-512 EVEX gather: vpgatherdd zmm0{k1}, [rdi+zmm1*4].
        # Bytes extracted via gcc -mavx512f + objdump.
        Candidate("crypto_gather_avx512_vpgatherdd", bytes.fromhex("62f27d4990048f")),
        Candidate("crypto_rdpid", bytes.fromhex("f30fc7f8")),
    ]


def full_corpus() -> list[Candidate]:
    return (
        map0()
        + map0f()
        + map_prefixed(0x66, "map66")
        + map_prefixed(0xF2, "mapF2")
        + map_prefixed(0xF3, "mapF3")
        + map1_38()
        + map1_3a()
        + reserved_nop_family()
        + paper_regressions()
        + rex_prefixed_map0()
        + rex_prefixed_map0f()
        + group_modrm_sweeps()
        + anomaly_followup()
        + avx512_seeds()
        + feature_seeds()
        + map1_38_prefixed(0x66, "map66_38")
        + map1_3a_prefixed(0x66, "map66_3a")
        + vex256_66_0f38_sweep()
        + vex256_66_0f3a_sweep()
        + group7_0f01_full_sweep()
        + group9_0fc7_full_sweep()
        + group15_0fae_prefixed_sweep(0x66, "grp0fae66")
        + group15_0fae_prefixed_sweep(0xF2, "grp0faeF2")
        + group15_0fae_prefixed_sweep(0xF3, "grp0faeF3")
        + crypto_relevant_seeds()
    )

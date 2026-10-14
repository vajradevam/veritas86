"""
fingerprint.py — Candidate + Result -> the canonical record
(docs/fingerprint-schema.md describes the target shape; this is the v1
subset that doesn't need XED wired in: no xed_len/xed_iform/diverges
fields yet, those need third_party/xed).
"""
from __future__ import annotations

from .corpus import Candidate
from .proto import Job, Mode, Result


def record(cand: Candidate, res: Result, state: str = "zero_v1") -> dict:
    return {
        "label": cand.label,
        "state": state,
        "enc": cand.prefix.hex(),
        "length": res.length,
        "valid_length": res.valid_length,
        "fault": res.fault_class.name,
        "signo": res.signo,
        "cr2_off": res.cr2_off,
        "in_arena": res.in_arena(),
        "rip_off": res.rip_off,
        # changed-register summary, not full state -- enough to flag
        # "executed and touched architectural state" vs "no-op length probe"
        "gpr_nonzero_count": sum(1 for v in res.gpr if v != 0),
        "rflags": res.rflags,
    }


def job_for(cand: Candidate, gpr: list[int]) -> Job:
    return Job(enc=cand.padded(), mode=Mode.BOTH, gpr=list(gpr), rflags=0)


def scratch_v1_gpr(default_gpr: list[int]) -> list[int]:
    """Second named input state (docs/fingerprint-schema.md 'state' key),
    built in Python with no core/injector change: 'zero_v1' zeroes every
    GPR except RSP (pointed at scratch_page so push/pop-ish candidates
    don't fault against unmapped memory); that means any `[rax]`-style
    ModRM memory operand resolves to address 0 and page-faults, regardless
    of whether the opcode itself is privileged -- sweep1_results.md's
    Result 5 found this dominates the GP_OR_PF bucket (426/427 of it).
    'scratch_v1' reuses the one pointer the hello handshake already
    guarantees is valid -- default_gpr[RSP] -- for every GPR, so a
    ModRM-memory candidate resolves into mapped scratch instead of NULL.
    An encoding whose fault class flips GP_OR_PF -> NONE between the two
    states was a NULL-deref artifact, not a real privilege fault; one that
    stays GP_OR_PF under both is the real thing."""
    from .proto import Gpr
    scratch_ptr = default_gpr[Gpr.RSP]
    return [scratch_ptr] * len(default_gpr)

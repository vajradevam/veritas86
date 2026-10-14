"""
test_ring3.py — orchestrator-level smoke tests for the Ring3Injector
backend, mirroring core/tests/smoke.c's known-answer cases but exercised
through the actual Python wire-protocol client, not the in-process C API.

Run from anywhere with: pytest orchestrator/tests/test_ring3.py -v
Requires core/injector/injector to be built (`make` in core/injector).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from tsfuzz.backends.ring3 import Ring3Injector
from tsfuzz.proto import FaultClass, Job, Mode


@pytest.fixture(scope="module")
def inj():
    with Ring3Injector() as injector:
        yield injector


def test_hello_handshake_sane(inj):
    assert len(inj.hello.default_gpr) == 16
    # default rsp must be a plausible userspace pointer, not 0/garbage.
    from tsfuzz.proto import Gpr
    assert inj.hello.default_gpr[Gpr.RSP] > 0x1000


def test_nop(inj):
    gpr = inj.default_gpr()
    res = inj.submit(Job(enc=b"\x90", mode=Mode.BOTH, gpr=gpr, rflags=0))
    assert res.length == 1
    assert res.fault_class == FaultClass.NONE
    assert res.in_arena()


def test_ud2_does_not_exist(inj):
    gpr = inj.default_gpr()
    res = inj.submit(Job(enc=b"\x0f\x0b", mode=Mode.BOTH, gpr=gpr, rflags=0))
    assert res.length == 2
    assert res.fault_class == FaultClass.UD
    assert res.in_arena()


def test_rex_prefix_nop(inj):
    gpr = inj.default_gpr()
    res = inj.submit(Job(enc=b"\x40\x90", mode=Mode.BOTH, gpr=gpr, rflags=0))
    assert res.length == 2
    assert res.fault_class == FaultClass.NONE


def test_paper_divergence_66_e9(inj):
    """The Domas paper's headline finding: the 66 (operand-size override)
    prefix is architecturally meaningless on jmp rel32 in 64-bit mode, so
    Intel silicon decodes it as a normal 6-byte jmp, not a 2-byte jmp +
    4 stray bytes. Reproduced live here, not asserted from the paper."""
    gpr = inj.default_gpr()
    res = inj.submit(Job(enc=b"\x66\xe9\x00\x00\x00\x00", mode=Mode.BOTH, gpr=gpr, rflags=0))
    assert res.length == 6
    assert res.fault_class == FaultClass.NONE


def test_hlt_exists_but_privileged(inj):
    gpr = inj.default_gpr()
    res = inj.submit(Job(enc=b"\xf4", mode=Mode.BOTH, gpr=gpr, rflags=0))
    assert res.length == 1
    assert res.fault_class == FaultClass.GP_OR_PF


def test_blacklist_refuses_syscall_execute(inj):
    gpr = inj.default_gpr()
    res = inj.submit(Job(enc=b"\x0f\x05", mode=Mode.EXECUTE, gpr=gpr, rflags=0))
    assert res.valid_length is False
    assert res.fault_class == FaultClass.UNKNOWN


def test_blacklist_refuses_pop_fs_gs_execute(inj):
    """Regression for a real blacklist gap found during the first full
    map0f sweep (data/fingerprints/*.jsonl runner.py run): `0f a1`
    (pop fs) and `0f a9` (pop gs) are segment-register loads exactly like
    mov Sreg/lss/lfs/lgs, but were missing from blacklist.c and crashed
    the injector outright (FS gets zeroed, breaking TLS-relative
    addressing before the fault-recovery path can run). See
    blacklist.c's comment and docs/safety.md."""
    gpr = inj.default_gpr()
    for enc in (b"\x0f\xa1", b"\x0f\xa9"):
        res = inj.submit(Job(enc=enc, mode=Mode.EXECUTE, gpr=gpr, rflags=0))
        assert res.valid_length is False
        assert res.fault_class == FaultClass.UNKNOWN


def test_blacklist_refuses_umonitor_execute(inj):
    """Regression for a real blacklist gap found during the sweep-3 corpus
    expansion (group15_0fae_prefixed_sweep): `f3 0f ae /2` (UMONITOR)
    killed the daemon outright on a single isolated submission, under
    either input state, with no accumulated prior jobs -- not a
    NULL-deref artifact, not an accumulation effect. Confirmed via BOTH
    mode (length resolution), which is the path every sweep actually
    uses, not just EXECUTE mode. See blacklist.c's comment and
    docs/safety.md."""
    gpr = inj.default_gpr()
    for modrm in (0xD0, 0xD1, 0xD7):
        enc = bytes([0xF3, 0x0F, 0xAE, modrm])
        res = inj.submit(Job(enc=enc, mode=Mode.BOTH, gpr=gpr, rflags=0))
        assert res.valid_length is False
        assert res.fault_class == FaultClass.UNKNOWN
    # the unprefixed and 66-prefixed forms of the same reg field are NOT
    # blacklisted -- only F3 0F AE /2 specifically is unsafe.
    for prefix in (None, 0x66):
        enc = (bytes([prefix]) if prefix else b"") + bytes([0x0F, 0xAE, 0xD0])
        res = inj.submit(Job(enc=enc, mode=Mode.BOTH, gpr=gpr, rflags=0))
        assert res.valid_length is True


def test_batch_pipeline_matches_sequential(inj):
    gpr = inj.default_gpr()
    encs = [bytes([b]) for b in (0x90, 0xcc, 0xf4, 0x0f)]
    jobs = [Job(enc=e, mode=Mode.LENGTH, gpr=gpr, rflags=0) for e in encs]
    batched = list(inj.submit_batch(jobs))
    sequential = [inj.submit(Job(enc=e, mode=Mode.LENGTH, gpr=gpr, rflags=0)) for e in encs]
    for b, s in zip(batched, sequential):
        assert b.length == s.length
        assert b.fault_class == s.fault_class


def test_full_byte_enumeration_is_nontrivial(inj):
    """Sanity bound, not a golden value (silicon-specific): some but not
    all single bytes should resolve as standalone 1-byte instructions."""
    gpr = inj.default_gpr()
    jobs = [Job(enc=bytes([b]), mode=Mode.LENGTH, gpr=gpr, rflags=0) for b in range(256)]
    results = list(inj.submit_batch(jobs))
    existing = sum(1 for r in results if r.valid_length and r.fault_class == FaultClass.NONE)
    assert 0 < existing < 256

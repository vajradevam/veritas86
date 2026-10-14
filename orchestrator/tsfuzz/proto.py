"""
proto.py — Python mirror of core/injector/proto.h.

Struct formats use '<' (little-endian, no alignment padding) so the byte
layout matches the C `__attribute__((packed))` structs exactly, field for
field. If proto.h changes, this file must change with it — there is no
other source of truth check (no shared codegen yet).
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import IntEnum

MAX_ENC_LEN = 15
NGPR = 16


class Gpr(IntEnum):
    RAX = 0; RBX = 1; RCX = 2; RDX = 3
    RSI = 4; RDI = 5; RBP = 6; RSP = 7
    R8 = 8; R9 = 9; R10 = 10; R11 = 11
    R12 = 12; R13 = 13; R14 = 14; R15 = 15


class Mode(IntEnum):
    LENGTH = 1
    EXECUTE = 2
    BOTH = 3


class FaultClass(IntEnum):
    NONE = 0
    UD = 1
    BOUNDARY_PF = 2
    GP_OR_PF = 3
    FP = 4
    BUS = 5
    UNKNOWN = 255


# enc[15]s, enc_len B, mode B, gpr[16]Q, rflags Q, pad 7x
_JOB_FMT = "<15sBB16sQ7x"
# the gpr array is packed as raw bytes then unpacked separately below,
# because struct's "16Q" repeat count works fine too -- use it directly.
_JOB_FMT = "<15sBB16QQ7x"
JOB_SIZE = struct.calcsize(_JOB_FMT)

_HELLO_FMT = "<B7x16Q"
HELLO_SIZE = struct.calcsize(_HELLO_FMT)

_RESULT_FMT = "<BBIIQ16QQQ"
RESULT_SIZE = struct.calcsize(_RESULT_FMT)

assert JOB_SIZE == 160, JOB_SIZE
assert HELLO_SIZE == 136, HELLO_SIZE
assert RESULT_SIZE == 162, RESULT_SIZE


@dataclass
class Job:
    enc: bytes
    mode: Mode = Mode.BOTH
    gpr: list[int] = field(default_factory=lambda: [0] * NGPR)
    rflags: int = 0

    def pack(self) -> bytes:
        if len(self.enc) > MAX_ENC_LEN:
            raise ValueError(f"enc too long: {len(self.enc)} > {MAX_ENC_LEN}")
        enc_buf = self.enc.ljust(MAX_ENC_LEN, b"\x00")
        return struct.pack(
            _JOB_FMT,
            enc_buf,
            len(self.enc),
            int(self.mode),
            *self.gpr,
            self.rflags,
        )


@dataclass
class Hello:
    null_page_mapped: bool
    default_gpr: list[int]

    @classmethod
    def unpack(cls, buf: bytes) -> "Hello":
        if len(buf) != HELLO_SIZE:
            raise ValueError(f"short hello read: {len(buf)} != {HELLO_SIZE}")
        parts = struct.unpack(_HELLO_FMT, buf)
        null_page_mapped = bool(parts[0])
        default_gpr = list(parts[1:])
        return cls(null_page_mapped=null_page_mapped, default_gpr=default_gpr)


@dataclass
class Result:
    length: int
    valid_length: bool
    fault_class: FaultClass
    signo: int
    cr2_off: int
    gpr: list[int]
    rflags: int
    rip_off: int

    @classmethod
    def unpack(cls, buf: bytes) -> "Result":
        if len(buf) != RESULT_SIZE:
            raise ValueError(f"short result read: {len(buf)} != {RESULT_SIZE}")
        parts = struct.unpack(_RESULT_FMT, buf)
        length, valid_length, fault_class_raw, signo, cr2_off = parts[0:5]
        gpr = list(parts[5:5 + NGPR])
        rflags, rip_off = parts[5 + NGPR:5 + NGPR + 2]
        try:
            fault_class = FaultClass(fault_class_raw)
        except ValueError:
            fault_class = FaultClass.UNKNOWN
        return cls(
            length=length,
            valid_length=bool(valid_length),
            fault_class=fault_class,
            signo=signo,
            cr2_off=cr2_off,
            gpr=gpr,
            rflags=rflags,
            rip_off=rip_off,
        )

    def in_arena(self, page_size: int = 4096) -> bool:
        """Sanity check from docs/injector-protocol.md: a candidate
        fault/trap's rip_off must fall inside [0, page_size]. Upper bound is
        INCLUSIVE: length.c's resolver right-justifies candidates against
        the end of exec_page, so an instruction that fully consumes the
        page lands its post-execution RIP exactly at page_size -- a real,
        legal value, not a host-side fault. Anything beyond that means the
        fault happened in the daemon's own code, not the candidate's -- see
        docs/safety.md 'faults from our own code vs. faults from the
        candidate'. Drivers must check this before trusting a result as a
        candidate finding."""
        return 0 <= self.rip_off <= page_size

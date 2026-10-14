/*
 * proto.h — shared job/result wire structures.
 *
 * These are the canonical types passed between:
 *   - the orchestrator (Python, over a pipe to the `injector` daemon), and
 *   - the in-process C API used directly by core/tests/smoke.c.
 *
 * Mirrors IMPLEMENTATION_PLAN.md §3.2. Keep this struct layout in sync with
 * docs/injector-protocol.md and orchestrator/tsfuzz/backends/ring3.py.
 *
 * GPR index order (used throughout core/injector), matches trampoline.S:
 *   0 rax  1 rbx  2 rcx  3 rdx  4 rsi  5 rdi  6 rbp  7 rsp
 *   8 r8   9 r9  10 r10 11 r11 12 r12 13 r13 14 r14 15 r15
 */
#ifndef BX862_PROTO_H
#define BX862_PROTO_H

#include <stdint.h>

#define BX862_MAX_ENC_LEN 15
#define BX862_NGPR        16

enum bx862_gpr_index {
    GPR_RAX = 0, GPR_RBX, GPR_RCX, GPR_RDX,
    GPR_RSI, GPR_RDI, GPR_RBP, GPR_RSP,
    GPR_R8,  GPR_R9,  GPR_R10, GPR_R11,
    GPR_R12, GPR_R13, GPR_R14, GPR_R15,
};

enum bx862_mode {
    MODE_LENGTH  = 1,   /* page-fault slide only: resolve instruction length */
    MODE_EXECUTE = 2,   /* execute once (TF set) and capture output state */
    MODE_BOTH    = 3,   /* length first, then execute if length resolved    */
};

/* fault classification written into result.fault_class (see signals.c) */
enum bx862_fault_class {
    FAULT_NONE        = 0,  /* single-stepped successfully (SIGTRAP)       */
    FAULT_UD          = 1,  /* #UD  — encoding does not exist (SIGILL)     */
    FAULT_BOUNDARY_PF = 2,  /* #PF at the exact guard-page boundary        */
    FAULT_GP_OR_PF    = 3,  /* SIGSEGV, not at the boundary — exists, but  */
                             /* faulted for privilege/other memory reason; */
                             /* #GP vs non-boundary #PF is NOT disambiguated*/
                             /* from userland signals alone (see length.c  */
                             /* header comment / docs/safety.md).          */
    FAULT_FP          = 4,  /* SIGFPE                                      */
    FAULT_BUS         = 5,  /* SIGBUS                                      */
    FAULT_UNKNOWN      = 255,
};

struct bx862_job {
    uint8_t  enc[BX862_MAX_ENC_LEN];
    uint8_t  enc_len;
    uint8_t  mode;                 /* enum bx862_mode */
    uint64_t gpr[BX862_NGPR];      /* input GPRs, see index enum above */
    uint64_t rflags;               /* input RFLAGS; TF bit is forced on internally */
    uint8_t  _pad[7];
} __attribute__((packed));

/*
 * bx862_hello — written ONCE to stdout immediately at daemon startup,
 * before any bx862_result. The caller (orchestrator/tsfuzz/backends/
 * ring3.py) must read this first. It exists because the daemon's
 * arena is inside an ASLR'd mmap the caller has no other way to learn
 * — in particular default_gpr[GPR_RSP] is the only rsp value guaranteed
 * to be valid, mapped, writable memory for THIS process instance (see
 * state.c's zero_v1 and signals.c's seed-write). Building a job with
 * gpr[GPR_RSP] = 0 (or any other guessed address) instead of a value
 * sourced from this handshake is unsafe and can crash the daemon (see
 * docs/safety.md).
 */
struct bx862_hello {
    uint8_t  null_page_mapped;
    uint8_t  _pad[7];
    uint64_t default_gpr[BX862_NGPR]; /* mirrors bx862_state_zero_v1() */
} __attribute__((packed));

struct bx862_result {
    uint8_t  length;               /* resolved length, valid iff valid_length */
    uint8_t  valid_length;
    uint32_t fault_class;          /* enum bx862_fault_class */
    uint32_t signo;                /* raw signal number, 0 if none */
    uint64_t cr2_off;              /* fault addr - exec_page base, or ~0ULL */
    uint64_t gpr[BX862_NGPR];      /* output GPRs (post-fault or post-exec) */
    uint64_t rflags;
    uint64_t rip_off;              /* fault/trap RIP - exec_page base */
} __attribute__((packed));

#endif /* BX862_PROTO_H */

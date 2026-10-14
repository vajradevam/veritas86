#define _GNU_SOURCE
#include "signals.h"

#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <ucontext.h>
#include <unistd.h>

/* defined in trampoline.S */
extern void bx862_run_candidate(void *entry, const uint64_t gpr[BX862_NGPR]);

#define BX862_ALTSTACK_SIZE (65536 * 4) /* fixed size: SIGSTKSZ is not a
                                          * compile-time constant on modern
                                          * glibc (it can be a sysconf()
                                          * call), so it can't size a
                                          * file-scope array. */

static sigjmp_buf         g_recovery_env;
static struct bx862_result *g_cur_result;
static struct bx862_arena  *g_cur_arena;
static uint8_t              g_altstack[BX862_ALTSTACK_SIZE];

/* Defense in depth: true only between sigsetjmp() and the end of the
 * candidate attempt (see bx862_run_attempt). If a signal we handle ever
 * arrives while this is false, it did NOT come from a controlled
 * candidate attempt — it's a bug in the injector itself (e.g. a bad
 * caller-supplied address faulting before we had anywhere safe to
 * unwind to). siglongjmp-ing into a stale or uninitialized
 * g_recovery_env in that case is worse than crashing cleanly, so we
 * don't try. */
static volatile sig_atomic_t g_armed = 0;

/* Writes into a naturally-aligned local array, never directly into a
 * possibly-misaligned field of the __attribute__((packed)) result struct
 * (the caller memcpy's the result in, avoiding -Waddress-of-packed-member
 * and any alignment-UB concerns even though x86-64 tolerates unaligned
 * loads/stores in practice). */
static void fill_gpr_from_gregs(uint64_t out[BX862_NGPR], const mcontext_t *mc)
{
    const greg_t *g = mc->gregs;
    out[GPR_RAX] = (uint64_t)g[REG_RAX];
    out[GPR_RBX] = (uint64_t)g[REG_RBX];
    out[GPR_RCX] = (uint64_t)g[REG_RCX];
    out[GPR_RDX] = (uint64_t)g[REG_RDX];
    out[GPR_RSI] = (uint64_t)g[REG_RSI];
    out[GPR_RDI] = (uint64_t)g[REG_RDI];
    out[GPR_RBP] = (uint64_t)g[REG_RBP];
    out[GPR_RSP] = (uint64_t)g[REG_RSP];
    out[GPR_R8]  = (uint64_t)g[REG_R8];
    out[GPR_R9]  = (uint64_t)g[REG_R9];
    out[GPR_R10] = (uint64_t)g[REG_R10];
    out[GPR_R11] = (uint64_t)g[REG_R11];
    out[GPR_R12] = (uint64_t)g[REG_R12];
    out[GPR_R13] = (uint64_t)g[REG_R13];
    out[GPR_R14] = (uint64_t)g[REG_R14];
    out[GPR_R15] = (uint64_t)g[REG_R15];
}

static void handler(int sig, siginfo_t *info, void *ucv)
{
    if (!g_armed) {
        /* Async-signal-safe path only: no fprintf/malloc/etc here. */
        static const char msg[] =
            "injector: signal outside a controlled attempt — "
            "internal bug or bad input state, aborting\n";
        ssize_t ignored = write(STDERR_FILENO, msg, sizeof(msg) - 1);
        (void)ignored;
        _exit(2);
    }

    ucontext_t *uc = (ucontext_t *)ucv;
    struct bx862_result *r = g_cur_result;

    memset(r, 0, sizeof(*r));
    r->signo = (uint32_t)sig;

    uint64_t gpr_tmp[BX862_NGPR];
    fill_gpr_from_gregs(gpr_tmp, &uc->uc_mcontext);
    memcpy(r->gpr, gpr_tmp, sizeof(gpr_tmp));
    r->rflags = (uint64_t)uc->uc_mcontext.gregs[REG_EFL];

    uintptr_t rip = (uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
    uintptr_t exec_base = (uintptr_t)g_cur_arena->exec_page;
    r->rip_off = rip - exec_base;

    switch (sig) {
    case SIGILL:
        r->fault_class = FAULT_UD;
        r->cr2_off = ~0ULL;
        break;
    case SIGTRAP:
        /* Successful single-step: the candidate executed exactly once. */
        r->fault_class = FAULT_NONE;
        r->cr2_off = ~0ULL;
        break;
    case SIGSEGV: {
        uintptr_t addr = (uintptr_t)info->si_addr;
        uintptr_t guard_base = (uintptr_t)g_cur_arena->guard_page;
        r->cr2_off = addr - exec_base;
        r->fault_class = (addr == guard_base) ? FAULT_BOUNDARY_PF
                                               : FAULT_GP_OR_PF;
        break;
    }
    case SIGBUS:
        r->fault_class = FAULT_BUS;
        r->cr2_off = (uint64_t)(uintptr_t)info->si_addr - exec_base;
        break;
    case SIGFPE:
        r->fault_class = FAULT_FP;
        r->cr2_off = ~0ULL;
        break;
    default:
        r->fault_class = FAULT_UNKNOWN;
        r->cr2_off = ~0ULL;
        break;
    }

    siglongjmp(g_recovery_env, 1);
}

int bx862_signals_install(struct bx862_arena *arena)
{
    g_cur_arena = arena;

    stack_t ss = {
        .ss_sp = g_altstack,
        .ss_size = sizeof(g_altstack),
        .ss_flags = 0,
    };
    if (sigaltstack(&ss, NULL) != 0)
        return -1;

    int sigs[] = { SIGILL, SIGSEGV, SIGBUS, SIGFPE, SIGTRAP };
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = handler;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);
    for (size_t i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++)
        sigaddset(&sa.sa_mask, sigs[i]);

    for (size_t i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++) {
        if (sigaction(sigs[i], &sa, NULL) != 0)
            return -1;
    }
    return 0;
}

int bx862_run_attempt(void *target, const uint64_t gpr[BX862_NGPR],
                       uint64_t rflags, struct bx862_result *out)
{
    memset(out, 0, sizeof(*out));
    g_cur_result = out;

    /* Force TF (bit 8) so every candidate — success or not — hands
     * control back to us via a signal rather than running free. */
    uint64_t rflags_tf = rflags | (1ULL << 8);

    /* g_recovery_env must be valid BEFORE we touch any caller-supplied
     * address — including gpr[GPR_RSP] below, which a caller testing a
     * deliberately-bad input state (e.g. rsp=0 without the NULL page
     * mapped) can make fault. Everything from here to the end of this
     * block runs "armed": any signal we handle is attributable to this
     * specific attempt and safe to unwind from. */
    if (sigsetjmp(g_recovery_env, 1) == 0) {
        g_armed = 1;

        /* Seed the stack slot the planted popfq will pop (see
         * trampoline.S). gpr[GPR_RSP] is a plain address in OUR OWN
         * address space (this is still the injector process). If it's
         * not valid, mapped, writable memory, this line itself faults
         * — now safely caught (armed) and reported back to the caller
         * as a result whose rip_off will NOT fall inside the arena's
         * exec_page, distinguishing "bad input state" from "candidate
         * fault". */
        *(uint64_t *)(uintptr_t)gpr[GPR_RSP] = rflags_tf;

        /* Plant the single-byte popfq immediately before the
         * candidate. Caller contract: target must have >=1 writable
         * byte before it. */
        uint8_t *entry = (uint8_t *)target - 1;
        *entry = 0x9D; /* POPFQ */

        bx862_run_candidate(entry, gpr);
        /* unreachable: run_candidate never returns normally */
        __builtin_unreachable();
    }
    g_armed = 0;
    return 0;
}

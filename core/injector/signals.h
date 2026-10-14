/*
 * signals.h — exception hooking and single-attempt execution/recovery.
 *
 * KNOWN LIMITATION (read before trusting fault_class output):
 * Linux delivers both #GP (general protection, e.g. a privileged
 * instruction from ring 3) and a non-boundary #PF as SIGSEGV to
 * userspace, and there is no portable, kernel-version-stable way to tell
 * them apart from a plain signal handler. We classify anything that
 * reaches SIGSEGV at an address OTHER than the known guard-page boundary
 * as FAULT_GP_OR_PF (see proto.h) rather than pretending to disambiguate
 * it. This is sufficient for length analysis (only the boundary case
 * matters there) but is a real gap for privilege-classification work —
 * IMPLEMENTATION_PLAN.md Idea 4/5 close it properly with a ptrace- or
 * VM-exit-based harness that can read the actual trap vector.
 */
#ifndef BX862_SIGNALS_H
#define BX862_SIGNALS_H

#include "memmap.h"
#include "proto.h"

/* Installs signal handlers + sigaltstack. Call once at startup.
 * Returns 0 on success, -1 on failure. */
int bx862_signals_install(struct bx862_arena *arena);

/*
 * Runs exactly one candidate under controlled input state and populates
 * *out with the outcome (fault class, output GPRs/RFLAGS if it ran to
 * completion, fault address info otherwise).
 *
 * `target` must point at the candidate's first byte, with AT LEAST ONE
 * writable byte immediately before it in the same mapping — this
 * function plants a single `popfq` (0x9D) at target-1 to arm
 * single-stepping exactly at the candidate's own boundary (see
 * trampoline.S for why a plain jmp-with-TF-armed can't be used instead).
 * Both of length.c's sliding window and inject.c's EXECUTE placement
 * reserve that leading byte; do not call this directly with a `target`
 * at the very start of a page.
 *
 * `gpr[GPR_RSP]` must point at 8 bytes of writable memory — this
 * function seeds it with (rflags | TF) for the planted popfq to consume;
 * the candidate's OWN observed %rsp on entry is therefore
 * gpr[GPR_RSP] + 8 (see trampoline.S).
 *
 * Returns 0 always (the outcome is in *out->fault_class etc); a nonzero
 * return is reserved for internal setup failure.
 */
int bx862_run_attempt(void *target, const uint64_t gpr[BX862_NGPR],
                       uint64_t rflags, struct bx862_result *out);

#endif /* BX862_SIGNALS_H */

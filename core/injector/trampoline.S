/*
 * trampoline.S — the final register-load + jump into candidate code.
 *
 * void bx862_run_candidate(void *entry, const uint64_t gpr[16]);
 *   rdi = entry address to jump into — this is NOT the candidate's first
 *         byte; it is one byte EARLIER, a single planted `popfq` (0x9D)
 *         that signals.c writes immediately before the candidate bytes.
 *         See the TF-ARMING note below for why.
 *   rsi = pointer to a 16-entry uint64_t array, index order matches
 *         enum bx862_gpr_index in proto.h. gpr[GPR_RSP] must already
 *         point at an 8-byte, writable memory location that signals.c
 *         has pre-seeded with the desired RFLAGS value (TF set) — that
 *         qword is exactly what the planted popfq pops.
 *
 * This function never returns normally. Once %rsp is loaded from the
 * caller-supplied array, the C stack is no longer valid — control only
 * comes back to the injector via a signal handler calling siglongjmp(),
 * which restores the real stack/registers captured by an earlier
 * sigsetjmp() on the C side. See signals.c.
 *
 * TF-ARMING ORDER — why this isn't just "popfq; jmp *target":
 * Single-stepping a `jmp` (with TF already live) traps AFTER the jmp
 * itself completes — i.e. you land exactly at the target with NOTHING
 * there executed yet. So a trampoline that does popfq immediately
 * followed by an indirect jmp burns its one post-POPF grace instruction
 * on the jmp, and the trap fires on arrival, before the candidate's own
 * first instruction ever runs. There is no way to "skip past" a jmp and
 * have the SAME popfq's deferred trap land on what the jmp jumps to.
 *
 * The fix: don't jump into the candidate with TF already armed. Instead,
 * reach the candidate with TF still OFF (via this function's own plain,
 * unconditional jmp below — safe, because at that point TF isn't set
 * yet), landing on a single `popfq` byte (0x9D) that signals.c has
 * planted directly adjacent to, and immediately before, the candidate's
 * real bytes. That popfq arms TF by popping the pre-seeded qword at
 * [rsp] — and the very next instruction boundary the CPU crosses after
 * THAT is the candidate's own first instruction, with no jmp in between.
 * That is what correctly receives the single-step trap on completion.
 *
 * Side effect worth documenting (docs/fingerprint-schema.md /
 * state.h): because popfq is a real pop, it consumes the qword at the
 * configured %rsp and advances %rsp by 8 as part of reaching the
 * candidate — so the candidate's OBSERVED entry %rsp is
 * (configured_rsp + 8), not configured_rsp itself.
 *
 * Single-threaded injector only: bx862_jmp_target is not thread-safe.
 */
    .section .bss
    .align 8
    .global bx862_jmp_target
bx862_jmp_target:
    .quad 0

    .section .text
    .global bx862_run_candidate
    .type bx862_run_candidate, @function

bx862_run_candidate:
    /* Stash entry before rdi gets reloaded with the candidate's own
     * test value. TF is not armed yet, so this ordinary jmp is safe. */
    mov     %rdi, bx862_jmp_target(%rip)

    /* Load all GPRs from the array (rsi still points at it). Indices
     * per enum bx862_gpr_index in proto.h. */
    mov     0*8(%rsi), %rax
    mov     1*8(%rsi), %rbx
    mov     2*8(%rsi), %rcx
    mov     3*8(%rsi), %rdx
    mov     6*8(%rsi), %rbp
    mov     8*8(%rsi), %r8
    mov     9*8(%rsi), %r9
    mov     10*8(%rsi), %r10
    mov     11*8(%rsi), %r11
    mov     12*8(%rsi), %r12
    mov     13*8(%rsi), %r13
    mov     14*8(%rsi), %r14
    mov     15*8(%rsi), %r15

    /* rsp: after this, the C stack is gone — but that's fine, we never
     * come back here normally (see file comment). */
    mov     7*8(%rsi), %rsp

    mov     5*8(%rsi), %rdi
    mov     4*8(%rsi), %rsi        /* rsi last: was our only pointer to the array */

    /* TF is still OFF here, so this ordinary jmp is not itself
     * single-stepped — it lands on the planted popfq, which is what
     * arms TF for the candidate that immediately follows it. */
    jmp     *bx862_jmp_target(%rip)

    .size bx862_run_candidate, . - bx862_run_candidate

    .section .note.GNU-stack,"",@progbits

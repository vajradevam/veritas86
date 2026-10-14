/*
 * length.h — page-fault-slide length analysis (the paper's core oracle).
 *
 * Places increasing prefixes of `enc` at the tail of exec_page (so the
 * remainder would fetch into the unmapped guard_page), and probes with
 * bx862_run_attempt until fetch no longer crosses the boundary. The last
 * probe IS an execution (single-stepped, TF forced) of whatever landed —
 * so a successful resolution also produces valid output state for free
 * (this is how MODE_BOTH is implemented on top of MODE_LENGTH).
 *
 * SAFETY: if the blacklist (blacklist.h) matches the bytes being probed
 * at a given length, the loop stops WITHOUT probing that length — we
 * will not risk a real single-step execution of a segment load or
 * syscall-entry encoding just to learn its length. out->valid_length is
 * left 0 in that case. This trades completeness for safety in v1; a
 * ptrace/VM-based harness (IMPLEMENTATION_PLAN.md Idea 4) can close the
 * gap later without this restriction.
 */
#ifndef BX862_LENGTH_H
#define BX862_LENGTH_H

#include "memmap.h"
#include "proto.h"

/*
 * Resolves the length of `enc` (candidate, up to enc_len meaningful
 * bytes, enc_len <= BX862_MAX_ENC_LEN). `gpr`/`rflags` are the input
 * state to execute under once fetch completes. Always returns 0; check
 * out->valid_length and out->fault_class for the outcome.
 */
int bx862_resolve_length(struct bx862_arena *a, const uint8_t *enc,
                          uint8_t enc_len, const uint64_t gpr[BX862_NGPR],
                          uint64_t rflags, struct bx862_result *out);

#endif /* BX862_LENGTH_H */

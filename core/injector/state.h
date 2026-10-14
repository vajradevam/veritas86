/*
 * state.h — named, reproducible input register states.
 *
 * Every fingerprint row is keyed by (encoding, input_state_id) — see
 * docs/fingerprint-schema.md. This file is the canonical source for what
 * each input_state_id actually means in terms of GPR contents, so results
 * collected on different machines/runs are comparable.
 */
#ifndef BX862_STATE_H
#define BX862_STATE_H

#include "memmap.h"
#include "proto.h"

/*
 * "zero_v1" — all GPRs zero, except RSP which points to the middle of the
 * scratch page (not literal 0). This keeps push/pop/call-ish faulting
 * candidates landing in mapped, disposable memory even when the NULL page
 * could not be mapped (the common case — see memmap.h). Computed operands
 * like [rax + 4*rcx] still resolve to address 0, which IS only mapped if
 * bx862_arena_try_map_null_page() succeeded; otherwise such operands fault,
 * which is itself useful signal (see docs/safety.md on #GP vs #PF
 * disambiguation limits).
 */
void bx862_state_zero_v1(const struct bx862_arena *a, uint64_t gpr[BX862_NGPR]);

/*
 * "zero_nullmapped_v1" — identical to zero_v1 but RSP is also 0. Only
 * meaningful (and only safe) when arena->null_page_mapped is true; the
 * caller must check that before using this state, or memory/stack ops in
 * the candidate will fault against unmapped page 0.
 */
void bx862_state_zero_nullmapped_v1(const struct bx862_arena *a,
                                     uint64_t gpr[BX862_NGPR]);

#endif /* BX862_STATE_H */

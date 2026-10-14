/*
 * memmap.h — the 4-page candidate-execution arena.
 *
 * Layout (each region is one page, contiguous, in this order):
 *
 *   [ exec_page   RWX  ]  <- candidate bytes land at the END of this page
 *   [ guard_page  NONE ]  <- unmapped; crossing into it while fetching
 *                           raises #PF with CR2 == guard_page base. This
 *                           is the length-analysis boundary signal.
 *   [ scratch     RW   ]  <- zeroed target for benign memory operands
 *   [ spare_guard NONE ]  <- second guard, catches any forward overrun
 *
 * Optionally, page 0 (the NULL page) is also mapped RW, so that GPRs
 * zeroed as input state resolve `[reg]`-style memory operands into mapped,
 * harmless memory instead of the process's own live address space, and so
 * that an unprivileged NULL-relative memory access can be told apart from
 * a privileged register access (both otherwise look like #GP). This needs
 * `sysctl vm.mmap_min_addr=0` (see scripts/safety_preflight.sh) and is
 * best-effort: if it fails, we continue without it and note the fact.
 */
#ifndef BX862_MEMMAP_H
#define BX862_MEMMAP_H

#include <stddef.h>
#include <stdint.h>

struct bx862_arena {
    uint8_t *exec_page;
    uint8_t *guard_page;
    uint8_t *scratch_page;
    uint8_t *spare_guard_page;
    size_t   page_size;
    int      null_page_mapped;   /* 1 if page 0 was successfully mapped RW */
};

/* Sets up the arena. Returns 0 on success, -1 on failure (errno set). */
int bx862_arena_init(struct bx862_arena *a);

/* Attempts to map page 0 RW. Returns 1 on success, 0 if unavailable
 * (EPERM/EINVAL etc — not fatal, caller should continue without it). */
int bx862_arena_try_map_null_page(struct bx862_arena *a);

void bx862_arena_destroy(struct bx862_arena *a);

#endif /* BX862_MEMMAP_H */

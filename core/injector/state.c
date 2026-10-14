#include "state.h"

#include <string.h>

void bx862_state_zero_v1(const struct bx862_arena *a, uint64_t gpr[BX862_NGPR])
{
    memset(gpr, 0, BX862_NGPR * sizeof(uint64_t));
    gpr[GPR_RSP] = (uint64_t)(uintptr_t)(a->scratch_page + a->page_size / 2);
}

void bx862_state_zero_nullmapped_v1(const struct bx862_arena *a,
                                     uint64_t gpr[BX862_NGPR])
{
    (void)a;
    memset(gpr, 0, BX862_NGPR * sizeof(uint64_t));
}

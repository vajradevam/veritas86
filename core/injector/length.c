#include "length.h"

#include "blacklist.h"
#include "signals.h"

#include <string.h>

int bx862_resolve_length(struct bx862_arena *a, const uint8_t *enc,
                          uint8_t enc_len, const uint64_t gpr[BX862_NGPR],
                          uint64_t rflags, struct bx862_result *out)
{
    for (uint8_t n = 1; n <= enc_len; n++) {
        if (bx862_is_blacklisted(enc, n)) {
            /* Refuse to probe further; see length.h safety note. */
            memset(out, 0, sizeof(*out));
            out->valid_length = 0;
            out->fault_class = FAULT_UNKNOWN;
            return 0;
        }

        uint8_t *dst = a->exec_page + a->page_size - n;
        memset(a->exec_page, 0, a->page_size);
        memcpy(dst, enc, n);

        struct bx862_result attempt;
        bx862_run_attempt(dst, gpr, rflags, &attempt);

        if (attempt.fault_class == FAULT_BOUNDARY_PF)
            continue; /* decoder wants more bytes than are resident */

        /* Fetch completed within n bytes: this is the resolved length,
         * regardless of whether the encoding turned out to exist. */
        *out = attempt;
        out->length = n;
        out->valid_length = 1;
        return 0;
    }

    /* Exhausted enc_len without a non-boundary result: the caller gave
     * us fewer bytes than the true instruction length. */
    memset(out, 0, sizeof(*out));
    out->valid_length = 0;
    out->fault_class = FAULT_BOUNDARY_PF;
    return 0;
}

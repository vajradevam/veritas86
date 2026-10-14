#include "inject.h"

#include "blacklist.h"
#include "length.h"
#include "signals.h"

#include <string.h>

static int do_execute(struct bx862_arena *a, const struct bx862_job *job,
                       struct bx862_result *out)
{
    if (bx862_is_blacklisted(job->enc, job->enc_len)) {
        memset(out, 0, sizeof(*out));
        out->fault_class = FAULT_UNKNOWN;
        out->valid_length = 0;
        return -1;
    }

    memset(a->exec_page, 0, a->page_size);
    /* +1: byte 0 is reserved for bx862_run_attempt's planted popfq (see
     * signals.h/trampoline.S) — the candidate itself starts at offset 1. */
    uint8_t *dst = a->exec_page + 1;
    memcpy(dst, job->enc, job->enc_len);

    /* Copy out of the packed struct into a naturally-aligned local before
     * handing a uint64_t* into the signal/trampoline path. */
    uint64_t gpr[BX862_NGPR];
    memcpy(gpr, job->gpr, sizeof(gpr));
    uint64_t rflags = job->rflags;

    bx862_run_attempt(dst, gpr, rflags, out);
    out->length = job->enc_len;
    out->valid_length = 1;
    return 0;
}

int bx862_inject(struct bx862_arena *a, const struct bx862_job *job,
                  struct bx862_result *out)
{
    switch (job->mode) {
    case MODE_EXECUTE:
        return do_execute(a, job, out);
    case MODE_LENGTH:
    case MODE_BOTH:
    default: {
        uint8_t enc[BX862_MAX_ENC_LEN];
        memcpy(enc, job->enc, sizeof(enc));
        uint64_t gpr[BX862_NGPR];
        memcpy(gpr, job->gpr, sizeof(gpr));
        return bx862_resolve_length(a, enc, job->enc_len, gpr,
                                     job->rflags, out);
    }
    }
}

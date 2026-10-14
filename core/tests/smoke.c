/*
 * smoke.c — known-answer tests. IMPLEMENTATION_PLAN.md §3.6:
 * "If these five pass, the engine is trustworthy enough to scan."
 *
 * Expected values here are hand-derived from the Intel SDM / known x86-64
 * semantics, not yet cross-checked against XED (third_party/xed is not
 * wired in as of this writing — see IMPLEMENTATION_PLAN.md §10 item 2).
 * That cross-check is a follow-up hardening step, not a blocker for v1.
 */
#include "../injector/blacklist.h"
#include "../injector/inject.h"
#include "../injector/memmap.h"
#include "../injector/proto.h"
#include "../injector/signals.h"
#include "../injector/state.h"

#include <stdio.h>
#include <string.h>

static int g_pass = 0, g_fail = 0;

#define CHECK(desc, cond)                                                   \
    do {                                                                    \
        if (cond) {                                                        \
            printf("  [PASS] %s\n", desc);                                  \
            g_pass++;                                                      \
        } else {                                                           \
            printf("  [FAIL] %s\n", desc);                                  \
            g_fail++;                                                      \
        }                                                                  \
    } while (0)

static struct bx862_job make_length_job(const uint8_t *enc, uint8_t len,
                                         const uint64_t gpr[BX862_NGPR])
{
    struct bx862_job j;
    memset(&j, 0, sizeof(j));
    memcpy(j.enc, enc, len);
    j.enc_len = len;
    j.mode = MODE_BOTH;
    memcpy(j.gpr, gpr, BX862_NGPR * sizeof(uint64_t));
    return j;
}

static const char *fault_name(uint32_t fc)
{
    switch (fc) {
    case FAULT_NONE: return "NONE(executed)";
    case FAULT_UD: return "UD";
    case FAULT_BOUNDARY_PF: return "BOUNDARY_PF";
    case FAULT_GP_OR_PF: return "GP_OR_PF";
    case FAULT_FP: return "FP";
    case FAULT_BUS: return "BUS";
    default: return "UNKNOWN";
    }
}

int main(void)
{
    struct bx862_arena arena;
    if (bx862_arena_init(&arena) != 0) {
        fprintf(stderr, "arena_init failed\n");
        return 1;
    }
    int null_mapped = bx862_arena_try_map_null_page(&arena);
    printf("NULL page mapped: %s\n", null_mapped ? "yes" : "no (degraded mode)");

    if (bx862_signals_install(&arena) != 0) {
        fprintf(stderr, "signals_install failed\n");
        return 1;
    }

    uint64_t gpr[BX862_NGPR];
    bx862_state_zero_v1(&arena, gpr);

    printf("\n1. `90` (nop) -> length 1, executes cleanly\n");
    {
        uint8_t enc[] = { 0x90 };
        struct bx862_job j = make_length_job(enc, sizeof(enc), gpr);
        struct bx862_result r;
        bx862_inject(&arena, &j, &r);
        printf("  length=%u fault=%s\n", r.length, fault_name(r.fault_class));
        CHECK("nop: valid_length", r.valid_length);
        CHECK("nop: length == 1", r.length == 1);
        CHECK("nop: executed (FAULT_NONE)", r.fault_class == FAULT_NONE);
    }

    printf("\n2. `0f0b` (ud2) -> length 2, #UD\n");
    {
        uint8_t enc[] = { 0x0f, 0x0b };
        struct bx862_job j = make_length_job(enc, sizeof(enc), gpr);
        struct bx862_result r;
        bx862_inject(&arena, &j, &r);
        printf("  length=%u fault=%s\n", r.length, fault_name(r.fault_class));
        CHECK("ud2: valid_length", r.valid_length);
        CHECK("ud2: length == 2", r.length == 2);
        CHECK("ud2: FAULT_UD", r.fault_class == FAULT_UD);
    }

    printf("\n3. `40 90` (REX prefix + nop) -> length 2, executes\n");
    {
        /* REX.- (0x40) is a no-op-ish prefix here; 0x40 90 decodes as a
         * single 2-byte instruction (REX-prefixed NOP == XCHG eax,eax
         * with REX, still effectively a nop) on real x86-64 decoders. */
        uint8_t enc[] = { 0x40, 0x90 };
        struct bx862_job j = make_length_job(enc, sizeof(enc), gpr);
        struct bx862_result r;
        bx862_inject(&arena, &j, &r);
        printf("  length=%u fault=%s\n", r.length, fault_name(r.fault_class));
        CHECK("rex-nop: valid_length", r.valid_length);
        CHECK("rex-nop: length == 2", r.length == 2);
        CHECK("rex-nop: executed (FAULT_NONE)", r.fault_class == FAULT_NONE);
    }

    printf("\n4. `66 e9 00 00 00 00` -> length 6 on Intel "
           "(66 prefix IGNORED, paper's headline divergence)\n");
    {
        uint8_t enc[] = { 0x66, 0xe9, 0x00, 0x00, 0x00, 0x00 };
        struct bx862_job j = make_length_job(enc, sizeof(enc), gpr);
        struct bx862_result r;
        bx862_inject(&arena, &j, &r);
        printf("  length=%u fault=%s\n", r.length, fault_name(r.fault_class));
        printf("  (a 66-honoring disassembler would predict length 4 here — "
               "that's the divergence the paper describes)\n");
        CHECK("66e9: valid_length", r.valid_length);
        CHECK("66e9: length == 6 (prefix ignored)", r.length == 6);
    }

    printf("\n5. `f4` (hlt) from ring 3 -> exists, but privileged (not #UD)\n");
    {
        uint8_t enc[] = { 0xf4 };
        struct bx862_job j = make_length_job(enc, sizeof(enc), gpr);
        struct bx862_result r;
        bx862_inject(&arena, &j, &r);
        printf("  length=%u fault=%s\n", r.length, fault_name(r.fault_class));
        CHECK("hlt: valid_length", r.valid_length);
        CHECK("hlt: length == 1", r.length == 1);
        CHECK("hlt: privileged, not FAULT_UD (i.e. exists)",
              r.fault_class != FAULT_UD);
    }

    printf("\n6. blacklist sanity: `0f05` (syscall) refused in EXECUTE mode\n");
    {
        uint8_t enc[] = { 0x0f, 0x05 };
        CHECK("blacklist: syscall flagged", bx862_is_blacklisted(enc, 2));
        struct bx862_job j;
        memset(&j, 0, sizeof(j));
        memcpy(j.enc, enc, 2);
        j.enc_len = 2;
        j.mode = MODE_EXECUTE;
        memcpy(j.gpr, gpr, sizeof(gpr));
        struct bx862_result r;
        int rc = bx862_inject(&arena, &j, &r);
        CHECK("blacklist: EXECUTE refused (rc != 0)", rc != 0);
    }

    bx862_arena_destroy(&arena);

    printf("\n== %d passed, %d failed ==\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}

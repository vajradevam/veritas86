#include "blacklist.h"

static int is_legacy_prefix(uint8_t b)
{
    switch (b) {
    case 0x66: case 0x67:             /* operand/address size override */
    case 0xF0: case 0xF2: case 0xF3:  /* lock / repne / rep             */
    case 0x2E: case 0x36: case 0x3E:  /* CS/SS/DS segment override      */
    case 0x26: case 0x64: case 0x65:  /* ES/FS/GS segment override      */
        return 1;
    default:
        return 0;
    }
}

static int is_rex_prefix(uint8_t b)
{
    return (b & 0xF0) == 0x40;
}

int bx862_is_blacklisted(const uint8_t *enc, size_t enc_len)
{
    size_t i = 0;
    int saw_f3 = 0;

    /* Skip legacy prefixes (any order/count, heuristically). Remember
     * whether F3 specifically was among them -- needed below to
     * distinguish F3 0F AE (UMONITOR, blacklisted) from the unprefixed
     * and 66-prefixed forms of the same opcode (not blacklisted). */
    while (i < enc_len && is_legacy_prefix(enc[i])) {
        if (enc[i] == 0xF3)
            saw_f3 = 1;
        i++;
    }
    /* A single REX prefix may follow (and must be last before the opcode). */
    if (i < enc_len && is_rex_prefix(enc[i]))
        i++;

    if (i >= enc_len)
        return 0; /* nothing but prefixes; not our concern here */

    uint8_t op0 = enc[i];

    /* mov Sreg, r/m (segment load) */
    if (op0 == 0x8E)
        return 1;

    /* int 0x80 / int 0x0e */
    if (op0 == 0xCD && i + 1 < enc_len) {
        uint8_t imm = enc[i + 1];
        if (imm == 0x80 || imm == 0x0E)
            return 1;
    }

    /* two-byte opcodes: 0F {05 syscall, 34 sysenter, B2 lss, B4 lfs, B5 lgs,
     * A1 pop fs, A9 pop gs}. A1/A9 were found missing empirically (the
     * first full map0f sweep crashed the injector at `0f a1` -- POP FS
     * loads FS from the zeroed default GPR state, which breaks the
     * TLS-relative addressing the process (including this handler's own
     * recovery path) depends on before the fault-recovery path can run.
     * Same hazard class as mov Sreg/lss/lfs/lgs: never execute it. */
    if (op0 == 0x0F && i + 1 < enc_len) {
        uint8_t op1 = enc[i + 1];
        switch (op1) {
        case 0x05: /* syscall */
        case 0x34: /* sysenter */
        case 0xB2: /* lss */
        case 0xB4: /* lfs */
        case 0xB5: /* lgs */
        case 0xA1: /* pop fs */
        case 0xA9: /* pop gs */
            return 1;
        case 0xAE: /* group 15 -- only F3 0F AE /2 (UMONITOR) is unsafe
                     * here; the unprefixed and 66-prefixed forms of this
                     * opcode are fine (already swept safely). Found
                     * empirically: the sweep-3 corpus's full 256-ModRM
                     * sweep of F3 0F AE killed the daemon outright at
                     * every ModRM byte with reg field 010 (D0-D7), on a
                     * single isolated submission with no prior state --
                     * not a NULL-deref artifact (reproduces under
                     * scratch_v1 too) and not an accumulation effect
                     * (reproduces as the very first job a fresh daemon
                     * is given). The daemon dies to an uncaught signal
                     * that bypasses bx862_signals_install's own handler,
                     * the same failure signature as the Debian SIGBUS
                     * finding (docs/safety.md), but reproducible on
                     * every machine and deterministic in a single shot
                     * rather than after ~2000 jobs. Root cause not
                     * pinned down; treated the same as the other
                     * unrecoverable-from-a-handler cases above: never
                     * execute it. */
            if (saw_f3 && i + 2 < enc_len) {
                uint8_t modrm = enc[i + 2];
                uint8_t mod = modrm >> 6;
                uint8_t reg = (modrm >> 3) & 0x7;
                if (mod == 0x3 && reg == 0x2)
                    return 1;
            }
            break;
        default:
            break;
        }
    }

    return 0;
}

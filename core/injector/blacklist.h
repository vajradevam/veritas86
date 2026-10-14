/*
 * blacklist.h — the unrecoverable-encoding filter (IMPLEMENTATION_PLAN.md §3.5).
 *
 * Segment-register loads and syscall-entry instructions can corrupt
 * process state past what the signal handlers in signals.c can restore
 * (e.g. loading a bogus selector, or actually entering the kernel's
 * syscall path). We refuse to EXECUTE these; LENGTH-mode analysis of
 * them is still fine and still run.
 *
 * NOTE: this is a best-effort byte-pattern matcher, not a real decoder.
 * It does prefix-skipping (legacy prefixes + REX) then matches the
 * opcode. It does not attempt to fully parse ModRM/SIB, so it can be
 * over-broad (blocking a LENGTH-safe encoding from EXECUTE) but must
 * never be under-broad for the patterns it lists. Hardening TODO: once
 * third_party/xed is wired in (see IMPLEMENTATION_PLAN.md §10 item 2),
 * replace this with a real XED-based decode + blacklist check.
 *
 * LDS/LES (legacy 0xC4/0xC5) are deliberately not matched: in 64-bit
 * mode those bytes are repurposed as VEX prefixes and LDS/LES cannot be
 * encoded at all (SDM Vol. 2), so they need no special handling here.
 */
#ifndef BX862_BLACKLIST_H
#define BX862_BLACKLIST_H

#include <stddef.h>
#include <stdint.h>

/* Returns 1 if `enc` (enc_len bytes) matches a blacklisted, unrecoverable
 * pattern and must not be executed; 0 if it's safe to attempt EXECUTE. */
int bx862_is_blacklisted(const uint8_t *enc, size_t enc_len);

#endif /* BX862_BLACKLIST_H */

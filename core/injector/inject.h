/*
 * inject.h — mode dispatcher: Job -> Result.
 *
 * This is the one function both main.c (the pipe-driven daemon used by
 * the Python orchestrator) and core/tests/smoke.c (direct in-process
 * calls) go through. See proto.h for bx862_job/bx862_result layout.
 */
#ifndef BX862_INJECT_H
#define BX862_INJECT_H

#include "memmap.h"
#include "proto.h"

/* Returns 0 if the job ran (check out->valid_length / fault_class for
 * outcome), -1 if the job was refused outright (e.g. EXECUTE mode on a
 * blacklisted encoding — see blacklist.h). `a` must already be
 * initialized (bx862_arena_init) and have signals installed
 * (bx862_signals_install). */
int bx862_inject(struct bx862_arena *a, const struct bx862_job *job,
                  struct bx862_result *out);

#endif /* BX862_INJECT_H */

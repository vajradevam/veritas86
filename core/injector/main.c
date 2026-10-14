/*
 * main.c — the injector daemon.
 *
 * Reads fixed-size `struct bx862_job` records from stdin, writes
 * `struct bx862_result` records to stdout, one in one out, until EOF.
 * This is what orchestrator/tsfuzz/backends/ring3.py speaks to (see
 * docs/injector-protocol.md). Run this only ring-3, only under
 * scripts/safety_preflight.sh.
 */
#include "inject.h"
#include "memmap.h"
#include "proto.h"
#include "signals.h"
#include "state.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

static ssize_t read_full(int fd, void *buf, size_t n)
{
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, (char *)buf + got, n - got);
        if (r == 0)
            return (ssize_t)got; /* EOF */
        if (r < 0)
            return -1;
        got += (size_t)r;
    }
    return (ssize_t)got;
}

static int write_full(int fd, const void *buf, size_t n)
{
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = write(fd, (const char *)buf + sent, n - sent);
        if (w < 0)
            return -1;
        sent += (size_t)w;
    }
    return 0;
}

int main(void)
{
    struct bx862_arena arena;
    if (bx862_arena_init(&arena) != 0) {
        fprintf(stderr, "injector: arena_init failed\n");
        return 1;
    }
    if (!bx862_arena_try_map_null_page(&arena)) {
        fprintf(stderr,
                "injector: NULL page not mapped (vm.mmap_min_addr?) — "
                "continuing without it\n");
    }
    if (bx862_signals_install(&arena) != 0) {
        fprintf(stderr, "injector: signals_install failed\n");
        return 1;
    }

    /* Handshake: tell the caller the only rsp value known-safe for this
     * process instance (see proto.h bx862_hello). Must be sent before
     * any job is read. */
    struct bx862_hello hello;
    memset(&hello, 0, sizeof(hello));
    hello.null_page_mapped = (uint8_t)arena.null_page_mapped;
    uint64_t default_gpr[BX862_NGPR];
    bx862_state_zero_v1(&arena, default_gpr);
    memcpy(hello.default_gpr, default_gpr, sizeof(default_gpr));
    if (write_full(STDOUT_FILENO, &hello, sizeof(hello)) != 0) {
        fprintf(stderr, "injector: hello write failed, exiting\n");
        return 1;
    }

    struct bx862_job job;
    struct bx862_result res;

    for (;;) {
        ssize_t r = read_full(STDIN_FILENO, &job, sizeof(job));
        if (r == 0)
            break; /* clean EOF */
        if (r != (ssize_t)sizeof(job)) {
            fprintf(stderr, "injector: short/invalid job read, exiting\n");
            return 1;
        }

        bx862_inject(&arena, &job, &res);

        if (write_full(STDOUT_FILENO, &res, sizeof(res)) != 0) {
            fprintf(stderr, "injector: write failed, exiting\n");
            return 1;
        }
    }

    bx862_arena_destroy(&arena);
    return 0;
}

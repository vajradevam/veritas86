#include "memmap.h"

#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

int bx862_arena_init(struct bx862_arena *a)
{
    memset(a, 0, sizeof(*a));
    long ps = sysconf(_SC_PAGESIZE);
    if (ps <= 0)
        return -1;
    a->page_size = (size_t)ps;

    size_t total = a->page_size * 4;
    void *base = mmap(NULL, total, PROT_NONE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED)
        return -1;

    uint8_t *b = (uint8_t *)base;
    a->exec_page       = b + 0 * a->page_size;
    a->guard_page       = b + 1 * a->page_size;
    a->scratch_page      = b + 2 * a->page_size;
    a->spare_guard_page  = b + 3 * a->page_size;

    if (mprotect(a->exec_page, a->page_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
        goto fail;
    if (mprotect(a->scratch_page, a->page_size, PROT_READ | PROT_WRITE) != 0)
        goto fail;
    /* guard_page and spare_guard_page stay PROT_NONE. */

    /* Zero exec/scratch so stale bytes never leak between candidates. */
    memset(a->exec_page, 0, a->page_size);
    memset(a->scratch_page, 0, a->page_size);

    return 0;

fail:
    munmap(base, total);
    memset(a, 0, sizeof(*a));
    return -1;
}

int bx862_arena_try_map_null_page(struct bx862_arena *a)
{
    void *r = mmap((void *)0, a->page_size, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                    -1, 0);
    if (r == MAP_FAILED)
        return 0; /* EPERM under default vm.mmap_min_addr, or unsupported */
    memset(r, 0, a->page_size);
    a->null_page_mapped = 1;
    return 1;
}

void bx862_arena_destroy(struct bx862_arena *a)
{
    if (a->exec_page)
        munmap(a->exec_page, a->page_size * 4);
    if (a->null_page_mapped)
        munmap((void *)0, a->page_size);
    memset(a, 0, sizeof(*a));
}

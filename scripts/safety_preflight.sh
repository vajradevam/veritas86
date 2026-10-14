#!/usr/bin/env bash
# safety_preflight.sh — gate every injector run (IMPLEMENTATION_PLAN.md §11).
#
# Checks the environment is what the injector's safety assumptions expect,
# and refuses to proceed (or warns loudly) otherwise. Run before `just smoke`,
# before any experiment, and from the daemon's own launch wrapper.
set -euo pipefail

warn()  { echo "  [WARN]  $*" >&2; }
ok()    { echo "  [ OK ]  $*"; }
fail()  { echo "  [FAIL]  $*" >&2; FAILED=1; }

FAILED=0

echo "== bx862 safety preflight =="

# 1. We must be x86_64 — the injector's asm is architecture-specific.
if [[ "$(uname -m)" != "x86_64" ]]; then
    fail "not running on x86_64 (uname -m = $(uname -m))"
else
    ok "x86_64"
fi

# 2. Refuse to run as root by default — ring-3 fuzzing does not need it,
#    and running as root defeats a chunk of the isolation this project
#    relies on. Sacrificial ring-0 work (Idea 4/5) is a DELIBERATE
#    exception and sets BX862_SACRIFICIAL=1 to skip this check.
if [[ "${BX862_SACRIFICIAL:-0}" != "1" ]]; then
    if [[ "$(id -u)" == "0" ]]; then
        fail "running as root without BX862_SACRIFICIAL=1 — refusing." \
             " Ring-3 fuzzing should never need root; if this really is" \
             " the sacrificial box for Idea 4/5, set BX862_SACRIFICIAL=1."
    else
        ok "not running as root"
    fi
else
    warn "BX862_SACRIFICIAL=1 set — ring-0/MSR-class experiments permitted." \
         " This machine should be the disposable Xeon, nothing else."
fi

# 3. vm.mmap_min_addr — informational only. The injector degrades
#    gracefully without the NULL page (memmap.c), so this is not fatal,
#    just worth knowing.
MMAP_MIN_ADDR="$(sysctl -n vm.mmap_min_addr 2>/dev/null || echo unknown)"
if [[ "$MMAP_MIN_ADDR" == "0" ]]; then
    ok "vm.mmap_min_addr=0 — NULL page mapping available"
else
    warn "vm.mmap_min_addr=$MMAP_MIN_ADDR — NULL page will NOT be mapped;" \
         " injector runs in degraded mode (see memmap.h). This is fine for" \
         " zero_v1 (default), but zero_nullmapped_v1 must not be used."
fi

# 4. core dumps off — a crashing candidate shouldn't leave a giant core
#    file from what may be a tight fuzzing loop.
if ulimit -c | grep -qx 0; then
    ok "core dumps disabled (ulimit -c = 0)"
else
    warn "core dumps enabled (ulimit -c = $(ulimit -c)) — consider 'ulimit -c 0'"
fi

echo
if [[ "$FAILED" == "1" ]]; then
    echo "== preflight FAILED =="
    exit 1
fi
echo "== preflight OK =="

#!/usr/bin/env bash
# env_probe.sh — dump cpuid/microcode/identity state for this machine.
# Used to populate the "identity" block stored once per fingerprint
# collection run (IMPLEMENTATION_PLAN.md §4).
set -euo pipefail

echo "== machine =="
hostname
uname -srm

echo
echo "== cpu =="
grep -m1 'model name' /proc/cpuinfo || true
grep -m1 'microcode'  /proc/cpuinfo || true
grep -m1 'stepping'   /proc/cpuinfo || true

echo
echo "== microcode (sysfs) =="
for f in /sys/devices/system/cpu/cpu0/microcode/version; do
    [[ -r "$f" ]] && echo "$f: $(cat "$f")"
done

echo
echo "== hybrid core check (informational — see EXTENSION_IDEAS.md Idea 2) =="
if grep -qi 'hybrid' /proc/cpuinfo 2>/dev/null; then
    echo "hybrid flag present in /proc/cpuinfo"
else
    echo "no hybrid indicator found (expected on this fleet — no P/E-core part)"
fi

echo
echo "== msr module =="
if lsmod | grep -q '^msr'; then
    echo "msr module loaded"
elif [[ -e /dev/cpu/0/msr ]]; then
    echo "/dev/cpu/0/msr present"
else
    echo "msr module NOT loaded — run: sudo modprobe msr"
fi

echo
echo "== vm.mmap_min_addr =="
sysctl vm.mmap_min_addr 2>/dev/null || echo "unreadable"

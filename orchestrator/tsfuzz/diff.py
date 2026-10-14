"""
diff.py — load N fingerprint JSONL runs (runner.py output) and report
per-encoding divergences in length/fault class across machines/CPUs.

This is the first real cross-silicon result the project is after: does
the *same byte sequence* decode/fault/execute identically on different
Intel parts (different microarchitecture generations, different
microcode revisions, different kernels)? Any row that doesn't agree
across all loaded runs is architecturally interesting by construction —
either a true silicon/microcode difference, or a bug in the harness
(duplicated as a to-check list either way).

Usage:
    python3 -m tsfuzz.diff data/fingerprints/*.jsonl
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path


def load(path: Path) -> tuple[dict, dict[str, dict]]:
    lines = path.read_text().splitlines()
    identity = json.loads(lines[0])["_identity"]
    name = path.stem
    by_label = {}
    for line in lines[1:]:
        rec = json.loads(line)
        key = (rec["label"], rec.get("state", "zero_v1"))
        by_label[key] = rec
    return identity, by_label, name


def main() -> int:
    paths = [Path(p) for p in sys.argv[1:]]
    if len(paths) < 2:
        print("usage: python3 -m tsfuzz.diff <a.jsonl> <b.jsonl> [...]", file=sys.stderr)
        return 2

    runs = []  # (name, identity, {label: rec})
    for p in paths:
        identity, by_label, name = load(p)
        runs.append((name, identity, by_label))

    print(f"== {len(runs)} runs loaded ==")
    for name, identity, by_label in runs:
        cpu = identity.get("cpu_model", "?")
        ucode = identity.get("microcode", "?")
        print(f"  {name:16s} {cpu:45s} microcode={ucode:8s} n={len(by_label)}")
    print()

    labels = set(runs[0][2].keys())
    for _, _, by_label in runs[1:]:
        labels &= set(by_label.keys())

    FIELDS = ("length", "fault", "in_arena")
    divergences = []
    for label in sorted(labels):
        vals = [tuple(by_label[label].get(f) for f in FIELDS) for _, _, by_label in runs]
        if len(set(vals)) > 1:
            divergences.append(label)

    print(f"== {len(divergences)} / {len(labels)} (label,state) rows diverge across runs ==\n")

    by_fault = defaultdict(list)
    MAX_PRINT = 200
    for i, key in enumerate(divergences):
        label, state = key
        row = [runs[0][2][key]["enc"]] + [
            f"{by_label[key]['length']}/{by_label[key]['fault']}"
            + ("" if by_label[key]["in_arena"] else "*")
            for _, _, by_label in runs
        ]
        if i < MAX_PRINT:
            print(f"  {label:24s} state={state:11s} enc={row[0]:32s} " + "  ".join(
                f"{name}={v}" for (name, _, _), v in zip(runs, row[1:])
            ))
        fault_sig = tuple(by_label[key]["fault"] for _, _, by_label in runs)
        by_fault[fault_sig].append(key)
    if len(divergences) > MAX_PRINT:
        print(f"  ... ({len(divergences) - MAX_PRINT} more rows omitted, see by-pattern summary below)")

    print("\n(* = post-execution RIP left the arena, e.g. a control-flow instr like ret/jmp -- expected, not a bug)")

    print("\n== divergence patterns (fault-class tuple -> count) ==")
    for sig, labs in sorted(by_fault.items(), key=lambda kv: -len(kv[1])):
        names = [r[0] for r in runs]
        print(f"  {dict(zip(names, sig))}: {len(labs)} encodings, e.g. {labs[:5]}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

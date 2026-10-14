# Veritas86 top-level build/run targets
# Install `just`: https://github.com/casey/just  (or translate to a Makefile if preferred)

default:
    @just --list

# --- build ---

build:
    make -C core/injector
    make -C core/tests

clean:
    make -C core/injector clean
    make -C core/tests clean

# --- safety-gated test/run ---

smoke: build
    ./scripts/safety_preflight.sh
    ./core/tests/smoke

# orchestrator-level tests, driving the real injector subprocess over the
# wire protocol (not the in-process C API core/tests/smoke.c uses)
pytest: build
    ./scripts/safety_preflight.sh
    python3 -m pytest orchestrator/tests -v

# run the full corpus sweep on this machine, writing
# data/fingerprints/<hostname>.jsonl
sweep: build
    ./scripts/safety_preflight.sh
    cd orchestrator && python3 -m tsfuzz.runner

# cross-machine diff over any number of collected .jsonl files
diff *files:
    python3 -m orchestrator.tsfuzz.diff {{files}}

# --- env probing ---

probe:
    ./scripts/env_probe.sh

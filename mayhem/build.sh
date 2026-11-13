#!/usr/bin/env bash
#
# mayhem/build.sh — build this repo's fuzz harness(es). EDIT per repo.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# VirtualSMC is a macOS kernel extension, so it cannot be built on Linux as upstream documents. Instead the
# real upstream sources below are compiled unmodified against a small user-space shim of the XNU/Lilu
# headers (mayhem/shim) and linked into each harness.
VSMC_SRCS=(
  VirtualSMC/kern_keystore.cpp
  VirtualSMC/kern_keys.cpp
  VirtualSMC/kern_keyvalue.cpp
  VirtualSMC/kern_value.cpp
  VirtualSMC/kern_vsmcapi.cpp
)
VSMC_FLAGS=(-std=c++17 -I"$SRC" -I"$SRC/mayhem/shim" -Dkern_vsmc_hpp -Dkern_efiend_h
            -include "$SRC/mayhem/shim/vsmc_stub.hpp" -Wno-mismatched-tags -Wno-unused-command-line-argument)
TARGETS=(keystore smccodec keyvalue)

OBJ="$SRC/build/mayhem"
rm -rf "$OBJ"
mkdir -p "$OBJ/san" "$OBJ/plain"

# 1) Upstream objects, sanitized + DWARF 3 + SanCov (fuzzer-no-link), for the harnesses.
pids=()
for s in "${VSMC_SRCS[@]}"; do
  # shellcheck disable=SC2086
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link "${VSMC_FLAGS[@]}" \
       -c "$SRC/$s" -o "$OBJ/san/$(basename "$s" .cpp).o" &
  pids+=($!)
done
for p in "${pids[@]}"; do wait "$p"; done

# 2) Harnesses: once with libFuzzer, once with the standalone single-input driver.
# shellcheck disable=SC2086
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OBJ/standalone_main.o"
# shellcheck disable=SC2086
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$OBJ/lsan_off.o"
for t in "${TARGETS[@]}"; do
  # shellcheck disable=SC2086
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link "${VSMC_FLAGS[@]}" \
       -c "$SRC/mayhem/$t/${t}_harness.cpp" -o "$OBJ/${t}_harness.o"
  # shellcheck disable=SC2086
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE \
       "$OBJ/${t}_harness.o" "$OBJ"/san/*.o "$OBJ/lsan_off.o" -o "$SRC/$t"
  # shellcheck disable=SC2086
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS \
       "$OBJ/${t}_harness.o" "$OBJ"/san/*.o "$OBJ/standalone_main.o" "$OBJ/lsan_off.o" -o "$SRC/$t-standalone"
done

# 3) Known-answer probe for mayhem/test.sh: the same upstream sources with NORMAL flags (no sanitizers, no SanCov).
pids=()
for s in "${VSMC_SRCS[@]}"; do
  # shellcheck disable=SC2086
  $CXX -O1 $COVERAGE_FLAGS "${VSMC_FLAGS[@]}" -c "$SRC/$s" -o "$OBJ/plain/$(basename "$s" .cpp).o" &
  pids+=($!)
done
for p in "${pids[@]}"; do wait "$p"; done
$CXX -O1 $COVERAGE_FLAGS "${VSMC_FLAGS[@]}" "$SRC/mayhem/kat.cpp" "$OBJ"/plain/*.o -o "$SRC/vsmc_kat"

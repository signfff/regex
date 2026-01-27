#!/usr/bin/env bash
LLVM_PROFDATA="$(rustc --print sysroot)/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-profdata"
LLVM_COV="$(rustc --print sysroot)/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-cov"

PROF_DIR="/home/lxy/regex_fuzzing/regex/fuzz/results/log/fuzz_2"
TARGET_DIR="/home/lxy/regex_fuzzing/regex/fuzz/target/target_2/x86_64-unknown-linux-gnu/release"

$LLVM_PROFDATA merge -sparse $PROF_DIR/*.profraw -o "$PROF_DIR/coverage.profdata"

$LLVM_COV report "$TARGET_DIR/fuzz_diff_eqs" \
  -instr-profile="$PROF_DIR/coverage.profdata" \
  > "$PROF_DIR/coverage-summary.txt"

  
# $(rustc --print sysroot)/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-profdata merge -sparse fuzz_1/*.profdata fuzz_2/*.profdata -o cov_all.profdata
#!/usr/bin/env bash
LLVM_PROFDATA="$(rustc --print sysroot)/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-profdata"
LLVM_COV="$(rustc --print sysroot)/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-cov"

COVERAGE_PROFDATA_DIR="/home/lxy/regex_fuzzing/regex/coverage_data"


PROF_DIR="/home/lxy/regex_fuzzing/regex/fuzz/results/log"
TARGET_DIR="/home/lxy/regex_fuzzing/regex/fuzz/target/x86_64-unknown-linux-gnu/release"

$LLVM_PROFDATA merge -sparse $PROF_DIR/*.profraw -o "$COVERAGE_PROFDATA_DIR/coverage.profdata"

# $LLVM_PROFDATA merge -sparse "$COVERAGE_PROFDATA_DIR"/*.profdata -o "$COVERAGE_PROFDATA_DIR/merged.profdata"

SOURCE_DIR="/home/lxy/regex_fuzzing/regex/fuzz/target/x86_64-unknown-linux-gnu/release/fuzz_diff_eqs"
$LLVM_COV report "$SOURCE_DIR" \
  -instr-profile="$COVERAGE_PROFDATA_DIR/coverage.profdata" \
  -ignore-filename-regex="fuzz/src/diff.rs" \
  -ignore-filename-regex="fuzz/src/eqs.rs" \
  > "$COVERAGE_PROFDATA_DIR/coverage-summary-empty-corpus.txt"
# $LLVM_COV report "$TARGET_DIR/fuzz_diff_eqs" \
#   -instr-profile="$PROF_DIR/coverage.profdata" \
#   > "$PROF_DIR/coverage-summary.txt"

  
# $(rustc --print sysroot)/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-profdata merge -sparse fuzz_1/*.profdata fuzz_2/*.profdata -o cov_all.profdata
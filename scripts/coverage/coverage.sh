#!/usr/bin/env bash
LLVM_PROFDATA="$(rustc --print sysroot)/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-profdata"
LLVM_COV="$(rustc --print sysroot)/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-cov"

COVERAGE_PROFDATA_DIR="/home/lxy/regex_fuzzing/regex/coverage_data"
THREADS=10
# for i in $(seq 1 $THREADS); do
#   PROF_DIR="/home/lxy/regex_fuzzing/regex/fuzz/results/log/fuzz_${i}"
#   TARGET_DIR="/home/lxy/regex_fuzzing/regex/fuzz/target/target_${i}/x86_64-unknown-linux-gnu/release"

#   $LLVM_PROFDATA merge -sparse $PROF_DIR/*.profraw -o "$COVERAGE_PROFDATA_DIR/coverage_${i}.profdata"
# done
$LLVM_PROFDATA merge -sparse "$COVERAGE_PROFDATA_DIR"/*.profdata -o "$COVERAGE_PROFDATA_DIR/merged.profdata"

SOURCE_DIR="/home/lxy/regex_fuzzing/regex/fuzz/target/target_1/x86_64-unknown-linux-gnu/release/fuzz_diff_eqs"
$LLVM_COV report "$SOURCE_DIR" \
  -instr-profile="$COVERAGE_PROFDATA_DIR/merged.profdata" \
  > "$COVERAGE_PROFDATA_DIR/coverage-summary.txt"
# $LLVM_COV report "$TARGET_DIR/fuzz_diff_eqs" \
#   -instr-profile="$PROF_DIR/coverage.profdata" \
#   > "$PROF_DIR/coverage-summary.txt"

  
# $(rustc --print sysroot)/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-profdata merge -sparse fuzz_1/*.profdata fuzz_2/*.profdata -o cov_all.profdata
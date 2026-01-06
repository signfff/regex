#!/usr/bin/env bash
set -euo pipefail

cd /home/lxy/regex_fuzzing/regex/fuzz
BASE_DIR="/home/lxy/regex_fuzzing/regex/fuzz/results"
TARGET="fuzz_diff_eqs"
THREADS=10
MAX_LEN=512
MAX_TIME=43200

mkdir -p "$BASE_DIR"

for i in $(seq 1 $THREADS); do
  (
    export FUZZ_DIFF_LOG="$BASE_DIR/fuzz_differential_failures_$i.log"
    export FUZZ_META_LOG="$BASE_DIR/fuzz_metamorphic_failures_$i.log"
    : > "$FUZZ_DIFF_LOG"
    : > "$FUZZ_META_LOG"

    echo "[*] Starting fuzz worker $i"

    export CARGO_TARGET_DIR="/home/lxy/regex_fuzzing/regex/fuzz/target/target_$i"
    export LLVM_PROFILE_FILE="$BASE_DIR/prof_${i}_%p.profraw"
    CORPUS="/home/lxy/regex_fuzzing/regex/fuzz/corpus/corpus_$i"
    rm -rf $CORPUS
    mkdir -p $CORPUS

    cargo fuzz run "$TARGET" "$CORPUS" -- \
      -max_len="$MAX_LEN" \
      -max_total_time="$MAX_TIME" \
      -jobs=1
  ) &
done

wait
echo "[*] All fuzz workers finished"

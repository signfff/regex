#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="/home/lxy/regex_fuzzing/regex/fuzz/results"
RESULT_FILE="$BASE_DIR/nonemptyFile.log"
THREADS=10

mkdir -p "$BASE_DIR"
rm -f "$RESULT_FILE"
touch "$RESULT_FILE"
for i in $(seq 1 $THREADS); do
    FUZZ_DIFF_LOG="$BASE_DIR/fuzz_differential_failures_$i.log"
    FUZZ_META_LOG="$BASE_DIR/fuzz_metamorphic_failures_$i.log"
    if [[ -s "$FUZZ_DIFF_LOG" ]]; then   # -s 检查文件非空
        echo "$FUZZ_DIFF_LOG" >> "$RESULT_FILE"
    fi
    if [[ -s "$FUZZ_META_LOG" ]]; then   # -s 检查文件非空
        echo "$FUZZ_META_LOG" >> "$RESULT_FILE"
    fi
done



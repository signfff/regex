#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="/home/monsoon/regex/fuzz/results"
TARGET="fuzz_diff_eqs"
THREADS=10
MAX_LEN=512
MAX_TIME=600

mkdir -p "$BASE_DIR"

for i in $(seq 1 $THREADS); do
  (
    export FUZZ_DIFF_LOG="$BASE_DIR/fuzz_differential_failures_$i.log"
    export FUZZ_META_LOG="$BASE_DIR/fuzz_metamorphic_failures_$i.log"

    : > "$FUZZ_DIFF_LOG"
    : > "$FUZZ_META_LOG"

    echo "[*] Starting fuzz worker $i"

    cargo fuzz run "$TARGET" -- \
      -max_len="$MAX_LEN" \
      -max_total_time="$MAX_TIME"
  ) &
done

wait
echo "[*] All fuzz workers finished"

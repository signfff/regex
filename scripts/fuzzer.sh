#!/usr/bin/env bash
set -euo pipefail

# Get the absolute path to the fuzz directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
FUZZ_DIR="$REPO_ROOT/fuzz"

cd "$FUZZ_DIR"
BASE_DIR="$FUZZ_DIR/results"
TARGET="fuzz_diff_eqs"
THREADS=10
MAX_LEN=512
MAX_TIME=90000 # 25h
# MAX_TIME=120 # 2min

rm -rf "$FUZZ_DIR/target"
mkdir -p "$BASE_DIR"
mkdir -p "$BASE_DIR/differential"
mkdir -p "$BASE_DIR/metamorphic"
mkdir -p "$BASE_DIR/log"

for i in $(seq 1 $THREADS); do
  (
    export FUZZ_DIFF_LOG="$BASE_DIR/differential/fuzz_differential_failures_$i.log"
    export FUZZ_META_LOG="$BASE_DIR/metamorphic/fuzz_metamorphic_failures_$i.log"
    export LOG_FILE_DIR="$BASE_DIR/log/fuzz_$i"

    rm -f "$FUZZ_DIFF_LOG"
    rm -f "$FUZZ_META_LOG"
    rm -rf "$LOG_FILE_DIR"

    touch "$FUZZ_DIFF_LOG"
    touch "$FUZZ_META_LOG"
    mkdir -p "$LOG_FILE_DIR"

    echo "[*] Starting fuzz worker $i"
    cd "$LOG_FILE_DIR"
    export CARGO_TARGET_DIR="$FUZZ_DIR/target/target_$i"
    export RUSTFLAGS="-Cinstrument-coverage"
    export LLVM_PROFILE_FILE="$LOG_FILE_DIR/prof_${i}_%p.profraw"
    CORPUS="$FUZZ_DIR/corpus/corpus_$i"
    rm -rf "$CORPUS"
    mkdir -p "$CORPUS"

    cargo fuzz run "$TARGET" "$CORPUS" -- \
      -max_len="$MAX_LEN" \
      -max_total_time="$MAX_TIME" \
      -jobs=1
  ) &
done

wait
echo "[*] All fuzz workers finished"

#!/usr/bin/env bash
set -euo pipefail

# Get the absolute path to the fuzz directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
FUZZ_DIR="$REPO_ROOT/fuzz"

cd "$FUZZ_DIR"
BASE_DIR="$FUZZ_DIR/results"
TARGET="fuzz_diff_eqs"
THREADS=8
MAX_LEN=512
# MAX_TIME=90000 # 25h
MAX_TIME=1200

rm -rf "$FUZZ_DIR/target"
rm -rf "$BASE_DIR"
mkdir -p "$BASE_DIR"
mkdir -p "$BASE_DIR/differential"
mkdir -p "$BASE_DIR/metamorphic"
mkdir -p "$BASE_DIR/log"

# Export base log paths
# The Rust code will append _<PID> before the extension
export FUZZ_DIFF_LOG="$BASE_DIR/differential/fuzz_differential_failures.log"
export FUZZ_META_LOG="$BASE_DIR/metamorphic/fuzz_metamorphic_failures.log"
export LOG_FILE_DIR="$BASE_DIR/log"

# Clean up old logs if needed
rm -rf "$LOG_FILE_DIR"
mkdir -p "$LOG_FILE_DIR"

echo "[*] Starting fuzz workers with $THREADS threads (jobs)"
cd "$LOG_FILE_DIR"

# Set up coverage profiling
export RUSTFLAGS="-Cinstrument-coverage"
export LLVM_PROFILE_CONTINUOUS_MODE="ON" 
export LLVM_PROFILE_DATA_SCHEME="continuous"
export LLVM_PROFILE_PERIODIC_FLUSH="10" 
export LLVM_PROFILE_FILE="$LOG_FILE_DIR/prof_%p.profraw"

# Shared corpus directory
CORPUS="$FUZZ_DIR/corpus/fuzz_diff_eqs"
# rm -rf "$CORPUS"
# mkdir -p "$CORPUS"

# Run cargo fuzz with jobs parameter
cargo clean
cargo fuzz run "$TARGET" "$CORPUS" -- \
  -max_len="$MAX_LEN" \
  -max_total_time="$MAX_TIME" \
  -jobs=$THREADS

echo "[*] All fuzz workers finished"
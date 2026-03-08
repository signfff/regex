#!/bin/bash
set -euo pipefail

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------
# Root directory of the regex project (as per your path description)
PROJECT_ROOT="/home/lxy/regex_fuzzing/regex"
FUZZ_ROOT="$PROJECT_ROOT/fuzz"
OUTPUT_DIR="$PROJECT_ROOT/coverage_data"

# Fuzz target name
TARGET="fuzz_diff_eqs"

# Source corpus directory (where the fuzzing results are stored)
CORPUS_SRC_DIR="$FUZZ_ROOT/corpus"

# Temporary directory for merged corpus (will be created)
MERGED_CORPUS_DIR="$OUTPUT_DIR/merged_corpus"

# -----------------------------------------------------------------------------
# Toolchain Setup
# -----------------------------------------------------------------------------
# Dynamically find the llvm tools from the rust toolchain
RUST_SYSROOT=$(rustc --print sysroot)
LLVM_PROFDATA="$RUST_SYSROOT/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-profdata"
LLVM_COV="$RUST_SYSROOT/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-cov"

# Fallback to system tools if rust-specific ones are missing
if [ ! -f "$LLVM_PROFDATA" ]; then LLVM_PROFDATA="llvm-profdata"; fi
if [ ! -f "$LLVM_COV" ]; then LLVM_COV="llvm-cov"; fi

echo "Using llvm-profdata: $LLVM_PROFDATA"
echo "Using llvm-cov: $LLVM_COV"

# -----------------------------------------------------------------------------
# Step 1: Prepare Directories and Merge Corpus
# -----------------------------------------------------------------------------
echo "--------------------------------------------------"
echo "Step 1: Merging corpus from all workers..."
echo "--------------------------------------------------"

# Ensure output directory exists
mkdir -p "$OUTPUT_DIR"
mkdir -p "$MERGED_CORPUS_DIR"

# Clean up old merged corpus to avoid stale data
rm -rf "$MERGED_CORPUS_DIR/*"

# Find all corpus directories (corpus_1, corpus_2, etc.) and copy their contents
# We use 'find' to handle potential variations in naming or depth
find "$CORPUS_SRC_DIR" -maxdepth 1 -name "corpus_*" -type d | while read -r dir; do
    echo "  Merging from: $dir"
    # Copy files, suppressing errors if directory is empty
    cp -r "$dir"/* "$MERGED_CORPUS_DIR/" 2>/dev/null || true
done

COUNT=$(ls -1 "$MERGED_CORPUS_DIR" | wc -l)
echo "Total corpus files merged: $COUNT"

if [ "$COUNT" -eq 0 ]; then
    echo "Error: No corpus files found! Cannot proceed with coverage."
    exit 1
fi

# -----------------------------------------------------------------------------
# Step 2: Replay Corpus to Generate Coverage
# -----------------------------------------------------------------------------
echo "--------------------------------------------------"
echo "Step 2: Replaying corpus with coverage instrumentation..."
echo "--------------------------------------------------"

# Clean up previous coverage data
rm -f "$OUTPUT_DIR"/*.profraw
rm -f "$OUTPUT_DIR"/*.profdata

# Set environment variables for coverage
export RUSTFLAGS="-C instrument-coverage"
export LLVM_PROFILE_FILE="$OUTPUT_DIR/coverage-%p-%m.profraw"

# Change to fuzz directory to run cargo fuzz
cd "$FUZZ_ROOT"

echo "Building and running coverage target..."
# 'cargo fuzz coverage' builds a special binary instrumented for coverage
# and runs it against the provided corpus.
# We use the merged corpus directory as input.
cargo fuzz coverage "$TARGET" "$MERGED_CORPUS_DIR"

# -----------------------------------------------------------------------------
# Step 3: Generate Report
# -----------------------------------------------------------------------------
echo "--------------------------------------------------"
echo "Step 3: Generating coverage report..."
echo "--------------------------------------------------"

# Merge the generated profraw files
"$LLVM_PROFDATA" merge -sparse "$OUTPUT_DIR"/*.profraw -o "$OUTPUT_DIR/coverage.profdata"

# Locate the coverage binary
# It is typically in target/x86_64-unknown-linux-gnu/coverage/x86_64-unknown-linux-gnu/release/
# or similar, depending on the platform. We search for it.
# We look for the file that is executable and matches the target name within the coverage directory.
COV_BINARY=$(find "$FUZZ_ROOT/target" -name "$TARGET" -type f -path "*/coverage/*" | head -n 1)

if [ -z "$COV_BINARY" ]; then
    echo "Error: Could not find the coverage binary."
    echo "Please check if 'cargo fuzz coverage' compiled successfully."
    exit 1
fi

echo "Found coverage binary: $COV_BINARY"

# Generate textual summary
"$LLVM_COV" report \
    "$COV_BINARY" \
    -instr-profile="$OUTPUT_DIR/coverage.profdata" \
    -ignore-filename-regex="/.cargo/registry" \
    -ignore-filename-regex="/rustc/" \
    -ignore-filename-regex="fuzz_targets" \
    > "$OUTPUT_DIR/coverage_summary.txt"

echo "Summary report generated at: $OUTPUT_DIR/coverage_summary.txt"

# Generate HTML report (optional but recommended)
# "$LLVM_COV" show \
#     "$COV_BINARY" \
#     -instr-profile="$OUTPUT_DIR/coverage.profdata" \
#     -ignore-filename-regex="/.cargo/registry" \
#     -ignore-filename-regex="/rustc/" \
#     -ignore-filename-regex="fuzz_targets" \
#     -format=html \
#     -output-dir="$OUTPUT_DIR/html_report"

# echo "HTML report generated at: $OUTPUT_DIR/html_report/index.html"
echo "Done."

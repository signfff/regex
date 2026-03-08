#!/bin/bash
set -euo pipefail

# 配置路径
PROJECT_ROOT="/home/lxy/regex_fuzzing/regex"
FUZZ_ROOT="$PROJECT_ROOT/fuzz"
RESULTS_DIR="$FUZZ_ROOT/results/log"
OUTPUT_DIR="$PROJECT_ROOT/coverage_data_quick"
TARGET="fuzz_diff_eqs"

# Worker 范围
START_ID=1
END_ID=10

# 工具链
RUST_SYSROOT=$(rustc --print sysroot)
LLVM_PROFDATA="$RUST_SYSROOT/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-profdata"
LLVM_COV="$RUST_SYSROOT/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-cov"

mkdir -p "$OUTPUT_DIR"

echo "--------------------------------------------------"
echo "正在快速生成覆盖率报告 (不重跑)..."
echo "--------------------------------------------------"

for i in $(seq $START_ID $END_ID); do
    # 关键：找到对应的二进制文件和 profraw 目录
    WORKER_LOG_DIR="$RESULTS_DIR/fuzz_$i"
    # 二进制文件位于 target/target_i/... 下
    WORKER_BINARY="$FUZZ_ROOT/target/target_$i/x86_64-unknown-linux-gnu/release/$TARGET"
    WORKER_PROFDATA="$OUTPUT_DIR/worker_$i.profdata"
    
    if [ ! -d "$WORKER_LOG_DIR" ] || [ ! -f "$WORKER_BINARY" ]; then
        echo "跳过 Worker $i: 找不到日志或二进制文件"
        continue
    fi
    
    echo "处理 Worker $i..."
    
    # 1. 合并该 Worker 的 profraw (忽略损坏的文件)
    "$LLVM_PROFDATA" merge -sparse "$WORKER_LOG_DIR"/*.profraw -o "$WORKER_PROFDATA" 2>/dev/null || true
    
    if [ ! -f "$WORKER_PROFDATA" ]; then
        echo "  无法生成 profdata"
        continue
    fi
    
    # 2. 生成该 Worker 的报告
    REPORT_FILE="$OUTPUT_DIR/report_worker_$i.txt"
    "$LLVM_COV" report \
        "$WORKER_BINARY" \
        -instr-profile="$WORKER_PROFDATA" \
        -ignore-filename-regex="/.cargo/registry" \
        -ignore-filename-regex="/rustc/" \
        -ignore-filename-regex="fuzz_targets" \
        > "$REPORT_FILE"
        
    # 3. 提取覆盖率百分比
    COV_LINE=$(grep "TOTAL" "$REPORT_FILE" | awk '{print $NF}')
    echo "  Worker $i 覆盖率: $COV_LINE"
done

echo "--------------------------------------------------"
echo "完成。请查看 $OUTPUT_DIR 下的 report_worker_*.txt"
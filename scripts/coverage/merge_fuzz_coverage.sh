#!/bin/bash

# 配置部分
# 动态获取 rustc 对应的 llvm 工具链路径，确保版本匹配
RUST_SYSROOT=$(rustc --print sysroot)
LLVM_PROFDATA="$RUST_SYSROOT/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-profdata"
LLVM_COV="$RUST_SYSROOT/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-cov"

# 检查工具是否存在，不存在则尝试直接使用系统命令
if [ ! -f "$LLVM_PROFDATA" ]; then
    LLVM_PROFDATA="llvm-profdata"
fi
if [ ! -f "$LLVM_COV" ]; then
    LLVM_COV="llvm-cov"
fi

# 假设进程编号是 1 到 10，如果是 0 到 9 请修改这里
START_ID=1
END_ID=10

# 基础路径配置
BASE_DIR="/home/lxy/regex_fuzzing/regex/fuzz"
OUTPUT_DIR="/home/lxy/regex_fuzzing/regex/coverage_data"

# 创建输出目录
mkdir -p "$OUTPUT_DIR"

echo "--------------------------------------------------"
echo "步骤 1: 将每个进程的 profraw 合并为 profdata..."
echo "--------------------------------------------------"

# 遍历所有进程ID
for i in $(seq $START_ID $END_ID); do
    # 定义输入和输出路径
    PROFRAW_DIR="$BASE_DIR/results/log/fuzz_${i}"
    OUTPUT_PROFDATA="$OUTPUT_DIR/fuzz_${i}.profdata"
    
    # 检查目录是否存在
    if [ -d "$PROFRAW_DIR" ]; then
        echo "正在处理进程 ${i}..."
        # 合并该进程下的所有 .profraw 文件
        # 忽略不匹配的警告（可能有部分 profraw 损坏或版本不一致）
        "$LLVM_PROFDATA" merge -sparse "$PROFRAW_DIR"/*.profraw -o "$OUTPUT_PROFDATA"
    else
        echo "警告: 目录 $PROFRAW_DIR 不存在，跳过..."
    fi
done

echo ""
echo "--------------------------------------------------"
echo "步骤 2: 合并所有进程的 profdata 文件..."
echo "--------------------------------------------------"

# 将上一步生成的所有 profdata 合并为一个总文件
"$LLVM_PROFDATA" merge -sparse "$OUTPUT_DIR"/fuzz_*.profdata -o "$OUTPUT_DIR/all_merged.profdata"
echo "已生成总覆盖率文件: $OUTPUT_DIR/all_merged.profdata"

echo ""
echo "--------------------------------------------------"
echo "步骤 3: 生成可视化覆盖率报告 (TXT)..."
echo "--------------------------------------------------"

# 构建包含所有二进制文件的参数列表
# 注意：llvm-cov report 要求第一个参数必须是主二进制文件，后续的可以用 -object 添加
MAIN_OBJECT=""
OBJECT_ARGS=""

for i in $(seq $START_ID $END_ID); do
    BINARY_PATH="$BASE_DIR/target/target_${i}/x86_64-unknown-linux-gnu/release/fuzz_diff_eqs"
    
    if [ -f "$BINARY_PATH" ]; then
        if [ -z "$MAIN_OBJECT" ]; then
            # 找到第一个二进制文件作为主参数
            MAIN_OBJECT="$BINARY_PATH"
            echo "主二进制文件: $MAIN_OBJECT"
        else
            # 其他的作为 object 参数
            OBJECT_ARGS="$OBJECT_ARGS -object $BINARY_PATH"
        fi
    else
        echo "警告: 二进制文件 $BINARY_PATH 不存在，跳过..."
    fi
done

if [ -z "$MAIN_OBJECT" ]; then
    echo "错误: 未找到任何二进制文件！"
    exit 1
fi

# 生成覆盖率摘要报告 (summary table)
# 使用 -Xdemangler=rustfilt 可以优化 Rust 符号显示（如果系统安装了 rustfilt）
"$LLVM_COV" report \
    "$MAIN_OBJECT" \
    $OBJECT_ARGS \
    -instr-profile="$OUTPUT_DIR/all_merged.profdata" \
    -ignore-filename-regex="/home/lxy/.cargo/.*" \
    -ignore-filename-regex="/home/lxy/regex_fuzzing/regex/fuzz/fuzz_targets/.*" \
    -ignore-filename-regex="rustc/.*" \
    > "$OUTPUT_DIR/coverage_summary.txt"

echo "完成！覆盖率报告已保存至: $OUTPUT_DIR/coverage_summary.txt"

# 如果你需要生成详细的源代码行级覆盖率
# "$LLVM_COV" show \
#     "$MAIN_OBJECT" \
#     $OBJECT_ARGS \
#     -instr-profile="$OUTPUT_DIR/all_merged.profdata" \
#     -ignore-filename-regex="/home/lxy/.cargo/.*" \
#     -format=text \
#     > "$OUTPUT_DIR/coverage_detailed.txt"

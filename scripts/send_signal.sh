#!/bin/bash

# fuzz target 进程名（改成你的）
FUZZ_NAME="fuzz_diff_eqs"
cnt=0
SRC="/home/lxy/regex_fuzzing/regex/fuzz/results/log"
BASE_DEST="/home/lxy/regex_fuzzing/coverage_data"
shopt -s nullglob
while true
do
    sleep 600

    echo "$(date) send SIGUSR1 to every job of $FUZZ_NAME"

    # pkill -USR1 -f "$FUZZ_NAME"
    for pid in $(pgrep -f "$FUZZ_NAME")
    do
        kill -USR1 $pid
    done

    cnt=$((cnt + 1))
    if [ $((cnt % 6)) -eq 0 ]; then
        hour_id=$((cnt / 6))
        DEST="$BASE_DEST/HOUR$hour_id"
        echo "HOUR$hour_id copy profraw to $DEST"

        mkdir -p "$DEST"
        profraw_files=("$SRC"/*.profraw)
        if [ ${#profraw_files[@]} -gt 0 ]; then
            cp "${profraw_files[@]}" "$DEST/"
        else
            echo "No profraw files found in $SRC"
        fi
    fi
    if [ $cnt -gt 150 ]; then
        break
    fi
done

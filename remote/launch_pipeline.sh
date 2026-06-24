#!/bin/bash
# Normalize line endings, stop any stale jobs, launch the pipeline DETACHED.
set -e
export PATH="$HOME/.local/bin:$PATH"
cd ~/bbverifier
perl -pi -e 's/\r$//' configs/bugbounty_lora.yaml run_pipeline.sh
pkill -f mlx_lm.lora 2>/dev/null || true
pkill -f 'hf download' 2>/dev/null || true
pkill -f run_pipeline.sh 2>/dev/null || true
sleep 1
# caffeinate keeps the Mac fully awake (no idle/disk/system sleep) for the whole
# run -- the overnight download likely died because the machine napped.
nohup caffeinate -dimsu bash run_pipeline.sh > logs/pipeline.log 2>&1 &
echo "PIPELINE_PID=$!"
sleep 6
echo "--- early pipeline log ---"
tail -8 logs/pipeline.log

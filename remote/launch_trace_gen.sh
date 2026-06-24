#!/usr/bin/env bash
# Resume Claude trace generation on Lambda (API-only; safe alongside GPU eval/train).
set -euo pipefail
cd ~/bbverifier
source ~/vt/bin/activate
[ -f ~/.env ] && set -a && source ~/.env && set +a

OUT=data/sft/train_traces.jsonl
BASE=$(cat data/sft/.trace_baseline_count 2>/dev/null || echo 0)
N=$(wc -l < "$OUT" 2>/dev/null || echo 0)
echo "[trace_gen] baseline=$BASE current=$N starting $(date)"

nohup python data/trace_gen.py \
  --in data/sft/train.jsonl \
  --out "$OUT" \
  --workers 8 \
  > ~/trace_gen.log 2>&1 &
echo "[trace_gen] pid=$! log=~/trace_gen.log"

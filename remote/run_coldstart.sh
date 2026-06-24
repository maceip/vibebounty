#!/bin/bash
# Autonomous Phase-1 cold-start pipeline. Survives SSH disconnect (run via nohup).
set -euo pipefail
cd ~/bbverifier
source ~/vt/bin/activate
export TOKENIZERS_PARALLELISM=false

echo "[orch] ===== cold-start pipeline start $(date) ====="

TRACE_PID="${1:-}"

if [ -n "$TRACE_PID" ]; then
  echo "[orch] waiting for trace_gen pid=$TRACE_PID ..."
  while kill -0 "$TRACE_PID" 2>/dev/null; do sleep 20; done
fi

TR=$(wc -l < data/sft/train_traces.jsonl 2>/dev/null || echo 0)
echo "[orch] train traces ready: $TR"
if [ "$TR" -lt 200 ]; then
  echo "[orch] FATAL: too few train traces ($TR) -- aborting"
  exit 1
fi

echo "[orch] preflight tokenization check ..."
python remote/verify_sft_data.py \
  --model ~/models/VibeThinker-3B \
  --data data/sft/train_traces.jsonl \
  --min-usable 100

echo "[orch] generating valid traces $(date) ..."
if ! python data/trace_gen.py --in data/sft/valid.jsonl --out data/sft/valid_traces.jsonl \
    --workers 24 --retries 2 --verify --drop-unfaithful \
    --model claude-opus-4-8 --predict-model claude-sonnet-4-6; then
  echo "[orch] valid trace gen returned nonzero (continuing)"
fi
VL=$(wc -l < data/sft/valid_traces.jsonl 2>/dev/null || echo 0)
echo "[orch] valid traces: $VL"
VALID_ARG=""
if [ "$VL" -ge 20 ]; then
  VALID_ARG="--valid data/sft/valid_traces.jsonl"
fi

echo "[orch] ===== SMOKE test $(date) ====="
python remote/train_sft.py --model ~/models/VibeThinker-3B \
  --data data/sft/train_traces.jsonl --out adapters/_smoke \
  --limit 64 --max-steps 8 --bs 4 --grad-accum 2 --save-steps 8 --valid-frac 0.1
echo "[orch] smoke OK"

echo "[orch] ===== FULL SFT $(date) ====="
python remote/train_sft.py --model ~/models/VibeThinker-3B \
  --data data/sft/train_traces.jsonl $VALID_ARG \
  --out adapters/coldstart --epochs 3 --bs 4 --grad-accum 8 --save-steps 200

echo "[orch] ===== MERGE $(date) ====="
python remote/merge_lora.py --base ~/models/VibeThinker-3B \
  --adapter adapters/coldstart --out ~/models/vibethinker-bbtriage-coldstart

echo "[orch] ===== PIPELINE COMPLETE $(date) ====="
ls -lh ~/models/vibethinker-bbtriage-coldstart 2>/dev/null || true

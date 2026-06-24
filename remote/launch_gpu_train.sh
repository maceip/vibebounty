#!/bin/bash
# Verified launch: preflight -> smoke -> full SFT -> merge -> eval gate.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=constants.sh
source "$SCRIPT_DIR/constants.sh"
cd ~/bbverifier
source ~/vt/bin/activate
export TOKENIZERS_PARALLELISM=false
export SERVE_MAX_NEW_TOKENS="$TRIAGE_MAX_TOKENS"
export SERVE_GEN_TIMEOUT="$SERVE_GEN_TIMEOUT"

MODEL=~/models/VibeThinker-3B
MERGED=~/models/vibethinker-bbtriage-coldstart
DATA=data/sft/train_traces.jsonl
N=$(wc -l < "$DATA")

echo "[launch] traces=$N $(date)"
if [ "$N" -lt 100 ]; then
  echo "[launch] FATAL: need >=100 traces, have $N"
  exit 1
fi

echo "[launch] step 1/4 verify tokenization ..."
python remote/verify_sft_data.py --model "$MODEL" --data "$DATA" --min-usable 100

echo "[launch] step 2/4 GPU smoke (8 steps) ..."
python remote/train_sft.py --model "$MODEL" --data "$DATA" \
  --out adapters/_smoke --limit 128 --max-steps 8 \
  --bs 4 --grad-accum 2 --save-steps 8 --valid-frac 0.05

echo "[launch] step 3/4 full SFT ..."
python remote/train_sft.py --model "$MODEL" --data "$DATA" \
  --out adapters/coldstart --epochs 3 --bs 4 --grad-accum 8 --save-steps 200

echo "[launch] merge ..."
python remote/merge_lora.py --base "$MODEL" \
  --adapter adapters/coldstart --out "$MERGED"

echo "$N" > data/sft/.trace_baseline_count

echo "[launch] step 4/4 eval gate ($N held-out, vLLM + ${EVAL_WORKERS:-8} workers) ..."
pkill -f serve_vibethinker 2>/dev/null || true
pkill -f 'vllm.entrypoints.openai.api_server' 2>/dev/null || true
sleep 2
BB=~/bbverifier REPO=~/bbverifier PY=~/vt/bin/python SERVE_BACKEND=vllm \
  MODEL_PATH="$MERGED" bash remote/eval_model.sh 300

echo "[launch] DONE $(date)"

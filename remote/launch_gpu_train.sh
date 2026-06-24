#!/bin/bash
# Verified launch: preflight -> smoke -> full SFT -> merge -> eval gate.
# Prefer: bash scripts/train_gpu_bugbounty.sh
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BB="$(cd "$SCRIPT_DIR/.." && pwd)"
# shellcheck source=constants.sh
source "$SCRIPT_DIR/constants.sh"
cd "$BB"
source ~/vt/bin/activate
export TOKENIZERS_PARALLELISM=false
export SERVE_MAX_NEW_TOKENS="$TRIAGE_MAX_TOKENS"
export SERVE_GEN_TIMEOUT="$SERVE_GEN_TIMEOUT"

if ! command -v emberglass-tune >/dev/null 2>&1; then
  echo "[launch] FATAL: pip install -e ../emberglass-tune"
  exit 1
fi

MODEL=~/models/VibeThinker-3B
MERGED=~/models/vibethinker-bbtriage-coldstart
DATA=data/sft/train_traces.jsonl
N=$(wc -l < "$DATA")

echo "[launch] preset=${PRESET:-lambda-gh200} traces=$N $(date)"
if [ "$N" -lt 100 ]; then
  echo "[launch] FATAL: need >=100 traces, have $N"
  exit 1
fi

emberglass-tune pipeline --preset "${PRESET:-lambda-gh200}" \
  --model "$MODEL" \
  --data "$DATA" \
  --out adapters/coldstart \
  --merged-out "$MERGED"

echo "$N" > data/sft/.trace_baseline_count

echo "[launch] eval gate ($N held-out, vLLM + ${EVAL_WORKERS:-8} workers) ..."
pkill -f serve_vibethinker 2>/dev/null || true
pkill -f 'vllm.entrypoints.openai.api_server' 2>/dev/null || true
sleep 2
BB=~/bbverifier REPO=~/bbverifier PY=~/vt/bin/python SERVE_BACKEND=vllm \
  MODEL_PATH="$MERGED" bash remote/eval_model.sh 300

echo "[launch] DONE $(date)"

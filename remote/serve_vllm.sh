#!/usr/bin/env bash
# Start vLLM OpenAI-compatible server for fast batched inference on Lambda.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=constants.sh
source "$SCRIPT_DIR/constants.sh"

MODEL="${1:-$HOME/models/vibethinker-bbtriage-coldstart}"
PORT="${PORT:-8080}"
SERVED_NAME="${SERVED_NAME:-$MODEL_NAME}"
MAX_LEN="${VLLM_MAX_MODEL_LEN:-4096}"

source ~/vt/bin/activate

pkill -f 'vllm.entrypoints.openai.api_server' 2>/dev/null || true
pkill -f serve_vibethinker.py 2>/dev/null || true
sleep 2

echo "[vllm] starting model=$MODEL port=$PORT max_len=$MAX_LEN"
nohup vllm serve "$MODEL" \
  --host 127.0.0.1 --port "$PORT" \
  --served-model-name "$SERVED_NAME" \
  --trust-remote-code \
  --max-model-len "$MAX_LEN" \
  --dtype bfloat16 \
  --enforce-eager \
  --gpu-memory-utilization "${VLLM_GPU_MEMORY_UTIL:-0.90}" \
  > ~/serve_vllm.log 2>&1 &

for i in $(seq 1 120); do
  sleep 3
  if curl -sf "http://127.0.0.1:$PORT/v1/models" >/dev/null 2>&1; then
    echo "[vllm] ready after ${i}x3s"
    exit 0
  fi
done
echo "[vllm] FATAL: did not start"
tail -30 ~/serve_vllm.log
exit 1

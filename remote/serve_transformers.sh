#!/usr/bin/env bash
# Legacy transformers+FastAPI serve (slow serial GPU). Prefer serve_vllm.sh on Lambda.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=constants.sh
source "$SCRIPT_DIR/constants.sh"

MODEL="${1:-$HOME/models/vibethinker-bbtriage-coldstart}"
PORT="${PORT:-8080}"

source ~/vt/bin/activate
export SERVE_MAX_NEW_TOKENS="$TRIAGE_MAX_TOKENS"
export SERVE_GEN_TIMEOUT="$SERVE_GEN_TIMEOUT"
export SERVE_MODEL_NAME="${MODEL_NAME}"

pkill -f serve_vibethinker.py 2>/dev/null || true
pkill -f 'vllm.entrypoints.openai.api_server' 2>/dev/null || true
sleep 2

nohup python "$SCRIPT_DIR/serve_vibethinker.py" --model "$MODEL" --port "$PORT" \
  > ~/serve_transformers.log 2>&1 &

for i in $(seq 1 60); do
  sleep 3
  curl -sf "http://127.0.0.1:$PORT/v1/models" >/dev/null && { echo "[transformers] ready"; exit 0; }
done
echo "[transformers] FATAL: did not start"; tail -20 ~/serve_transformers.log; exit 1

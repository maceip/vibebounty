#!/usr/bin/env bash
# Unified OpenAI-compatible server launcher. Reads SERVE_BACKEND from constants.sh.
# Usage: MODEL_PATH=~/models/foo bash remote/start_serve.sh
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=constants.sh
source "$SCRIPT_DIR/constants.sh"

MODEL="${MODEL_PATH:-$HOME/models/vibethinker-bbtriage-coldstart}"
export PORT="${SERVE_PORT:-8080}"

case "$SERVE_BACKEND" in
  vllm)
    exec bash "$SCRIPT_DIR/serve_vllm.sh" "$MODEL"
    ;;
  transformers)
    exec bash "$SCRIPT_DIR/serve_transformers.sh" "$MODEL"
    ;;
  mlx)
    PY="${PY:-$HOME/bbverifier/.venv/bin/python}"
    ADAPTER="${ADAPTER_PATH:-$HOME/bbverifier/adapters}"
    BASE="${MLX_BASE_MODEL:-WeiboAI/VibeThinker-3B}"
    pkill -f mlx_lm.server 2>/dev/null || true
    sleep 2
    echo "[mlx] starting base=$BASE adapter=$ADAPTER port=$PORT"
    caffeinate -is nohup "$PY" -m mlx_lm server \
      --model "$BASE" --adapter-path "$ADAPTER" --port "$PORT" \
      > "${SERVE_LOG:-$HOME/bbverifier/logs/server.log}" 2>&1 &
    for i in $(seq 1 60); do
      sleep 3
      curl -sf "http://127.0.0.1:$PORT/v1/models" >/dev/null 2>&1 && {
        echo "[mlx] ready after ${i}x3s"; exit 0; }
    done
    echo "[mlx] FATAL: did not start"; exit 1
    ;;
  *)
    echo "[start_serve] FATAL: unknown SERVE_BACKEND=$SERVE_BACKEND (vllm|transformers|mlx)"
    exit 1
    ;;
esac

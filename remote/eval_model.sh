#!/bin/bash
# Canonical model eval gate. Lambda: vLLM + parallel workers. Mac: mlx_lm + parallel workers.
# Fail-closed: stale reports deleted, 1-report smoke, then full N-report eval.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=constants.sh
source "$SCRIPT_DIR/constants.sh"

BB="${BB:-$HOME/bbverifier}"
REPO="${REPO:-$BB}"
PY="${PY:-$HOME/vt/bin/python}"
DATA="${DATA:-$BB/data/sft/test.jsonl}"
PORT="${PORT:-${SERVE_PORT:-8080}}"
N="${1:-300}"
MIN_DROVE="${MIN_DROVE:-0.8}"
WORKERS="${EVAL_WORKERS:-8}"
BACKEND="${SERVE_BACKEND:-vllm}"
FORCE_RESTART_SERVE="${FORCE_RESTART_SERVE:-1}"
if [ "$BACKEND" = "transformers" ]; then
  WORKERS="${EVAL_WORKERS_TRANSFORMERS:-2}"
fi
MODEL_PATH="${MODEL_PATH:-$HOME/models/vibethinker-bbtriage-coldstart}"
OUT_JSON="${OUT_JSON:-$REPO/eval/report_model.json}"
OUT_MD="${OUT_MD:-$REPO/eval/report_model.md}"

cd "$REPO" || { echo "[eval] FATAL: no repo at $REPO"; exit 1; }
mkdir -p eval

echo "[eval] n=$N workers=$WORKERS backend=$BACKEND max_tokens=$TRIAGE_MAX_TOKENS timeout=${TRIAGE_MODEL_TIMEOUT}s"

if [ ! -f feeds/cache/kev.json ]; then
  echo "[eval] building feeds cache ..."
  "$PY" feeds/fetch_feeds.py --days 14
fi

if [ "$BACKEND" = "vllm" ] && [ "$FORCE_RESTART_SERVE" != "0" ]; then
  echo "[eval] force-starting vLLM for model identity: $MODEL_PATH"
  bash "$SCRIPT_DIR/serve_vllm.sh" "$MODEL_PATH"
elif ! curl -sf "http://127.0.0.1:$PORT/v1/models" >/dev/null; then
  case "$BACKEND" in
    vllm)
      echo "[eval] starting vLLM ..."
      bash "$SCRIPT_DIR/serve_vllm.sh" "$MODEL_PATH"
      ;;
    transformers)
      echo "[eval] starting transformers serve ..."
      bash "$SCRIPT_DIR/serve_transformers.sh" "$MODEL_PATH"
      ;;
    *)
      echo "[eval] FATAL: no server on :$PORT and unknown SERVE_BACKEND=$BACKEND"
      exit 1
      ;;
  esac
fi

rm -f eval/report.json eval/report.md eval/report_model.json eval/report_model.md

echo "[eval] smoke (1 report) ..."
if ! MODEL_BASE_URL="http://127.0.0.1:$PORT/v1" MODEL_NAME="${MODEL_NAME}" \
     MODEL_MAX_TOKENS="$TRIAGE_MAX_TOKENS" MODEL_TEMPERATURE="$MODEL_TEMPERATURE" \
     MODEL_TOP_P="$MODEL_TOP_P" MODEL_TIMEOUT="$TRIAGE_MODEL_TIMEOUT" \
     MODEL_NO_FALLBACK="$MODEL_NO_FALLBACK" \
     "$PY" eval/run_eval.py --data "$DATA" --n 1 \
     --model-base-url "http://127.0.0.1:$PORT/v1" --workers 1; then
  echo "[eval] FATAL: smoke eval failed"
  exit 1
fi
SMOKE=$( "$PY" -c "import json; r=json.load(open('eval/report.json')); print(r.get('model_drove_share',0), r.get('engine_counts',{}))" )
echo "[eval] smoke OK: model_drove=$SMOKE"
rm -f eval/report.json eval/report.md

echo "[eval] full $N-report eval (workers=$WORKERS) ..."
MODEL_BASE_URL="http://127.0.0.1:$PORT/v1" MODEL_NAME="${MODEL_NAME}" \
  MODEL_MAX_TOKENS="$TRIAGE_MAX_TOKENS" MODEL_TEMPERATURE="$MODEL_TEMPERATURE" \
  MODEL_TOP_P="$MODEL_TOP_P" MODEL_TIMEOUT="$TRIAGE_MODEL_TIMEOUT" \
  MODEL_NO_FALLBACK="$MODEL_NO_FALLBACK" \
  "$PY" -u eval/run_eval.py --data "$DATA" --n "$N" \
  --model-base-url "http://127.0.0.1:$PORT/v1" --workers "$WORKERS"

[ -f eval/report.json ] || { echo "[eval] FATAL: no report.json"; exit 1; }
cp -f eval/report.json "$OUT_JSON"
cp -f eval/report.md "$OUT_MD" 2>/dev/null || true

DROVE=$( "$PY" -c "import json; print(json.load(open('$OUT_JSON')).get('model_drove_share',0))" )
ACC=$( "$PY" -c "import json; print(json.load(open('$OUT_JSON')).get('disposition_accuracy',0))" )
echo "[eval] DONE disposition_acc=$ACC model_drove=$DROVE -> $OUT_JSON"

python3 - "$MIN_DROVE" "$DROVE" <<'PY'
import sys
min_d, drove = float(sys.argv[1]), float(sys.argv[2])
if drove < min_d:
    print(f"[eval] FATAL: model_drove_share {drove:.2%} < {min_d:.0%}")
    sys.exit(1)
PY

#!/usr/bin/env bash
# Infra gate: vLLM serve + timed 20-report parallel eval. Must pass before any new SFT.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=constants.sh
source "$SCRIPT_DIR/constants.sh"

BB="${BB:-$HOME/bbverifier}"
REPO="${REPO:-$BB}"
PY="${PY:-$HOME/vt/bin/python}"
PORT="${SERVE_PORT:-8080}"
MODEL_PATH="${MODEL_PATH:-$HOME/models/vibethinker-bbtriage-coldstart}"
GATE_N="${GATE_N:-20}"
WORKERS="${EVAL_WORKERS:-8}"
DATA="${DATA:-$BB/data/sft/test.jsonl}"
SCOREBOARD="${SCOREBOARD:-$REPO/eval/scoreboard.jsonl}"

cd "$REPO" || exit 1
mkdir -p eval

echo "[infra_gate] START $(date -Iseconds)"
echo "[infra_gate] backend=$SERVE_BACKEND workers=$WORKERS gate_n=$GATE_N model=$MODEL_PATH"

pkill -f serve_vibethinker.py 2>/dev/null || true
pkill -f 'vllm.entrypoints.openai.api_server' 2>/dev/null || true
sleep 2

T0=$SECONDS
bash "$SCRIPT_DIR/serve_vllm.sh" "$MODEL_PATH"
SERVE_SEC=$((SECONDS - T0))
echo "[infra_gate] serve_up seconds=$SERVE_SEC"

T1=$SECONDS
BB="$BB" REPO="$REPO" PY="$PY" PORT="$PORT" SERVE_BACKEND=vllm EVAL_WORKERS="$WORKERS" \
  bash "$SCRIPT_DIR/eval_model.sh" "$GATE_N"
EVAL_SEC=$((SECONDS - T1))
TOTAL_SEC=$((SECONDS - T0))

REPORT="$REPO/eval/report_model.json"
if [ ! -f "$REPORT" ]; then
  echo "[infra_gate] FATAL: no $REPORT"
  exit 1
fi

"$PY" - "$REPORT" "$SCOREBOARD" "$SERVE_SEC" "$EVAL_SEC" "$TOTAL_SEC" "$WORKERS" "$GATE_N" <<'PY'
import json, sys, datetime
from pathlib import Path
report, sb, serve_s, eval_s, total_s, workers, n = sys.argv[1:8]
r = json.loads(Path(report).read_text())
row = {
    "ts": datetime.datetime.utcnow().isoformat() + "Z",
    "run_id": "infra_gate_vllm",
    "model_path": "vibethinker-bbtriage-coldstart",
    "infra": {"backend": "vllm", "workers": int(workers), "gate_n": int(n)},
    "timing_sec": {"serve": int(serve_s), "eval": int(eval_s), "total": int(total_s)},
    "n": r.get("n"),
    "disposition_accuracy": r.get("disposition_accuracy"),
    "accept_reject_accuracy": r.get("accept_reject_accuracy"),
    "model_drove_share": r.get("model_drove_share"),
    "macro_f1": r.get("macro_f1"),
}
Path(sb).parent.mkdir(parents=True, exist_ok=True)
with open(sb, "a", encoding="utf-8") as f:
    f.write(json.dumps(row) + "\n")
print("[infra_gate] scoreboard", json.dumps(row, indent=2))
PY

# Fail if 20 reports took >10 min (600s) — infra still too slow.
if [ "$EVAL_SEC" -gt 600 ]; then
  echo "[infra_gate] FATAL: eval $GATE_N reports took ${EVAL_SEC}s (>600s budget)"
  exit 2
fi

echo "[infra_gate] PASS eval_${GATE_N}_in_${EVAL_SEC}s total_${TOTAL_SEC}s $(date -Iseconds)"

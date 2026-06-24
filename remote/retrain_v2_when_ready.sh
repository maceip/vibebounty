#!/bin/bash
# Wait for trace_gen, then run full SFT ONLY if trace count grew past baseline.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=constants.sh
source "$SCRIPT_DIR/constants.sh"
cd ~/bbverifier
source ~/vt/bin/activate
export TOKENIZERS_PARALLELISM=false
TRACE_PID="${1:?usage: retrain_v2_when_ready.sh TRACE_PID}"
BASELINE_FILE=data/sft/.trace_baseline_count
BASELINE=$(cat "$BASELINE_FILE" 2>/dev/null || echo 0)

echo "[v2] waiting for trace_gen pid=$TRACE_PID baseline=$BASELINE ..."
while kill -0 "$TRACE_PID" 2>/dev/null; do sleep 30; done
N=$(wc -l < data/sft/train_traces.jsonl)
echo "[v2] traces=$N $(date)"
if [ "$N" -le "$BASELINE" ]; then
  echo "[v2] FATAL: trace count did not grow ($N <= $BASELINE). Not retraining duplicate v1."
  exit 1
fi
python remote/verify_sft_data.py --model ~/models/VibeThinker-3B --data data/sft/train_traces.jsonl --min-usable 500
python remote/train_sft.py --model ~/models/VibeThinker-3B --data data/sft/train_traces.jsonl \
  --out adapters/coldstart_v2 --epochs 3 --bs 4 --grad-accum 8 --save-steps 200
python remote/merge_lora.py --base ~/models/VibeThinker-3B \
  --adapter adapters/coldstart_v2 --out ~/models/vibethinker-bbtriage-coldstart-v2
echo "$N" > "$BASELINE_FILE"
echo "[v2] DONE $(date)"

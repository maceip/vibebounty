#!/bin/bash
# VibeBounty GPU train — unified emberglass-tune pipeline preset.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BB="$(cd "$SCRIPT_DIR/.." && pwd)"
# shellcheck source=../remote/constants.sh
source "$BB/remote/constants.sh"
cd "$BB"
export TOKENIZERS_PARALLELISM=false

MODEL="${MODEL:-$HOME/models/VibeThinker-3B}"
DATA="${DATA:-data/sft/train_traces.jsonl}"
ADAPTER_OUT="${ADAPTER_OUT:-adapters/vibebounty-run}"
MERGED="${MERGED:-$HOME/models/vibethinker-bbtriage-run}"
PRESET="${PRESET:-lambda-gh200}"

if ! command -v emberglass-tune >/dev/null 2>&1; then
  echo "[vibebounty-train] FATAL: uv sync (installs emberglass-tune editable)"
  exit 1
fi

N=$(wc -l < "$DATA")
echo "[vibebounty-train] preset=$PRESET traces=$N $(date)"

emberglass-tune pipeline --preset "$PRESET" \
  --model "$MODEL" \
  --data "$DATA" \
  --out "$ADAPTER_OUT" \
  --merged-out "$MERGED"

echo "[vibebounty-train] DONE adapter=$ADAPTER_OUT merged=$MERGED"

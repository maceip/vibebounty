#!/usr/bin/env bash
# Sync repo scripts to Lambda bbverifier dir (run from dev machine).
set -euo pipefail
HOST="${LAMBDA_HOST:-ubuntu@192.222.53.8}"
KEY="${LAMBDA_KEY:-$HOME/.ssh/id_ed25519}"
DEST="${LAMBDA_DEST:-bbverifier}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "[deploy] $ROOT -> $HOST:~/$DEST"
scp -i "$KEY" -r \
  "$ROOT/remote/"*.sh \
  "$ROOT/remote/constants.sh" \
  "$ROOT/remote/serve_vibethinker.py" \
  "$ROOT/remote/train_sft.py" \
  "$ROOT/remote/merge_lora.py" \
  "$ROOT/remote/verify_sft_data.py" \
  "$HOST:~/$DEST/remote/" 2>/dev/null || true

scp -i "$KEY" \
  "$ROOT/eval/run_eval.py" \
  "$HOST:~/$DEST/eval/run_eval.py"

scp -i "$KEY" \
  "$ROOT/app/triage.py" \
  "$HOST:~/$DEST/app/triage.py"

scp -i "$KEY" \
  "$ROOT/data/trace_gen.py" \
  "$HOST:~/$DEST/data/trace_gen.py"

echo "[deploy] fixing LF on remote"
ssh -i "$KEY" "$HOST" "sed -i 's/\r$//' ~/$DEST/remote/*.sh 2>/dev/null; chmod +x ~/$DEST/remote/*.sh"
echo "[deploy] DONE"

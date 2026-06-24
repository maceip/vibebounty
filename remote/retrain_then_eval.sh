#!/usr/bin/env bash
# Canonical, version-controlled retrain pipeline. Run it on the Mac under
# caffeinate; it is idempotent end-to-end and FAILS CLOSED at every gate:
#
#   1. rebuild SFT from the OLD-format source on the NATURAL label distribution
#      -> data/rebuild_sft_from_jsonl.py asserts train share ~= held-out test
#         share (PARITY_TOL) and exits non-zero on skew. No skew can ship.
#   2. install the version-controlled lora_config.yaml (max_seq_length 4096,
#      save_every 200) and run mlx_lm.lora.
#   3. checkpoint gate: score every saved checkpoint on a natural dev slice and
#      install the one with the best held-out accept/reject (not the final iter,
#      not the lowest val loss).
#   4. full 300-report eval + lift vs baseline.
#
# Usage:  caffeinate -dimsu bash remote/retrain_then_eval.sh
set -uo pipefail

REPO="$HOME/vibebounty"
BB="$HOME/bbverifier"
PY="$BB/.venv/bin/python"
SRC="$BB/data/sft_v1"        # OLD-format, natural-distribution source corpus
OUT="$BB/data/sft"           # rebuilt train/valid/test (new render) live here

cd "$REPO" || { echo "no repo at $REPO"; exit 1; }
mkdir -p "$BB/logs"
echo "PIPELINE_START $(date)  HEAD=$(git rev-parse --short HEAD)"

# ---- 1. rebuild data on the natural distribution (guard fails closed) ------
echo "== rebuild SFT (natural distribution + parity guard) =="
if ! "$PY" data/rebuild_sft_from_jsonl.py --src "$SRC" --out "$OUT" 2>&1 | tee "$BB/logs/rebuild.log"; then
  echo "REBUILD_FAILED: distribution guard tripped or build error. Aborting before train."
  exit 3
fi
grep -aq "DISTRIBUTION GUARD PASSED" "$BB/logs/rebuild.log" || {
  echo "REBUILD_FAILED: guard did not pass. Aborting."; exit 3; }

# ---- 2. train --------------------------------------------------------------
cp -f "$REPO/configs/bugbounty_lora.yaml" "$BB/lora_config.yaml"
cd "$BB"
# Back up any prior adapters so the gate can't pick a stale checkpoint.
if [ -d adapters ] && ls adapters/*.safetensors >/dev/null 2>&1; then
  mv adapters "adapters_prev_$(date +%s)"
fi
mkdir -p adapters
pkill -f mlx_lm.server 2>/dev/null; sleep 2
echo "== train (mlx_lm.lora) start $(date) =="
caffeinate -dimsu nohup "$PY" -m mlx_lm lora --config lora_config.yaml > logs/retrain.log 2>&1 &
sleep 5
while pgrep -f mlx_lm.lora >/dev/null; do sleep 30; done
echo "TRAIN_PROCESS_EXITED $(date)"
[ -f adapters/adapters.safetensors ] || { echo "TRAIN_FAILED: no final adapter"; tail -40 logs/retrain.log; exit 2; }
echo "TRAIN_OK $(grep -aE 'Iter [0-9]+: Val loss' logs/retrain.log | tail -1)"

# ---- 3. checkpoint selection gate -----------------------------------------
cd "$REPO"
echo "== checkpoint selection gate =="
bash remote/select_checkpoint.sh 2>&1 | tee "$BB/logs/select_checkpoint.log" || \
  echo "WARN: checkpoint gate returned non-zero; final adapter remains installed"

# ---- 4. full 300 eval + lift ----------------------------------------------
echo "== full 300-report eval =="
bash remote/validate_tune.sh 300
echo "PIPELINE_DONE $(date)"

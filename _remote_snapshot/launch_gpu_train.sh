#!/bin/bash
# Verified launch: preflight -> smoke -> full SFT. Run with nohup.
set -euo pipefail
cd ~/bbverifier
source ~/vt/bin/activate
export TOKENIZERS_PARALLELISM=false

MODEL=~/models/VibeThinker-3B
DATA=data/sft/train_traces.jsonl
N=$(wc -l < "$DATA")

echo "[launch] traces=$N $(date)"
if [ "$N" -lt 100 ]; then
  echo "[launch] FATAL: need >=100 traces, have $N"
  exit 1
fi

echo "[launch] step 1/3 verify tokenization ..."
python remote/verify_sft_data.py --model "$MODEL" --data "$DATA" --min-usable 100

echo "[launch] step 2/3 GPU smoke (8 steps) ..."
python remote/train_sft.py --model "$MODEL" --data "$DATA" \
  --out adapters/_smoke --limit 128 --max-steps 8 \
  --bs 4 --grad-accum 2 --save-steps 8 --valid-frac 0.05

echo "[launch] step 3/3 full SFT ..."
python remote/train_sft.py --model "$MODEL" --data "$DATA" \
  --out adapters/coldstart --epochs 3 --bs 4 --grad-accum 8 --save-steps 200

echo "[launch] merge ..."
python remote/merge_lora.py --base "$MODEL" \
  --adapter adapters/coldstart --out ~/models/vibethinker-bbtriage-coldstart

echo "[launch] DONE $(date)"

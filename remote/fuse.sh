#!/bin/bash
# Fuse the trained LoRA adapter into the base weights -> standalone model asset.
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH"
cd ~/bbverifier
mkdir -p logs
.venv/bin/mlx_lm.fuse \
  --model "WeiboAI/VibeThinker-3B" \
  --adapter-path adapters \
  --save-path vibethinker-bbtriage 2>&1 | tee logs/fuse.log
echo "[fuse] standalone model written to ~/bbverifier/vibethinker-bbtriage"
ls -lh vibethinker-bbtriage

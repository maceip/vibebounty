#!/bin/bash
# Launch MLX LoRA fine-tune for VibeBounty. Logs -> logs/train.log
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH"
export HF_HUB_ENABLE_HF_TRANSFER=1
cd ~/bbverifier
mkdir -p adapters logs
CONFIG="${CONFIG:-configs/bugbounty_lora.yaml}"
echo "[train] config=$CONFIG start $(date)"
.venv/bin/mlx_lm.lora --config "$CONFIG" 2>&1 | tee logs/train.log
echo "[train] end $(date)"

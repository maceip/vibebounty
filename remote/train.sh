#!/bin/bash
# Launch the LoRA fine-tune. Logs stream to logs/train.log.
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH"
export HF_HUB_ENABLE_HF_TRANSFER=1
cd ~/bbverifier
mkdir -p adapters logs
echo "[train] start $(date)"
.venv/bin/mlx_lm.lora --config lora_config.yaml 2>&1 | tee logs/train.log
echo "[train] end $(date)"

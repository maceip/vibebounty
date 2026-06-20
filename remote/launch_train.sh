#!/bin/bash
# Normalize config, then launch the LoRA fine-tune DETACHED so it survives SSH.
set -e
export PATH="$HOME/.local/bin:$PATH"
# Xet backend stalls on this network; force plain HTTPS + parallel hf_transfer.
export HF_HUB_DISABLE_XET=1
export HF_HUB_ENABLE_HF_TRANSFER=1
cd ~/bbverifier
perl -pi -e 's/\r$//' lora_config.yaml
mkdir -p logs adapters

if pgrep -f mlx_lm.lora >/dev/null; then
  echo "ALREADY_RUNNING"
  tail -8 logs/train.log 2>/dev/null || true
  exit 0
fi

nohup .venv/bin/mlx_lm.lora --config lora_config.yaml > logs/train.log 2>&1 &
echo "STARTED_PID=$!"
sleep 10
echo "--- early log ---"
tail -20 logs/train.log

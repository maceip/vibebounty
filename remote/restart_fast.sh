#!/bin/bash
# Install hf_transfer, stop the slow download, and relaunch via launch_train.sh.
set -e
export PATH="$HOME/.local/bin:$PATH"
cd ~/bbverifier
uv pip install --python .venv hf_transfer >/dev/null 2>&1 && echo "hf_transfer installed"
pkill -f mlx_lm.lora 2>/dev/null || true
sleep 2
find ~/.cache/huggingface/hub/models--WeiboAI--VibeThinker-3B -name '*.incomplete' -delete 2>/dev/null || true
echo "relaunching..."

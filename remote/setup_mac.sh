#!/bin/bash
# Idempotent Mac-side environment setup for MLX LoRA fine-tuning.
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH"

echo "[setup] uv: $(uv --version)"
mkdir -p ~/bbverifier/data/sft
cd ~/bbverifier

if [ ! -d .venv ]; then
  uv venv --python 3.12 .venv
fi
uv pip install --python .venv mlx-lm "huggingface_hub[hf_transfer]"

.venv/bin/python - <<'PY'
import mlx.core as mx
import mlx_lm
print("mlx_lm READY")
print("metal available:", mx.metal.is_available())
PY
echo "[setup] done"

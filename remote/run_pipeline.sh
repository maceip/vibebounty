#!/bin/bash
# Resilient end-to-end pipeline for a flaky HF link:
#   auth -> create vibebounty repo -> download(resume+retry) -> train -> fuse -> push -> smoke
# Only once ALL model files are present does training begin; download resumes
# partial shards and retries many times, so a dropped connection never restarts it.
set -u
export PATH="$HOME/.local/bin:$PATH"
export HF_HUB_DISABLE_XET=1
export HF_HUB_DOWNLOAD_TIMEOUT=120
cd ~/bbverifier
mkdir -p logs adapters
[ -f .hftoken ] && export HF_TOKEN="$(cat .hftoken)"

echo "[pipeline] START $(date)"
echo "[auth] $(.venv/bin/python -c 'from huggingface_hub import whoami; print(whoami().get("name","?"))' 2>/dev/null)"

# 0) Create the target model repo up-front (idempotent).
.venv/bin/python -c "from huggingface_hub import create_repo; print('[repo]', create_repo('vibebounty', repo_type='model', exist_ok=True))" 2>>logs/hub.log || echo "[repo] create deferred"

# 1) Robust model download (resumes automatically; retry until complete).
DL_OK=0
for try in $(seq 1 60); do
  echo "[dl] attempt $try $(date)"
  if .venv/bin/hf download WeiboAI/VibeThinker-3B >/dev/null 2>>logs/dl.log; then
    echo "[dl] COMPLETE on attempt $try"; DL_OK=1; break
  fi
  echo "[dl] failed, retry in 10s"; sleep 10
done
if [ "$DL_OK" != "1" ]; then echo "[pipeline] ABORT: model download never completed"; exit 1; fi

# 2) Train LoRA (skip if a final adapter already exists -> never clobber).
if [ -f adapters/adapters.safetensors ]; then
  echo "[train] SKIP - adapters/adapters.safetensors already present"
else
  echo "[train] START $(date)"
  .venv/bin/mlx_lm.lora --config configs/bugbounty_lora.yaml || { echo "[pipeline] ABORT: train failed"; exit 2; }
  echo "[train] END $(date)"
fi

# 3) Fuse adapter -> standalone model (skip if already fused).
if [ -f vibethinker-bbtriage/config.json ]; then
  echo "[fuse] SKIP - vibethinker-bbtriage already fused"
else
  echo "[fuse] START $(date)"
  .venv/bin/mlx_lm.fuse --model WeiboAI/VibeThinker-3B --adapter-path adapters --save-path vibethinker-bbtriage || { echo "[pipeline] ABORT: fuse failed"; exit 3; }
  echo "[fuse] END $(date)"
fi

# 4) Push the fused model to the Hub (skip if already pushed).
if [ -f .pushed ]; then
  echo "[push] SKIP - already pushed"
else
  echo "[push] START $(date)"
  .venv/bin/python push_hub.py vibebounty vibethinker-bbtriage 2>>logs/hub.log && { echo "[push] OK"; touch .pushed; } || echo "[push] FAILED (model still saved locally)"
fi

# 5) Smoke test the tuned model.
echo "[smoke] START $(date)"
.venv/bin/python smoke.py vibethinker-bbtriage 8 || true
echo "[pipeline] ALL DONE $(date)"

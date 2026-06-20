#!/bin/bash
# Idempotent entry point. On every (re)connect this decides: DONE, RUNNING, or LAUNCH.
# It NEVER restarts a healthy run and NEVER clobbers a finished model.
set -u
export PATH="$HOME/.local/bin:$PATH"
cd ~/bbverifier
perl -pi -e 's/\r$//' run_pipeline.sh lora_config.yaml push_hub.py smoke.py 2>/dev/null || true
[ -f .hftoken ] && export HF_TOKEN="$(cat .hftoken)"

# 1) Already finished? Verify the fused model artifact and ensure it's pushed.
if [ -f vibethinker-bbtriage/config.json ] && ls vibethinker-bbtriage/*.safetensors >/dev/null 2>&1; then
  echo "STATE=DONE  fused model present at ~/bbverifier/vibethinker-bbtriage"
  du -sh vibethinker-bbtriage 2>/dev/null
  if [ ! -f .pushed ]; then
    echo "[push] pushing existing model to Hub..."
    .venv/bin/python push_hub.py vibebounty vibethinker-bbtriage 2>>logs/hub.log && touch .pushed && echo "[push] OK"
  else
    echo "[push] already pushed"
  fi
  exit 0
fi

# 2) Already running? Leave it alone (disconnection != failure).
if pgrep -f run_pipeline.sh >/dev/null || pgrep -f mlx_lm.lora >/dev/null || pgrep -f 'hf download' >/dev/null; then
  echo "STATE=RUNNING  pipeline already in progress - NOT restarting"
  tail -12 logs/pipeline.log 2>/dev/null
  exit 0
fi

# 3) Nothing running, not finished -> launch detached, awake, survives SSH loss.
echo "STATE=LAUNCH  starting resilient pipeline detached"
mkdir -p logs adapters
nohup caffeinate -dimsu bash run_pipeline.sh > logs/pipeline.log 2>&1 &
echo "PIPELINE_PID=$!"
sleep 8
echo "--- early log ---"
tail -12 logs/pipeline.log

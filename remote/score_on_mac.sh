#!/bin/bash
# Score the fine-tuned model on the Mac, fully offline. Idempotent.
#   - fuses the adapter if the pipeline hasn't already,
#   - serves the tuned model on an OpenAI-compatible endpoint,
#   - runs the held-out eval against it and prints the lift vs the baseline.
#
# Usage (on the Mac):   bash score_on_mac.sh [N]
#   N = number of test examples to score (default 300; use e.g. 60 for a quick read)
set -u
export PATH="$HOME/.local/bin:$PATH"
cd ~/bbverifier || { echo "no ~/bbverifier"; exit 1; }
N="${1:-300}"
perl -pi -e 's/\r$//' eval/run_eval.py score_on_mac.sh 2>/dev/null || true
mkdir -p logs

# 0) the eval's model path needs the openai client
uv pip install -q openai 2>/dev/null || .venv/bin/python -m pip install -q openai 2>/dev/null || true

# 1) ensure a fused standalone model exists
if [ ! -f vibethinker-bbtriage/config.json ]; then
  if [ -f adapters/adapters.safetensors ]; then
    echo "[fuse] no fused model yet -> fusing current adapter..."
    .venv/bin/mlx_lm.fuse --model WeiboAI/VibeThinker-3B \
      --adapter-path adapters --save-path vibethinker-bbtriage || { echo "fuse failed"; exit 2; }
  else
    echo "no adapter found - has training produced adapters/adapters.safetensors yet?"; exit 1
  fi
fi

# 2) serve it (background) and wait until it answers
pkill -f 'mlx_lm.server' 2>/dev/null || true
sleep 1
nohup .venv/bin/mlx_lm.server --model vibethinker-bbtriage --port 8080 > logs/serve.log 2>&1 &
SRV=$!
echo "[serve] mlx_lm.server pid $SRV, waiting for ready..."
ready=0
for i in $(seq 1 90); do
  if curl -s http://localhost:8080/v1/models >/dev/null 2>&1; then ready=1; break; fi
  sleep 2
done
[ "$ready" = 1 ] || { echo "server did not come up; see logs/serve.log"; tail -20 logs/serve.log; exit 3; }
echo "[serve] ready"

# 3) score the tuned model
echo "=== TUNED MODEL  (n=$N) ==="
.venv/bin/python eval/run_eval.py --model-base-url http://localhost:8080/v1 --n "$N"
echo
echo "Baseline for comparison (heuristic+defense): 97.3% accept/reject, 56.3% 9-class, macro-F1 0.191"
echo "Tuned report written to eval/report.json + eval/report.md"
echo "(server still running on :8080 — the live console will now use the tune. kill: pkill -f mlx_lm.server)"

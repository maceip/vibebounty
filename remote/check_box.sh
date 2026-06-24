#!/bin/bash
set -uo pipefail
echo "=== TIME ==="
date
echo "=== GPU ==="
nvidia-smi --query-gpu=name,utilization.gpu,memory.used,memory.total --format=csv,noheader 2>/dev/null || echo "no nvidia-smi"
echo "=== PROCESSES ==="
pgrep -af 'train_sft|run_coldstart|trace_gen|launch_gpu' || echo "none"
echo "=== TRACES ==="
wc -l /home/ubuntu/bbverifier/data/sft/train_traces.jsonl 2>/dev/null || echo 0
echo "=== CRLF FILES ==="
grep -rl $'\r' /home/ubuntu/bbverifier/remote/*.sh /home/ubuntu/bbverifier/remote/train_sft.py /home/ubuntu/bbverifier/remote/verify_sft_data.py 2>/dev/null || echo "NONE"
echo "=== SCRIPT CHECKS ==="
grep -c 'tokenize=False' /home/ubuntu/bbverifier/remote/train_sft.py || echo 0
grep -c 'remove_unused_columns=False' /home/ubuntu/bbverifier/remote/train_sft.py || echo 0
echo "=== LAST SMOKE LOG ==="
tail -8 /home/ubuntu/gpu_smoke2.log 2>/dev/null || tail -8 /home/ubuntu/gpu_smoke.log 2>/dev/null || echo "no smoke log"
echo "=== PREFLIGHT ==="
cd /home/ubuntu/bbverifier
source /home/ubuntu/vt/bin/activate
python remote/verify_sft_data.py \
  --model /home/ubuntu/models/VibeThinker-3B \
  --data data/sft/train_traces.jsonl \
  --min-usable 100 --sample 200

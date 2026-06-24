#!/usr/bin/env bash
set -euo pipefail
for pat in serve_vllm.sh infra_gate.sh vllm.entrypoints; do
  pkill -f "$pat" 2>/dev/null || true
done
sleep 3
echo "=== procs after kill ==="
pgrep -af 'serve_vllm|infra_gate|vllm.entrypoints' || echo none
pgrep -af trace_gen.py || echo "WARN no trace_gen"
nohup bash ~/bbverifier/remote/infra_gate.sh > ~/infra_gate.log 2>&1 &
echo "infra_gate pid=$!"
for i in $(seq 1 60); do
  sleep 5
  if curl -sf http://127.0.0.1:8080/v1/models >/dev/null 2>&1; then
    echo "vllm UP after $((i*5))s"
    break
  fi
  if grep -qE 'infra_gate.*PASS|infra_gate.*FATAL|FATAL: did not start' ~/infra_gate.log 2>/dev/null; then
    break
  fi
done
echo "=== infra_gate ==="
tail -20 ~/infra_gate.log
echo "=== serve_vllm ==="
tail -10 ~/serve_vllm.log 2>/dev/null || true
echo "=== traces ==="
wc -l ~/bbverifier/data/sft/train_traces.jsonl

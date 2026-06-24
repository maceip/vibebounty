#!/usr/bin/env bash
# Pick the LoRA checkpoint that maximizes held-out DECISION accuracy, not the one
# with the lowest val loss (which masked the last regression) and not blindly the
# final iter (which is usually over-trained).
#
# For each candidate checkpoint it: serves base+checkpoint, scores it on a small
# NATURAL-distribution dev slice (carved from data/sft/valid.jsonl -> held out of
# training, disjoint from the 300-report test set), greedy + no-fallback so a
# parse miss counts against the model. Ranks by accept/reject, then disposition
# accuracy, then model-drove share. Installs the winner as adapters/adapters.safetensors.
#
# Usage:
#   bash remote/select_checkpoint.sh                       # default sweep
#   CKPTS="800 1200 1600 2000" DEV_N=48 bash remote/select_checkpoint.sh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=constants.sh
source "$SCRIPT_DIR/constants.sh"

REPO="$HOME/vibethinker/bb-triage"
BB="$HOME/bbverifier"
PY="$BB/.venv/bin/python"
ADIR="$BB/adapters"
VALID="$BB/data/sft/valid.jsonl"
MODEL="WeiboAI/VibeThinker-3B"
PORT="${PORT:-8080}"
CKPTS="${CKPTS:-600 800 1000 1200 1400 1600 1800 2000}"
DEV_N="${DEV_N:-48}"
WORKERS="${EVAL_WORKERS:-$EVAL_WORKERS_MLX}"
MAXTOK="${MODEL_MAX_TOKENS:-$TRIAGE_MAX_TOKENS}"
SEL="$BB/adapters_sel"               # scratch adapter dir we point the server at
RESULTS="$REPO/eval/ckpt_sweep.tsv"

cd "$REPO" || { echo "no repo at $REPO"; exit 1; }
mkdir -p eval
[ -f "$ADIR/adapter_config.json" ] || { echo "no adapter_config.json in $ADIR"; exit 1; }

# Natural-distribution dev slice (first DEV_N of the stratified valid split).
DEV="$REPO/eval/dev_slice.jsonl"
head -n "$DEV_N" "$VALID" > "$DEV"
echo "dev slice: $(wc -l < "$DEV") reports from valid.jsonl (held out, != test)"

serve() {  # $1 = adapter dir
  pkill -f mlx_lm.server 2>/dev/null; sleep 2
  caffeinate -is nohup "$PY" -m mlx_lm server \
    --model "$MODEL" --adapter-path "$1" --port "$PORT" \
    > "$BB/logs/server_sel.log" 2>&1 &
  for i in $(seq 1 60); do
    sleep 3
    curl -s "http://localhost:$PORT/v1/models" >/dev/null 2>&1 && return 0
  done
  echo "  server did not come up"; tail -20 "$BB/logs/server_sel.log"; return 1
}

printf "iter\taccept_reject\tdisposition\tmodel_drove\n" > "$RESULTS"
echo
printf "%-8s %-14s %-13s %-12s\n" "ckpt" "accept/reject" "disposition" "model-drove"
printf -- "------------------------------------------------------\n"

mkdir -p "$SEL"
cp -f "$ADIR/adapter_config.json" "$SEL/adapter_config.json"

for it in $CKPTS; do
  f="$ADIR/$(printf '%07d' "$it")_adapters.safetensors"
  [ -f "$f" ] || { printf "%-8s %s\n" "$it" "(missing, skipped)"; continue; }
  cp -f "$f" "$SEL/adapters.safetensors"
  serve "$SEL" || continue
  rm -f eval/report.json
  echo "  scoring ckpt $it ($DEV_N reports, workers=$WORKERS) ..."
  MODEL_BASE_URL="http://localhost:$PORT/v1" MODEL_NAME="$MODEL" \
    MODEL_MAX_TOKENS="$MAXTOK" MODEL_NO_FALLBACK=1 MODEL_TEMPERATURE=0 MODEL_TOP_P=1.0 \
    MODEL_TIMEOUT="$TRIAGE_MODEL_TIMEOUT" \
    "$PY" -u eval/run_eval.py --data "$DEV" --n "$DEV_N" \
    --model-base-url "http://localhost:$PORT/v1" --workers "$WORKERS"
  if [ ! -f eval/report.json ]; then
    printf "%-8s %s\n" "$it" "(eval failed, skipped)"; continue
  fi
  read -r AR DP MD < <("$PY" - <<PYEOF
import json
r=json.load(open("eval/report.json"))
print(r.get("accept_reject_accuracy",0), r.get("disposition_accuracy",0), r.get("model_drove_share",0))
PYEOF
)
  printf "%-8s %-14s %-13s %-12s\n" "$it" "$AR" "$DP" "$MD"
  printf "%s\t%s\t%s\t%s\n" "$it" "$AR" "$DP" "$MD" >> "$RESULTS"
  cp -f eval/report.json "eval/report_ckpt_${it}.json"
done

printf -- "------------------------------------------------------\n"
# Rank: accept/reject desc, then disposition desc, then model-drove desc.
BEST=$("$PY" - <<PYEOF
rows=[l.split("\t") for l in open("$RESULTS").read().splitlines()[1:] if l.strip()]
if not rows:
    print(""); raise SystemExit
rows.sort(key=lambda r:(float(r[1]),float(r[2]),float(r[3])), reverse=True)
print(rows[0][0])
PYEOF
)
if [ -z "$BEST" ]; then
  echo "!! no checkpoint produced a usable result; leaving adapters.safetensors as-is"
  exit 2
fi
echo "BEST checkpoint: iter $BEST  -> installing as adapters/adapters.safetensors"
cp -f "$ADIR/$(printf '%07d' "$BEST")_adapters.safetensors" "$ADIR/adapters.safetensors"
pkill -f mlx_lm.server 2>/dev/null; sleep 2
echo "SELECT_DONE iter=$BEST"

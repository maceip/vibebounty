#!/usr/bin/env bash
# Validate the LoRA tune on the Mac, end to end, from the git-synced repo.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=constants.sh
source "$SCRIPT_DIR/constants.sh"

REPO="$HOME/vibethinker/bb-triage"
PY="$HOME/bbverifier/.venv/bin/python"
ADAPTER="$HOME/bbverifier/adapters"
DATA="$HOME/bbverifier/data/sft/test.jsonl"
MODEL="WeiboAI/VibeThinker-3B"
PORT=8080
N="${1:-20}"

cd "$REPO" || { echo "no repo at $REPO"; exit 1; }
mkdir -p eval logs
echo "== deps =="
UV="$(command -v uv || echo "$HOME/.local/bin/uv")"
if ! "$PY" -c 'import openai' 2>/dev/null; then
  echo "  installing openai into the mlx venv via uv"
  "$UV" pip install --python "$PY" openai >/dev/null 2>&1 || "$UV" pip install --python "$PY" openai
fi
"$PY" -c 'import openai, sys; print("  openai", openai.__version__)' || { echo "openai still missing"; exit 1; }

# Threat-intel cache must exist or KEV corroboration cannot fire (defense case 5).
if [ ! -f feeds/cache/kev.json ]; then
  echo "== building threat-intel cache (KEV/NVD) =="
  "$PY" feeds/fetch_feeds.py 2>&1 | tail -4
fi

# ---- 1. serve the tuned model (idempotent) -------------------------------
if curl -s "http://localhost:$PORT/v1/models" >/dev/null 2>&1; then
  echo "== server already up on :$PORT =="
else
  echo "== starting mlx_lm.server (base + adapter) =="
  caffeinate -is nohup "$PY" -m mlx_lm server \
    --model "$MODEL" --adapter-path "$ADAPTER" \
    --port "$PORT" > logs/server.log 2>&1 &
  for i in $(seq 1 60); do
    sleep 3
    curl -s "http://localhost:$PORT/v1/models" >/dev/null 2>&1 && { echo "  ready after ${i}x3s"; break; }
    [ "$i" = 60 ] && { echo "  server did not come up; tail logs/server.log:"; tail -20 logs/server.log; exit 1; }
  done
fi

# ---- 2. defense suite (offline guardrails) -------------------------------
echo; echo "== defense suite (offline, model-independent) =="
"$PY" eval/adversarial.py

# ---- 3. score the SERVED tuned model (canonical eval gate) -----------------
echo; echo "== tuned model eval gate (greedy, max_tokens=$TRIAGE_MAX_TOKENS) =="
BB="$HOME/bbverifier" REPO="$REPO" PY="$PY" PORT="$PORT" \
  bash "$SCRIPT_DIR/eval_model.sh" "$N" || exit 1

# ---- 4. score the heuristic+defense baseline on the SAME reports ---------
echo; echo "== heuristic+defense baseline on the same $N reports =="
"$PY" eval/run_eval.py --data "$DATA" --n "$N"
cp -f eval/report.json eval/report_baseline.json 2>/dev/null

# ---- 5. lift summary -----------------------------------------------------
echo; echo "== LIFT (tuned model vs baseline) =="
"$PY" - "$N" <<'PYEOF'
import json, pathlib, sys
e = pathlib.Path("eval")
m = json.loads((e/"report_model.json").read_text())
b = json.loads((e/"report_baseline.json").read_text())
def row(label, key, pct=True):
    mv, bv = m.get(key,0) or 0, b.get(key,0) or 0
    d = mv - bv
    f = (lambda x: f"{x:6.1%}") if pct else (lambda x: f"{x:6.3f}")
    arrow = "UP " if d>0 else ("== " if abs(d)<1e-9 else "DN ")
    print(f"  {label:<26} model {f(mv)}   baseline {f(bv)}   {arrow}{f(d) if not pct else f'{d:+.1%}'}")
print(f"  reports scored: {m.get('n')}   model drove verdict: {m.get('model_drove_share',0):.0%} "
      f"(engine mix {m.get('engine_counts')})")
print()
row("disposition acc (9-class)","disposition_accuracy")
row("accept/reject acc","accept_reject_accuracy")
row("macro-F1","macro_f1",pct=False)
row("severity within-1","severity_within_1")
print()
share = m.get("model_drove_share",0)
if share < 0.8:
    print("  >> WARNING: model drove <80% of verdicts -> it is emitting invalid")
    print("     JSON and hiding behind the heuristic. The tune has a FORMAT problem.")
elif m.get("disposition_accuracy",0) <= b.get("disposition_accuracy",0):
    print("  >> Tune does NOT beat the baseline on this slice. Inspect eval/report_model.md")
    print("     (confusion matrix) for class collapse before shipping.")
else:
    print("  >> Tune beats baseline AND drives its own verdicts. Looks healthy.")
PYEOF
echo; echo "reports: eval/report_model.md  eval/report_baseline.json"

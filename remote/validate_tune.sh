#!/usr/bin/env bash
# Validate the LoRA tune on the Mac, end to end, from the git-synced repo.
#   1. serve base VibeThinker-3B + the trained adapter (mlx_lm.server)
#   2. defense suite (offline, model-independent guardrails) -> must stay 6/6
#   3. score the SERVED tuned model on held-out reports, greedy + bounded budget
#   4. score the heuristic+defense baseline on the SAME reports
#   5. print the lift + the share of verdicts the MODEL actually drove
#
# Usage:  bash validate_tune.sh [N]      (N = held-out reports to score, default 20)
set -uo pipefail

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

# ---- 3. score the SERVED tuned model -------------------------------------
# VibeThinker is a REASONING model: it emits a long <think> phase FIRST and the
# JSON answer only AFTER it. A small budget truncates it mid-think -> empty
# content -> parse fail. Give it real room (8000) and DISABLE the heuristic
# fallback so a parse miss counts against the MODEL, not as a hidden baseline win.
MAXTOK="${MODEL_MAX_TOKENS:-8000}"
NOFB="${MODEL_NO_FALLBACK:-1}"
echo; echo "== tuned model on $N held-out reports (greedy, max_tokens=$MAXTOK, no-fallback=$NOFB) =="
rm -f eval/report.json eval/report.md   # never let a stale report masquerade as the model's
if ! MODEL_MAX_TOKENS="$MAXTOK" MODEL_NO_FALLBACK="$NOFB" MODEL_TEMPERATURE=0 MODEL_TOP_P=1.0 MODEL_TIMEOUT=600 \
     "$PY" eval/run_eval.py --data "$DATA" --n "$N" \
     --model-base-url "http://localhost:$PORT/v1"; then
  echo; echo "!! model eval FAILED (see traceback above). Aborting before the lift step"
  echo "   so we do not report a bogus comparison."
  exit 1
fi
[ -f eval/report.json ] || { echo "!! model eval produced no report.json; aborting"; exit 1; }
cp -f eval/report.json eval/report_model.json
cp -f eval/report.md   eval/report_model.md 2>/dev/null

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

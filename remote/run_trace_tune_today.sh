#!/usr/bin/env bash
# Today-only guarded training entrypoint. It refuses to train unless the
# improvement rationale, artifact manifest, and trace data gate are present.
set -euo pipefail

cd "${BB:-$HOME/bbverifier}"
source "${PYENV:-$HOME/vt/bin/activate}"
export TOKENIZERS_PARALLELISM=false

if ! command -v emberglass-tune >/dev/null 2>&1; then
  echo "[today] FATAL: pip install -e ../emberglass-tune"
  exit 1
fi

DOC="ops/today_tune_preflight_2026-06-23.md"
ASSETS="ops/expected_assets_2026-06-23.md"
TRACE_FILE="${TRACE_FILE:-data/sft/train_traces.jsonl}"
MODEL="${MODEL:-$HOME/models/VibeThinker-3B}"
OUT_ADAPTER="${OUT_ADAPTER:-adapters/trace-aligned-today}"
OUT_MODEL="${OUT_MODEL:-$HOME/models/vibethinker-bbtriage-trace-aligned-today}"
RUN_ID="${RUN_ID:-trace_aligned_today_$(date -u +%Y%m%dT%H%M%SZ)}"

mkdir -p ops adapters logs eval "$HOME/models"

test -f "$DOC" || { echo "[today] FATAL: missing preflight doc $DOC"; exit 1; }
test -f "$ASSETS" || { echo "[today] FATAL: missing expected asset doc $ASSETS"; exit 1; }

echo "[today] run_id=$RUN_ID"
echo "[today] trace gate ..."
emberglass-tune gate-traces \
  --traces "$TRACE_FILE" \
  --test data/sft/test.jsonl \
  --out "ops/${RUN_ID}_trace_gate.json" \
  --min-traces "${MIN_TRACES:-1000}" \
  --min-think-p50 "${MIN_THINK_P50:-900}" \
  --min-per-tested-class "${MIN_PER_TESTED_CLASS:-40}"

echo "[today] tokenization preflight ..."
emberglass-tune verify \
  --model "$MODEL" \
  --data "$TRACE_FILE" \
  --min-usable "${MIN_USABLE:-500}"

echo "[today] smoke train ..."
emberglass-tune train --model "$MODEL" \
  --data "$TRACE_FILE" --out adapters/_smoke_trace_today \
  --limit 64 --max-steps 8 --bs 4 --grad-accum 2 --save-steps 8 --valid-frac 0.1

echo "[today] full trace-aligned SFT ..."
emberglass-tune train --model "$MODEL" \
  --data "$TRACE_FILE" \
  --out "$OUT_ADAPTER" \
  --epochs "${EPOCHS:-4}" \
  --bs "${TRAIN_BS:-4}" \
  --grad-accum "${GRAD_ACCUM:-8}" \
  --save-steps "${SAVE_STEPS:-50}" \
  --lr "${LR:-1e-4}" \
  --valid-frac "${VALID_FRAC:-0.05}"

echo "[today] merge adapter ..."
emberglass-tune merge --base "$MODEL" --adapter "$OUT_ADAPTER" --out "$OUT_MODEL"

python - "$RUN_ID" "$TRACE_FILE" "$OUT_ADAPTER" "$OUT_MODEL" <<'PY'
import hashlib, json, os, subprocess, sys
from pathlib import Path

run_id, trace_file, adapter, model = sys.argv[1:5]
def sha(path):
    p = Path(path).expanduser()
    if p.is_file():
        return hashlib.sha256(p.read_bytes()).hexdigest()
    return ""

manifest = {
    "run_id": run_id,
    "base_model": os.environ.get("MODEL", str(Path.home() / "models/VibeThinker-3B")),
    "trace_file": trace_file,
    "trace_sha256": sha(trace_file),
    "adapter_dir": adapter,
    "merged_model_dir": model,
    "git_head": subprocess.getoutput("git rev-parse HEAD 2>/dev/null || true"),
    "git_status": subprocess.getoutput("git status --short 2>/dev/null || true"),
}
Path("ops").mkdir(exist_ok=True)
Path(f"ops/{run_id}_artifact_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
print(json.dumps(manifest, indent=2))
PY

echo "[today] complete: adapter=$OUT_ADAPTER merged=$OUT_MODEL"

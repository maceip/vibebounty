#!/usr/bin/env bash
# Convert the fused VibeThinker-3B bug-bounty tune into MLC q4f16_1 weights for
# in-browser WebGPU (WebLLM), then publish them to Hugging Face.
#
# We do NOT compile a WASM here: VibeThinker-3B is Qwen2.5-3B architecture, so the
# browser reuses the prebuilt model_lib referenced in docs/app.js:
#   Qwen2.5-3B-Instruct-q4f16_1-ctx4k_cs1k-webgpu.wasm
# Therefore the weights MUST be produced with the SAME knobs the lib was built for:
#   quantization q4f16_1 · conv_template qwen2 · context 4096 · prefill chunk 1024
#
# These names are kept in lockstep with docs/app.js (WEBGPU_APP_CONFIG):
#   HF repo   : macmacmacmac/VibeThinker-3B-BugBounty-Triage-MLC
#   model_id  : VibeThinker-3B-BugBounty-Triage-q4f16_1-MLC
#
# Idempotent: re-running skips conversion if $DIST is already built and skips the
# upload if .mlc_pushed exists. Output-gated: every stage verifies its artifacts
# before continuing.
#
#   bash remote/convert_mlc.sh                 # uses the fused model on disk
#   SRC=WeiboAI/VibeThinker-3B bash ...        # or convert any source model
set -uo pipefail

PY="${PY:-$HOME/bbverifier/.venv/bin/python}"
SRC="${SRC:-$HOME/bbverifier/vibethinker-bbtriage}"          # fused tune (or an HF id)
DIST="${DIST:-$HOME/bbverifier/mlc/VibeThinker-3B-BugBounty-Triage-q4f16_1-MLC}"
MLC_REPO="${MLC_REPO:-macmacmacmac/VibeThinker-3B-BugBounty-Triage-MLC}"
QUANT="q4f16_1"
CONV="qwen2"
CTX=4096
PREFILL=1024

echo "[mlc] PY=$PY"
echo "[mlc] SRC=$SRC"
echo "[mlc] DIST=$DIST"
echo "[mlc] target HF repo=$MLC_REPO  (must match docs/app.js WEBGPU_APP_CONFIG)"

# ---- 0. source must exist -------------------------------------------------
if [ ! -e "$SRC" ] && ! printf '%s' "$SRC" | grep -q '/'; then
  echo "[mlc] ABORT: source '$SRC' not found and is not an HF id"; exit 1
fi
if [ -e "$SRC/config.json" ]; then
  echo "[mlc] source is a local fused model dir"
elif [ -d "$SRC" ]; then
  echo "[mlc] ABORT: '$SRC' exists but has no config.json (not a fused model dir)"; exit 1
else
  echo "[mlc] source will be resolved as an HF id: $SRC"
fi

# ---- 1. toolchain (mlc-llm + tvm) -----------------------------------------
if ! "$PY" -c 'import mlc_llm' 2>/dev/null; then
  echo "[mlc] installing mlc-llm + mlc-ai nightly (CPU build is enough for weight conversion)"
  "$PY" -m pip install --pre -U -f https://mlc.ai/wheels mlc-llm-nightly-cpu mlc-ai-nightly-cpu \
    || "$PY" -m pip install --pre -U -f https://mlc.ai/wheels mlc-llm-nightly mlc-ai-nightly \
    || { echo "[mlc] ABORT: could not install mlc-llm. See https://llm.mlc.ai/docs/install/mlc_llm.html"; exit 2; }
fi
"$PY" -c 'import mlc_llm, tvm; print("[mlc] mlc_llm + tvm ready")' \
  || { echo "[mlc] ABORT: mlc_llm/tvm import failed after install"; exit 2; }
MLC=("$PY" -m mlc_llm)

mkdir -p "$DIST"

# ---- 2. convert weights (skip if already done) ----------------------------
if [ -f "$DIST/ndarray-cache.json" ]; then
  echo "[mlc] weights already converted -> skip convert_weight"
else
  echo "[mlc] convert_weight ($QUANT) ..."
  "${MLC[@]}" convert_weight "$SRC" --quantization "$QUANT" -o "$DIST" \
    || { echo "[mlc] ABORT: convert_weight failed"; exit 3; }
fi

# ---- 3. generate mlc-chat-config (matches the prebuilt WASM lib) ----------
echo "[mlc] gen_config (conv=$CONV ctx=$CTX prefill=$PREFILL) ..."
"${MLC[@]}" gen_config "$SRC" --quantization "$QUANT" --conv-template "$CONV" \
  --context-window-size "$CTX" --prefill-chunk-size "$PREFILL" -o "$DIST" \
  || { echo "[mlc] ABORT: gen_config failed"; exit 4; }

# ---- 4. output gate: verify the artifacts ---------------------------------
shards=$(ls "$DIST"/params_shard_*.bin 2>/dev/null | wc -l | tr -d ' ')
if [ ! -f "$DIST/mlc-chat-config.json" ] || [ ! -f "$DIST/ndarray-cache.json" ] || [ "$shards" = "0" ]; then
  echo "[mlc] ABORT: incomplete output (config=$( [ -f "$DIST/mlc-chat-config.json" ] && echo ok || echo MISSING) shards=$shards)"; exit 5
fi
echo "[mlc] OK: mlc-chat-config.json + ndarray-cache.json + $shards weight shards"
"$PY" - "$DIST" <<'PYEOF'
import json, sys, pathlib
d = pathlib.Path(sys.argv[1]); c = json.loads((d/"mlc-chat-config.json").read_text())
print(f"[mlc] config: quant={c.get('quantization')} conv={c.get('conv_template')} "
      f"ctx={c.get('context_window_size')} prefill={c.get('prefill_chunk_size')}")
assert c.get("quantization") == "q4f16_1", "quantization must be q4f16_1 to match the WASM lib"
print("[mlc] config sanity OK")
PYEOF
[ $? -eq 0 ] || { echo "[mlc] ABORT: config sanity failed"; exit 5; }

# ---- 5. publish to Hugging Face (skip if already pushed) ------------------
if [ -f "$DIST/.mlc_pushed" ]; then
  echo "[mlc] already published -> skip upload"
else
  [ -f "$HOME/bbverifier/.hftoken" ] && export HF_TOKEN="$(cat "$HOME/bbverifier/.hftoken")"
  echo "[mlc] creating + uploading to https://huggingface.co/$MLC_REPO"
  "$PY" -c "from huggingface_hub import create_repo; print('[mlc] repo', create_repo('$MLC_REPO', repo_type='model', exist_ok=True))" \
    || echo "[mlc] repo create deferred"
  if "$PY" -m huggingface_hub.commands.huggingface_cli upload "$MLC_REPO" "$DIST" . --repo-type model; then
    touch "$DIST/.mlc_pushed"; echo "[mlc] UPLOAD OK"
  else
    echo "[mlc] UPLOAD FAILED (weights still saved locally at $DIST) — retry when the link is stable"
  fi
fi

echo "[mlc] DONE. In the browser, the 'Run in this browser (WebGPU)' option will now"
echo "      fetch $MLC_REPO and run on the visitor's GPU. Smoke-test it from docs/."

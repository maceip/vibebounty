#!/usr/bin/env bash
# Convert the fused VibeThinker-3B bug-bounty tune into MLC q4f16_1 weights for
# in-browser WebGPU (WebLLM), then publish them to Hugging Face.
#
# We do NOT compile a WASM here: VibeThinker-3B is Qwen2.5-3B architecture, so the
# browser reuses the prebuilt model_lib referenced in docs/app.js:
#   Qwen2.5-3B-Instruct-q4f16_1_cs1k-webgpu.wasm
#
# VibeThinker is a reasoning model, so 4k context is too tight once the prompt
# and long <think> budget are counted. The source model supports much longer
# context; the demo default is 8k because it is materially safer on laptop
# WebGPU than the stock 32k MLC config. Override CTX/PREFILL when intentionally
# building a larger artifact:
#   CTX=32768 PREFILL=2048 bash remote/convert_mlc.sh
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
QUANT="${QUANT:-q4f16_1}"
CONV="${CONV:-qwen2}"
CTX="${CTX:-8192}"
PREFILL="${PREFILL:-2048}"

echo "[mlc] PY=$PY"
echo "[mlc] SRC=$SRC"
echo "[mlc] DIST=$DIST"
echo "[mlc] target HF repo=$MLC_REPO  (must match docs/app.js WEBGPU_APP_CONFIG)"
echo "[mlc] knobs: quant=$QUANT conv=$CONV ctx=$CTX prefill=$PREFILL"

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
# Newer MLC writes tensor-cache.json; older WebLLM expects ndarray-cache.json.
if [ -f "$DIST/ndarray-cache.json" ] || [ -f "$DIST/tensor-cache.json" ]; then
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
# Newer MLC emits tensor-cache.json instead of ndarray-cache.json. WebLLM
# (<=0.2.84) loads ndarray-cache.json, so mirror it when only the new name exists.
if [ -f "$DIST/tensor-cache.json" ] && [ ! -f "$DIST/ndarray-cache.json" ]; then
  cp "$DIST/tensor-cache.json" "$DIST/ndarray-cache.json"
  echo "[mlc] mirrored tensor-cache.json -> ndarray-cache.json (WebLLM compat)"
fi
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
assert int(c.get("context_window_size") or 0) >= 8192, "context must be at least 8192 for VibeThinker demo"
print("[mlc] config sanity OK")
PYEOF
[ $? -eq 0 ] || { echo "[mlc] ABORT: config sanity failed"; exit 5; }

# ---- 4b. write provenance for local/browser e2e verification --------------
GIT_COMMIT="$(git -C "$(dirname "$0")/.." rev-parse HEAD 2>/dev/null || echo unknown)"
"$PY" - "$DIST" "$SRC" "$MLC_REPO" "$GIT_COMMIT" "$CTX" "$PREFILL" <<'PYEOF'
import json, pathlib, sys, datetime
dist, src, repo, commit, ctx, prefill = map(str, sys.argv[1:7])
path = pathlib.Path(dist) / "vibebounty-webgpu-provenance.json"
path.write_text(json.dumps({
    "artifact": "webllm-mlc",
    "model_id": "VibeThinker-3B-BugBounty-Triage-q4f16_1-MLC",
    "source_model": src,
    "hf_repo": repo,
    "base_model": "WeiboAI/VibeThinker-3B",
    "quantization": "q4f16_1",
    "conv_template": "qwen2",
    "context_window_size": int(ctx),
    "prefill_chunk_size": int(prefill),
    "git_commit": commit,
    "created_utc": datetime.datetime.now(datetime.UTC).isoformat(),
}, indent=2), encoding="utf-8")
print(f"[mlc] provenance -> {path}")
PYEOF

# ---- 5. publish to Hugging Face (skip if already pushed) ------------------
if [ -f "$DIST/.mlc_pushed" ]; then
  echo "[mlc] already published -> skip upload"
else
  if [ -f "$HOME/bbverifier/.hftoken" ]; then
    export HF_TOKEN="$(cat "$HOME/bbverifier/.hftoken")"
    export HUGGING_FACE_HUB_TOKEN="$HF_TOKEN"
  fi
  echo "[mlc] creating + uploading to https://huggingface.co/$MLC_REPO"
  if "$PY" - "$DIST" "$MLC_REPO" <<'PYEOF'
import sys
from huggingface_hub import create_repo, upload_folder
dist, repo = sys.argv[1], sys.argv[2]
print("[mlc] repo", create_repo(repo, repo_type="model", exist_ok=True))
print("[mlc] upload ->", upload_folder(folder_path=dist, repo_id=repo, repo_type="model",
      commit_message="VibeThinker-3B bug-bounty triage q4f16_1 MLC"))
PYEOF
  then
    touch "$DIST/.mlc_pushed"; echo "[mlc] UPLOAD OK"
  else
    echo "[mlc] UPLOAD FAILED (weights still saved locally at $DIST) — retry when the link is stable"
  fi
fi

echo "[mlc] DONE. In the browser, the 'Run in this browser (WebGPU)' option will now"
echo "      fetch $MLC_REPO and run on the visitor's GPU. Smoke-test it from docs/."

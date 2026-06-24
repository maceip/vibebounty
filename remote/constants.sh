# Single source of truth for inference/eval budgets. Source from every pipeline script:
#   source "$(dirname "$0")/constants.sh"
#
# Architecture:
#   SERVE layer  -> vLLM (Lambda/CUDA, continuous batching) | transformers (fallback) | mlx (Mac)
#   EVAL layer   -> run_eval.py --workers N (parallel HTTP clients; vLLM batches on GPU)
#
# 4096 is the hard cap everywhere: enough room for thinking + JSON on triage reports.
export TRIAGE_MAX_TOKENS="${TRIAGE_MAX_TOKENS:-4096}"
export TRIAGE_MODEL_TIMEOUT="${TRIAGE_MODEL_TIMEOUT:-300}"
export SERVE_MAX_NEW_TOKENS="${SERVE_MAX_NEW_TOKENS:-4096}"
export SERVE_GEN_TIMEOUT="${SERVE_GEN_TIMEOUT:-240}"
export MODEL_TEMPERATURE="${MODEL_TEMPERATURE:-0}"
export MODEL_TOP_P="${MODEL_TOP_P:-1}"
export MODEL_NO_FALLBACK="${MODEL_NO_FALLBACK:-1}"
# Parallel eval: HTTP workers hitting the serve backend (vLLM batches on GPU; MLX queues).
export EVAL_WORKERS="${EVAL_WORKERS:-8}"
export EVAL_WORKERS_TRANSFORMERS="${EVAL_WORKERS_TRANSFORMERS:-2}"
export EVAL_WORKERS_MLX="${EVAL_WORKERS_MLX:-4}"

export SERVE_BACKEND="${SERVE_BACKEND:-vllm}"
export SERVE_PORT="${SERVE_PORT:-8080}"
export MODEL_NAME="${MODEL_NAME:-VibeThinker-3B-BugBounty-Triage}"
export MODEL_PATH="${MODEL_PATH:-$HOME/models/vibethinker-bbtriage-coldstart}"
export VLLM_MAX_MODEL_LEN="${VLLM_MAX_MODEL_LEN:-4096}"
export VLLM_GPU_MEMORY_UTIL="${VLLM_GPU_MEMORY_UTIL:-0.90}"

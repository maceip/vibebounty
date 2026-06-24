# Software Catalog For VibeThinker Tune Session

Date: 2026-06-23

Purpose: define the software needed on the local Windows laptop and the remote
Linux Lambda GPU machine to complete the trace-aligned VibeThinker-3B tune,
merge it, evaluate it, and demo it.

## Current Job

Tune `WeiboAI/VibeThinker-3B` on the generated bug-bounty thinking traces:

- training data: `data/sft/train_traces.jsonl`
- trace gate: passed on Lambda
- base model: `/home/ubuntu/models/VibeThinker-3B`
- target adapter: `/home/ubuntu/bbverifier/adapters/trace-aligned-today`
- target merged model:
  `/home/ubuntu/models/vibethinker-bbtriage-trace-aligned-today`
- eval target: `eval/report_trace_aligned_today.json`

## Machine Boundary

Local machine:

- OS: Windows 11
- Shell: PowerShell
- Role: orchestration, file transfer, browser/demo work, artifact pull-back
- Must not be the training runtime

Remote machine:

- OS: Ubuntu 22.04 on aarch64
- Shell: bash
- GPU: NVIDIA GH200 480GB
- Driver/CUDA reported: driver `570.148.08`, CUDA `12.8`
- Role: trace generation, training, merge, vLLM eval/serve

## Windows Software Needed

Required:

- OpenSSH client: `ssh`, `scp`
- Git
- Python for local helper scripts
- Node.js/npm for GitHub Pages demo tests
- Playwright/browser tooling for web demo verification
- A terminal that can run PowerShell commands

Useful but not required for training:

- `uv`
- `hf` CLI, only if uploading/pulling HF artifacts from Windows

Windows secrets/files needed:

- Lambda SSH key: `C:\Users\mac\.ssh\id_ed25519`
- Lambda API key in `C:\Users\mac\.env`
- Anthropic API key in `C:\Users\mac\.env`
- Hugging Face token, if pushing artifacts

Windows should not need:

- CUDA
- torch
- transformers
- peft
- vLLM

## Remote Linux Software Needed

System-level:

- Ubuntu 22.04 aarch64
- NVIDIA driver visible through `nvidia-smi`
- CUDA 12.8 runtime/toolkit
- Python 3.10
- pip
- git optional but useful
- enough disk for base model, adapters, merged model, logs, and eval reports

GPU training Python stack:

- `torch` built for CUDA 12.8, with:
  - `torch.cuda.is_available() == True`
  - `torch.cuda.is_bf16_supported() == True`
- `transformers`
- `peft`
- `datasets`
- `accelerate`
- `safetensors`
- `sentencepiece`
- `protobuf`
- `pillow`
- `numpy`
- `pandas`
- `pyarrow`
- `scikit-learn`
- `huggingface_hub`

Trace generation Python stack:

- `anthropic`
- `httpx` and its transitive deps
- same repo code at `/home/ubuntu/bbverifier`
- `ANTHROPIC_API_KEY` available outside the repo

Merge stack:

- `torch`
- `transformers`
- `peft`
- `safetensors`
- tokenizer dependencies for VibeThinker/Qwen tokenizer

Eval and serving stack:

- `openai` Python client
- `vllm` with a CUDA-compatible torch stack
- `fastapi`/server dependencies pulled by vLLM
- repo app dependencies used by `app/triage.py` and `eval/run_eval.py`

Important separation:

- Training can run in one Python environment.
- vLLM serving/eval may need a separate Python environment.
- Do not let vLLM install choices overwrite the training torch stack.

## Remote Assets Needed

Repo:

- `/home/ubuntu/bbverifier`

Base model:

- `/home/ubuntu/models/VibeThinker-3B`

Data:

- `data/sft/train_traces.jsonl`
- `data/sft/test.jsonl`
- `ops/trace_tune_gate_report.json`
- `ops/today_tune_preflight_2026-06-23.md`
- `ops/expected_assets_2026-06-23.md`

Logs:

- `logs/trace_gen_today.log`
- `logs/trace_tune_today.log`
- `~/serve_vllm.log`

Outputs:

- `adapters/trace-aligned-today/`
- `/home/ubuntu/models/vibethinker-bbtriage-trace-aligned-today/`
- `ops/*artifact_manifest*.json`
- `eval/report_trace_aligned_today.json`
- `eval/report_trace_aligned_today.md`
- `eval/scoreboard.jsonl`

## Known Remote State From Catalog

Working system stack:

- system Python: 3.10.12
- system torch: 2.7.0
- system torch CUDA runtime: 12.8
- system torch CUDA available: true
- system GPU: NVIDIA GH200 480GB

Problematic environment:

- `/home/ubuntu/vt` had torch `2.11.0+cu130`
- that environment could not see CUDA on this driver/toolkit stack
- do not use `/home/ubuntu/vt` for training unless it is rebuilt or corrected

Candidate training environment:

- `/home/ubuntu/vt-train`
- created with system site packages so it can use working system torch
- requires confirmation that these import cleanly together:
  - torch
  - transformers
  - peft
  - datasets
  - accelerate
  - PIL/Pillow

## Minimum Pre-Training Checks

Before full training, confirm:

- no train/eval/server/install process is running
- GPU memory is idle
- selected Python is `/home/ubuntu/vt-train/bin/python` or another explicitly
  chosen Python
- selected Python imports:
  - torch
  - transformers
  - peft
  - datasets
  - accelerate
  - safetensors
  - sentencepiece
  - PIL
- selected Python reports:
  - CUDA available: true
  - bf16 supported: true
- trace gate passes on `data/sft/train_traces.jsonl`
- tokenizer loads from `/home/ubuntu/models/VibeThinker-3B`
- a one-step smoke train writes an adapter

Only after those pass should the full tune start.

## Minimum Pre-Eval Checks

Before eval:

- merged model directory exists
- vLLM environment imports vLLM
- vLLM can start the merged model
- `/v1/models` responds
- one eval row runs with `--workers 1`
- full eval runs with explicit workers, e.g. `EVAL_WORKERS=8`

## Do Not Do During Critical Run

- Do not install broad packages into the training environment after training
  starts.
- Do not mix training and vLLM dependency repair in the same environment unless
  forced.
- Do not start full training before a one-step smoke train succeeds.
- Do not terminate the Lambda instance until artifacts and logs are pulled back.


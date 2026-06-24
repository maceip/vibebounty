# VibeBounty — a defense-hardened bug-bounty triage sidecar

A locally fine-tuned **VibeThinker-3B** that triages vulnerability-disclosure
reports — filtering the noise (self-XSS, no-PoC, scanner/AI slop, accepted risk)
and surfacing the genuinely impactful ones, **with a rationale** — and hardened so
an adversary can't flip the verdict with prompt-injection or polished-but-fake prose.

- **Model (LoRA adapter):** https://huggingface.co/macmacmacmac/VibeThinker-3B-BugBounty-Triage
- **Live console:** FastAPI + SSE app in [`app/`](app/) — a HackerOne-style inbox with the model auto-triaging reports as they arrive. Works as a platform-agnostic sidecar (HackerOne / Bugcrowd / Intigriti / YesWeHack / raw paste).
- **In-browser demo (no server):** the static console in [`docs/`](docs/) runs the model **fully client-side** — either in-browser on **WebGPU** (WebLLM/MLC) or against your own local OpenAI-compatible endpoint (MLX / Ollama / vLLM). The model **never runs on our servers**; nothing is uploaded.

## Why it's interesting

Most "LLM triage" trusts the model's prose. The literature shows that's unsafe:
LLM-as-judge verdicts can be flipped 40–74% of the time by prompt-injection —
**including on 3B judges** (JudgeDeceiver `2403.17710`; `2504.18333`; CUA/JMA
`2505.13348`; RobustJudge `2506.09443`), and AI-text detectors collapse under
paraphrase (`2402.11638`). So this system **does not trust the model alone** — it
wraps it in a model-independent **defense layer**:

1. **Prompt-injection isolation** — the report is treated as untrusted *data*, never as instructions.
2. **Claim-level verification** — fabricated code symbols → forced `slop` (a code-canary); real symbols → supported.
3. **Threat-intel corroboration** — CVE/KEV/OSV matches → `corroborated_surge`, so a flood of *legit* reports after a public disclosure is never auto-trashed as spam.
4. **Confidence gating** — confidence is bounded by a claim-reliability score, so fluent-but-unverifiable reports can't present as high-confidence.
5. **No-PoC calibration** — a report carrying real reproduction evidence (steps, request, payload, code, or URL) can never be dismissed as `theoretical_no_poc`; it's reclassified by severity. Stops the model under-valuing reports that *do* include a working PoC.

## Results

The model has been through **two tuning iterations**, each scored on held-out
reports with the real adjudicated outcome as ground truth.

**Iteration 1 — cold-start (short-rationale SFT)** *(superseded)*
MLX LoRA on a Mac over 17k reports, target = short (~200 char) rationale + JSON.
It **collapsed onto the majority class** (`valid_low`): disposition accuracy 0.62,
macro-F1 0.157, and **0% recall** on the classes that matter (`valid_impactful`,
`corroborated_surge`) — below the deterministic heuristic baseline.

**Iteration 2 — trace-aligned SFT** *(shipping — the model on HF + in the demo)*
Re-tuned on **teacher-generated `<think>` reasoning traces** (~1.4k chars of
report-specific reasoning before the verdict), sanitized to remove outcome leakage,
on an NVIDIA GH200.

| metric (held-out, 9-class) | heuristic baseline | iter-1 cold-start | iter-2 trace-aligned |
|---|---|---|---|
| disposition accuracy | 0.60 | 0.62 *(on 300)* | 0.53 *(calibrated)* |
| accept / reject accuracy | 0.98 | — | 0.88 *(calibrated)* |
| macro-F1 | 0.247 | 0.157 | **0.428** |
| `corroborated_surge` recall | 0.00 | 0.00 | **1.00** |
| model drove the verdict | n/a | — | **100%** |
| adversarial defense suite | 12/12 | 12/12 | **12/12** |

**Honest read:** iteration 2 is a large jump over iteration 1 on the hard minority
classes (macro-F1 0.157 → 0.428; surge recall 0 → 100%) and finally *drives* the
verdicts rather than deferring to the heuristic. It does **not yet beat the pure
deterministic heuristic** on headline 9-class accuracy, so the defense layer stays
in front of the model. (Iter-2 numbers are on a 60-report slice; iter-1's are on
300 — not perfectly comparable; re-run `remote/validate_tune.sh 300` for a matched
eval. The adversarial suite is model-independent, so it reports regardless.)

**A real verdict from the tuned model** (greedy, served via `mlx_lm`):

```json
// IDOR: GET /api/v2/invoices/{id} returns other tenants' invoices
{"disposition": "valid_impactful", "severity_estimate": "high",
 "reasoning": "Reproducible IDOR on an authenticated endpoint; incrementing the id
 returns other tenants' invoices -> crosses a privilege boundary with demonstrated
 cross-tenant disclosure impact.",
 "confidence": 0.92, "used_external_corroboration": false}
```

## How we tune

The tune is a **two-stage, gated pipeline**, not a one-shot fine-tune. The guiding
rule: only ship a tune that beats the previous one on held-out, real-outcome data.

### 1. Data — reasoning traces, not outcome labels

The cold-start failure taught us the input signal was wrong: short rationales that
leaked the outcome (`"It resolved as ..."`) — information a live analyst never has.
So the shipping stage trains on **faithful `<think>` reasoning traces**:

```bash
# pick a class-balanced seed from the labeled corpus (counters the valid_low collapse)
python data/select_trace_seed.py --in data/sft/train.jsonl \
  --out data/sft/train_trace_seed.jsonl --manifest ops/train_trace_seed_manifest.json
# generate teacher traces (a strong model thinks; a second model checks faithfulness)
python data/trace_gen.py --in data/sft/train_trace_seed.jsonl \
  --out data/sft/train_traces.jsonl --verify --drop-unfaithful \
  --model claude-opus-4-8 --predict-model claude-sonnet-4-6
```

Traces are then **sanitized** — assistant-side outcome leakage stripped, malformed
final JSON dropped — before they're allowed near the trainer.

### 2. Gate — refuse to train on bad data

`remote/run_trace_tune_today.sh` will not start training unless every gate passes:

| gate | check |
|------|-------|
| `remote/trace_tune_gate.py` | ≥1000 traces, `<think>` p50 ≥ 900 chars, ≥40 rows per tested class |
| `remote/verify_sft_data.py` | ≥500 rows tokenize cleanly against the base tokenizer |
| smoke train | an 8-step run must succeed before the full run starts |

### 3. Train — prompt-masked LoRA SFT on GPU

`remote/train_sft.py` (PyTorch + PEFT) on the Lambda GH200, with loss masked to the
assistant turn only:

- base: `WeiboAI/VibeThinker-3B` (Qwen2.5-3B architecture)
- LoRA `r=32` / `α=64` / dropout `0.05` on all attention + MLP projections
- bf16, gradient checkpointing, cosine LR (`1e-4`) + 3% warmup, `max_seq 8192`, 4 epochs
- merge the adapter into a full model with `remote/merge_lora.py`

```bash
bash remote/run_trace_tune_today.sh   # gate -> smoke -> full SFT -> merge -> manifest
```

Every accepted run writes `ops/<run_id>_artifact_manifest.json` (trace sha256 + git
HEAD) for provenance.

### 4. Evaluate — must beat the prior tune

Serve the merged model with vLLM and score it in parallel against the held-out split:

```bash
MODEL_PATH=$HOME/models/vibethinker-bbtriage-<run> SERVE_BACKEND=vllm \
  EVAL_WORKERS=8 bash remote/eval_model.sh 300
```

Acceptance: `model_drove_share ≥ 0.8`, minority-class recall up vs the prior tune,
and clean JSON/verdict validity. If it doesn't beat the baseline it ships demo-only,
labeled honestly.

### 5. Package for the browser

The accepted merged model is converted to MLC `q4f16_1` and published to HF for
in-browser WebGPU:

```bash
bash remote/convert_mlc.sh            # fused tune -> MLC q4f16_1 -> Hugging Face
```

## Quickstart — the live console

```bash
pip install -r requirements.txt
uvicorn app.server:app --port 8000      # run from bb-triage/
# open http://localhost:8000
```

- The inbox seeds itself and triages live on load (updates stream over SSE).
- **+ New report** ingests a submission; **⚡ Simulate disclosure surge** injects a
  detailed report plus a burst of near-duplicates about a real vulnerable package,
  showing they're tagged `corroborated_surge` (not spam) with a live KEV/OSV panel.
- **Engine:** if `MODEL_BASE_URL` (default `http://localhost:8080/v1`) is reachable
  it uses VibeThinker-3B; otherwise it falls back to a transparent heuristic so the
  demo always works. To serve the tuned model:

```bash
mlx_lm.server --model WeiboAI/VibeThinker-3B --adapter-path adapters --port 8080
```

## Run it in the browser (no server)

The static console in [`docs/`](docs/) (deployable to GitHub Pages from `main`/`docs`)
loads the UI and then **blocks behind a model gate** — the model runs client-side, never on a server:

- **WebGPU (in-browser):** VibeThinker-3B is Qwen2.5-3B architecture, so the tuned
  weights are converted to **MLC `q4f16_1`** and reuse the prebuilt Qwen2.5-3B WASM
  lib; WebLLM runs them on the visitor's GPU. Build + publish the weights with:

```bash
bash remote/convert_mlc.sh        # fused tune -> MLC q4f16_1 -> Hugging Face
```

- **Local endpoint:** already serving the model with MLX/Ollama/vLLM? Point the gate
  at your OpenAI-compatible base URL (allow CORS from the page origin).

The deterministic engine (`docs/engine.mjs`) is a 1:1 port of the Python defense
layer and is covered by `node docs/engine.test.mjs` (18 checks, parity with
`eval/adversarial.py`).

## How it works

| path | purpose |
|------|---------|
| `prompts/triage_system.txt` | system prompt / disposition taxonomy for the model |
| `app/triage.py` | enrich → model verdict → **defense layer** (`_apply_defenses`) |
| `feeds/enrich.py` | corroborate a report against KEV/NVD/GHSA/OSV |
| `app/` | live FastAPI + SSE triage console (the sidecar) |
| `docs/` | static, client-side console (GitHub Pages) — WebGPU or local endpoint; `docs/engine.mjs` is the deterministic engine shared with `docs/engine.test.mjs` |
| `eval/run_eval.py` | score the pipeline on held-out data (baseline or served model) |
| `eval/adversarial.py` | the 12-case defense suite (6 end-to-end + 6 unit overrides: injection, slop, corroboration, **no-PoC calibration**, confidence gating) |
| `eval/report_viewer.html` | offline viewer for `report.json` — headline lift, confusion-matrix heatmap, per-class P/R/F1 |
| `remote/convert_mlc.sh` | convert the fused tune to MLC `q4f16_1` for in-browser WebGPU and publish to HF |

## Evaluation — reproduce

```bash
# score the heuristic+defense baseline on the held-out split (fully offline)
python eval/run_eval.py
# score the served tuned model and compare the lift (writes report_model.json + report_baseline.json)
bash remote/validate_tune.sh 300
# the 12-case adversarial defense suite (model-independent guardrails)
python eval/adversarial.py
```

`run_eval.py` writes `eval/report.json` + `eval/report.md` (accuracy, per-class
P/R/F1, confusion matrix, severity) and reports the share of verdicts the model
actually drove — so a model that emits invalid JSON can't hide behind the heuristic.
Open `eval/report_viewer.html` in a browser and drop in `report_model.json`
(+ `report_baseline.json`) for a visual lift + confusion-matrix heatmap.

## Threat-intel corroboration

When a CVE drops in a popular library, hundreds of *legitimate* reports flood in at
once; they must not be auto-trashed as duplicates/spam. `feeds/` grounds triage in
live, free, anonymous threat intel:

| source | what | auth |
|--------|------|------|
| CISA KEV | actively-exploited CVEs | none |
| OSV.dev | per-package vuln lookup (npm/PyPI/…) + GHSA | none |
| NVD | recent CVE disclosures | none (flaky; optional key) |
| GHSA | recent GitHub advisories | optional token |

```bash
python feeds/fetch_feeds.py --days 14     # refresh local cache (KEV always)
```

A recent match steers the verdict toward `corroborated_surge` / `valid_*` and never
`slop`; a CISA KEV hit (actively exploited) bumps severity.

## Build it from scratch (optional)

The kit also bootstraps from zero real submissions, in order:

0. **`rubric.md`** — the disposition taxonomy / spec (source of truth).
1. **`schema.json`** — JSON schema for the verdict; `data/seed_examples.jsonl` — hand-labeled examples across all 9 dispositions.
2. **`synthesize.py`** — scale the dataset with synthetic submissions (use a *strong* model, not the 3B); spot-check, then mix with real data.
3. **`baseline.py`** — score the model zero-shot vs labels; that number is the bar fine-tuning must beat.
4. **Fine-tune** — convert rows to chat format, LoRA fine-tune with `mlx_lm.lora`, re-run the eval to measure the lift, then deploy in shadow mode and harvest real adjudications to retrain.

Each `label` is the *real adjudicated outcome* — your ground truth. Hold out a chunk
as the test set.

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

**Training** — LoRA (rank 16, all 36 layers) on **17k reports labeled from real
disclosure outcomes**, 2000 iters on a 128 GB M-series Mac via MLX:

```
Iter   10: Train loss 3.43
Iter  400: Val loss 1.056
Iter 2000: train loss ~0.67   (3.43 -> 0.67)   peak mem ~32 GB
```

**Evaluation** — held-out 300 reports, real disclosure outcomes. The table below
is the deterministic **heuristic + defense baseline**, which is the bar the tuned
model is measured against (`eval/run_eval.py` scores either path):

| metric | baseline |
|---|---|
| accept / reject accuracy | **97.0%** |
| disposition accuracy (9-class) | 65.0% |
| macro-F1 / weighted-F1 | 0.194 / 0.580 |
| severity within-1 (ordinal) | 76.3% (MAE 0.90) |
| adversarial defense suite | **12 / 12 pass** |

Read this as the floor: rules already nail the binary decision (97%) but are weak
on fine-grained 9-class disposition and rare classes (e.g. `corroborated_surge`
needs a live feed match) — exactly what the tune is for. Re-run with
`--model-base-url` to measure the lift over this baseline; the tuned-model numbers
on the same 300 are produced by `remote/validate_tune.sh 300`.

**A real verdict from the tuned model** (greedy, served via `mlx_lm`):

```json
// IDOR: GET /api/v2/invoices/{id} returns other tenants' invoices
{"disposition": "valid_impactful", "severity_estimate": "high",
 "reasoning": "Reproducible IDOR on an authenticated endpoint; incrementing the id
 returns other tenants' invoices -> crosses a privilege boundary with demonstrated
 cross-tenant disclosure impact.",
 "confidence": 0.92, "used_external_corroboration": false}
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

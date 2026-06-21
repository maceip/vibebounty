# VibeBounty — a defense-hardened bug-bounty triage sidecar

A locally fine-tuned **VibeThinker-3B** that triages vulnerability-disclosure
reports — flagging the noise (self-XSS, no-PoC, scanner/AI slop, accepted risk)
and surfacing the genuinely impactful ones — **with a rationale**, and hardened
so an adversary can't flip the verdict with prompt-injection or polished-but-fake
prose.

- **Model (LoRA adapter):** https://huggingface.co/macmacmacmac/VibeThinker-3B-BugBounty-Triage
- **Live console:** FastAPI + SSE app in [`app/`](app/) — HackerOne-style inbox + AI triage sidecar, works as a platform-agnostic sidecar for HackerOne / Bugcrowd / Intigriti / YesWeHack / raw paste.

## Why it's interesting

Most "LLM triage" trusts the model's prose. The literature shows that's unsafe:
LLM-as-judge verdicts can be flipped 40–74% of the time by prompt-injection,
**including on 3B judges** (JudgeDeceiver 2403.17710; 2504.18333; CUA/JMA on 3B
2505.13348; RobustJudge 2506.09443), and AI-text detectors collapse under
paraphrase (2402.11638). So this system **does not trust the model alone** — it
adds a model-independent **defense layer**:

1. **Prompt-injection isolation** — the report is treated as untrusted *data*, never instructions.
2. **Claim-level verification** — decompose the report into claims and check each against ground truth: fabricated code symbols → forced `slop` (a "Honeyslop" code-canary), real symbols → supported.
3. **Threat-intel corroboration** — CVE/KEV/OSV matches → `corroborated_surge`, so a flood of *legit* reports after a public disclosure is never auto-trashed as spam.
4. **Confidence gating** — confidence is bounded by a claim-reliability score, so fluent-but-unverifiable reports can't present as high-confidence.

## Results (real, reproducible)

**Training** — LoRA (rank 16, all 36 layers) on **~18k reports labeled from real
disclosure outcomes**, 2000 iters on an M-series Mac via MLX:

```
Iter   10: Train loss 3.43   ...   Iter 400: Val loss 1.056
Iter 2000: train loss < 0.7   (train 3.43 -> 0.67, val ~1.06)   peak mem 32 GB
```

**Evaluation** (held-out 300 reports, offline; the deterministic baseline the
tuned model is measured against):

| metric | value |
|---|---|
| accept / reject accuracy | **97.3%** |
| disposition accuracy (9-class) | 56.3% |
| macro-F1 | 0.191 |
| severity within-1 | 71.0% |
| **adversarial defense suite** | **6/6 pass** |

Reproduce: `uv run python eval/run_eval.py` and `uv run python eval/adversarial.py`.

---

This kit also lets you start **with zero real submissions** by bootstrapping from
a rubric + synthetic data, baseline the model zero-shot, then improve it as real
data arrives.

## Results & showcase

**Tuned model:** [`macmacmacmac/VibeThinker-3B-BugBounty-Triage`](https://huggingface.co/macmacmacmac/VibeThinker-3B-BugBounty-Triage) — a LoRA fine-tune of VibeThinker-3B, trained on ~18k real bug-bounty disclosure outcomes.

### Training run (MLX LoRA, Apple silicon, 128 GB)
2000 iters · batch 8 · seq 2048 · LoRA rank 16 (all 36 layers) · lr 1e-4 · `mask_prompt`.

```
Iter  10: Train loss 3.43 ...
Iter 400: Val loss 1.056, Val took 59.0s
Iter 400: Train loss 1.155 ... Saved adapter weights
Iter 470: Train loss 0.672 ...
Iter 2000: training complete -> adapters/adapters.safetensors  (peak mem ~32 GB)
```
Train loss **3.43 → ~0.67**, val loss **1.056** — the adapter learned the verdict
schema and reasoning style from real disclosure outcomes.

### Inference (base + LoRA adapter, no fuse needed)

```bash
mlx_lm.generate --model WeiboAI/VibeThinker-3B --adapter-path adapters \
  --prompt "<triage system prompt> + <report>"
```

Representative verdicts the tuned model produced on held-out reports:

```json
// IDOR: GET /api/v2/invoices/{id} returns other tenants' invoices
{"disposition": "valid_impactful", "severity_estimate": "high",
 "reasoning": "IDOR / broken-authz against an authenticated API; incrementing id
 walks the table -> crosses a real trust boundary with demonstrated impact.",
 "confidence": 0.9}

// Log4Shell report carrying an EXTERNAL CORROBORATION block (CVE-2021-44228, KEV)
{"disposition": "corroborated_surge", "severity_estimate": "critical",
 "reasoning": "Maps to a publicly disclosed advisory confirmed by the live feed
 (CISA KEV, actively exploited) -> corroborated, not spam.",
 "used_external_corroboration": true, "confidence": 0.9}
```

### Evaluation (held-out 300 reports, offline)

| metric | heuristic + defense baseline |
|---|---|
| accept / reject accuracy | **97.3%** |
| disposition accuracy (9-class) | 56.3% |
| macro-F1 | 0.191 |
| severity within-1 (ordinal) | 71.0% |
| **adversarial defense suite** | **6 / 6 pass** |

Re-run against the served tune to measure the lift:
`python eval/run_eval.py --model-base-url http://localhost:8080/v1`

### Why it's interesting
A 3B model small/cheap enough to run on a laptop, specialized for verifiable
security triage, **wrapped in a model-independent defense layer** (prompt-injection
isolation, claim-level verification against a real symbol table, and live
threat-intel corroboration) so an adversary can't flip the verdict with prettier
prose. See `eval/adversarial.py` and the citation map in the project notes.

## Layout

| file | purpose |
|------|---------|
| `rubric.md` | Step 0 — the disposition taxonomy / spec (the source of truth). |
| `schema.json` | Step 1 — JSON schema for the model's verdict. |
| `prompts/triage_system.txt` | System prompt for the triage model. |
| `prompts/synthesis_system.txt` | System prompt for generating synthetic data. |
| `data/seed_examples.jsonl` | Step 2 — 15 hand-labeled examples across all 8 dispositions. |
| `synthesize.py` | Step 2c — scale the dataset with synthetic submissions. |
| `baseline.py` | Step 3 — score the model vs labels (accuracy + confusion). |
| `feeds/fetch_feeds.py` | Refresh local threat-intel cache (CISA KEV, NVD recent, opt. GHSA). |
| `feeds/enrich.py` | Corroborate a submission against KEV/NVD/GHSA/OSV; emit `external_corroboration`. |
| `app/` | **Live triage console** — a HackerOne/Bugcrowd-style web app with the sidecar auto-triaging reports as they arrive. |

## Live console (the sidecar PoC)

A web app where reports stream into an inbox and are **auto-triaged the moment
they arrive** — the model acts as a passive observer "on your shoulder," not a
script you run per report. Updates push to the browser live over SSE.

```bash
pip install -r requirements.txt
# (optional) serve the real model so the sidecar uses VibeThinker:
#   mlx_lm.server --model WeiboAI/VibeThinker-3B --port 8080
# (optional) refresh threat-intel cache for corroboration badges:
#   python feeds/fetch_feeds.py --days 14

uvicorn app.server:app --port 8000   # run from the bb-triage/ directory
# open http://localhost:8000
```

- The inbox seeds itself and triages live on load.
- **+ New report** ingests a random submission; **⚡ Simulate disclosure surge**
  injects one detailed report + a burst of near-duplicates about a real
  vulnerable package, demonstrating they're tagged `corroborated_surge` (not
  spam) with a live CISA KEV / OSV corroboration panel.
- Engine: if `MODEL_BASE_URL` (default `http://localhost:8080/v1`) is reachable
  it uses **VibeThinker-3B**; otherwise it falls back to a transparent heuristic
  so the demo always works. The active engine is shown in the header and per
  report. Configure via env: `MODEL_BASE_URL`, `MODEL_NAME`, `MODEL_MAX_TOKENS`.

## Setup

```bash
pip install -r requirements.txt
```

## Step 3: baseline the model (do this first)

Serve VibeThinker-3B on an OpenAI-compatible endpoint. On the Mac:

```bash
pip install mlx-lm
mlx_lm.server --model WeiboAI/VibeThinker-3B --port 8080
```

(or vLLM / Ollama / llama.cpp — anything OpenAI-compatible). Then:

```bash
python baseline.py --base-url http://localhost:8080/v1 --model WeiboAI/VibeThinker-3B
```

This prints exact-disposition accuracy, a coarse accept/reject accuracy, and a
confusion list. That number is your zero-shot baseline — the bar fine-tuning
must beat. If it's already good enough, you may not need to fine-tune at all.

## Step 2c: scale the dataset (if baseline needs work)

Use a **strong** model for generation (not the 3B):

```bash
python synthesize.py --base-url <strong-model-endpoint> --model <strong-model> \
  --n-per-class 25 --out data/synthetic.jsonl
```

Review/spot-check the output, then mix `synthetic.jsonl` with real submissions.

## Threat-intel corroboration (anti-false-negative)

Problem: when a CVE drops in a popular library, hundreds of *legitimate* reports
flood in at once. We must not auto-trash them as spam/duplicates. The `feeds/`
module grounds triage in live threat intelligence.

All sources below are anonymous / free (verified working):

| Source | What | Auth |
|--------|------|------|
| CISA KEV | actively-exploited CVEs | none |
| OSV.dev | per-package vuln lookup (npm/PyPI/...) + GHSA | none |
| NVD | recent CVE disclosures | none (flaky; optional API key recommended) |
| GHSA | recent GitHub advisories | optional GitHub token |

Note: the US-gov STIX/TAXII feed (CISA AIS, `ais2.cisa.dhs.gov`) and MITRE
ATT&CK TAXII carry IOCs/TTPs, not library disclosures, so they are NOT used here.
CISA AIS also requires a signed Interconnection Agreement + Federal Bridge PKI
cert + static IP — out of scope for this pipeline.

```bash
# 1. refresh the local cache (KEV always; NVD best-effort)
python feeds/fetch_feeds.py --days 14
#    optionally add recent GitHub advisories:
python feeds/fetch_feeds.py --days 14 --github-token ghp_xxx

# 2. enrich a batch of submissions (adds an external_corroboration field)
python feeds/enrich.py --data data/incoming.jsonl --out data/incoming.enriched.jsonl

# 3. baseline WITH corroboration injected into the triage prompt
python baseline.py --enrich --base-url http://localhost:8080/v1 --model WeiboAI/VibeThinker-3B
```

When `enrich` finds a recent match, the triage prompt instructs the model to
prefer `corroborated_surge` / `valid_*` and never label it `slop` or
`theoretical_no_poc`. A CISA KEV hit (actively exploited) bumps severity.

## Adding real submissions

Append them to a JSONL with the same shape as `data/seed_examples.jsonl`:
each line = `{"id", "submission": {title, severity_claimed, asset, description,
steps_to_reproduce, impact}, "label": {disposition, severity_estimate,
is_duplicate_risk, reasoning, questions_for_researcher, confidence}}`.

The `label` is the *real adjudicated outcome* — that's your ground truth.
Hold out a chunk as a test set and re-run `baseline.py` against it.

## Evaluation (`eval/`)

Two harnesses, both runnable **fully offline** (no model server, no network):

```bash
# 1) score the pipeline over the held-out test split (real disclosure outcomes)
uv run --with pandas --with pyarrow python eval/run_eval.py      # heuristic+defense baseline
uv run python eval/run_eval.py --model-base-url http://localhost:8080/v1  # score the tuned model
#    -> writes eval/report.json + eval/report.md (accuracy, per-class P/R/F1, confusion, severity)

# 2) adversarial defense suite (injection, fabricated slop, corroborated surge)
uv run python eval/adversarial.py
```

**Baseline (heuristic + defense layers, 300 held-out examples, offline):**

| metric | value |
|---|---|
| accept / reject accuracy | **97.3%** |
| disposition accuracy (9-class) | 56.3% |
| macro-F1 | 0.191 |
| weighted-F1 | 0.548 |
| severity within-1 (ordinal) | 71.0% (MAE 1.00) |
| adversarial defense suite | **6/6 pass** |

Read this as the **bar fine-tuning must beat**: the rules already nail the binary
triage decision (97%), but are weak on fine-grained 9-class disposition, rare
classes, and historical-CVE corroboration (the cache only holds recent/KEV CVEs).
Closing that gap is precisely the job of the fine-tuned model — re-run
`run_eval.py --model-base-url ...` against the served tune to measure the lift.

## Next (fine-tuning)

Once you have a few hundred examples and a baseline:
1. Convert rows to chat format (`messages`: system=triage prompt, user=rendered
   submission, assistant=reasoning + verdict JSON).
2. LoRA fine-tune with `mlx_lm.lora` on the Mac.
3. Re-run `baseline.py` on the held-out test set to measure the lift.
4. Iterate: deploy in shadow mode, harvest real adjudications, retrain.

# Bug Bounty Triage — VibeThinker-3B starter kit

Goal: a local, fine-tuned VibeThinker-3B that triages bug bounty submissions —
flagging the bullshit (self-XSS, no-PoC, scanner slop, accepted risk) and
surfacing the genuinely interesting ones — with a rationale.

This kit lets you start **with zero real submissions** by bootstrapping from a
rubric + synthetic data, baseline the model zero-shot, then improve it as real
data arrives.

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

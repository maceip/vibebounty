---
license: mit
base_model: WeiboAI/VibeThinker-3B
base_model_relation: adapter
library_name: mlx
pipeline_tag: text-generation
language:
- en
tags:
- mlx
- lora
- security
- bug-bounty
- vulnerability-triage
- vibethinker
- llm-as-judge
---

# VibeThinker-3B — Bug-Bounty Triage (LoRA adapter)

A LoRA fine-tune of [**WeiboAI/VibeThinker-3B**](https://huggingface.co/WeiboAI/VibeThinker-3B)
that triages bug-bounty / vulnerability-disclosure submissions into a structured
verdict — disposition, severity, confidence, and a rationale — and is hardened
against prompt-injection and AI-generated "slop" reports.

> Project name: **VibeBounty**. This repo hosts the trained **LoRA adapter** (mlx-lm
> format); fuse it onto the base model to get a standalone model.

## What it does

Given a report (title, asset, description, steps, impact), it emits a JSON verdict
over a 9-class disposition taxonomy:

`valid_impactful · valid_low · corroborated_surge · likely_duplicate ·
out_of_scope · theoretical_no_poc · self_inflicted · accepted_risk · slop`

plus a severity estimate, a confidence gated by claim-reliability, and questions
for the researcher.

## Files

| file | purpose |
|------|---------|
| `adapters/adapters.safetensors` | final LoRA adapter (iter 2000, mlx-lm) |
| `adapters/adapter_config.json` | adapter / training config |
| `lora_config.yaml` | full mlx-lm LoRA recipe |

## Usage (Apple Silicon / MLX)

```bash
pip install mlx-lm huggingface_hub
hf download macmacmacmac/vibebounty --local-dir vibebounty

# fuse adapter -> standalone model
mlx_lm.fuse --model WeiboAI/VibeThinker-3B \
  --adapter-path vibebounty/adapters --save-path vibethinker-bbtriage

# generate
mlx_lm.generate --model vibethinker-bbtriage \
  --prompt "Triage this report: IDOR in invoice download ..."
```

Or load the base + adapter directly with mlx-lm without fusing
(`--adapter-path vibebounty/adapters`).

## Usage (in-browser, WebGPU)

VibeThinker-3B is Qwen2.5-3B architecture, so the fused tune converts cleanly to
**MLC `q4f16_1`** and runs in the browser via [WebLLM](https://github.com/mlc-ai/web-llm),
reusing the prebuilt Qwen2.5-3B WASM lib (no compile step). Convert + publish with
[`remote/convert_mlc.sh`](https://github.com/maceip/vibebounty) → an MLC weights repo
(`…-BugBounty-Triage-MLC`). The static console in `docs/` then loads it client-side
on the visitor's GPU — nothing is uploaded.

## Training

- **Base:** WeiboAI/VibeThinker-3B (Qwen2.5-3B lineage)
- **Method:** LoRA (rank 16, scale 20, all 36 layers; q/k/v/o + MLP proj), `mask_prompt`
- **Iters:** 2000, batch 8, seq 2048, lr 1e-4, AdamW
- **Data:** ~18k bug-bounty reports labeled from **real disclosure outcomes**
  (substate / severity / bounty / CVE), rendered as chat with reasoning targets
- **Train loss** 3.4 → <0.7; **val loss** ~1.06

## Sample verdicts

```json
// IDOR: GET /api/v2/invoices/{id} returns other tenants' invoices
{"disposition": "valid_impactful", "severity_estimate": "high",
 "reasoning": "IDOR / broken-authz against an authenticated API; incrementing id
 walks the table -> crosses a real trust boundary with demonstrated impact.",
 "confidence": 0.9}

// Log4Shell report with an EXTERNAL CORROBORATION block (CVE-2021-44228, CISA KEV)
{"disposition": "corroborated_surge", "severity_estimate": "critical",
 "reasoning": "Maps to a publicly disclosed advisory confirmed by the live feed
 (actively exploited) -> corroborated, not spam.",
 "used_external_corroboration": true, "confidence": 0.9}
```

## Evaluation (held-out 300 reports, offline)

| metric | heuristic + defense baseline |
|---|---|
| accept / reject accuracy | **97.0%** |
| disposition accuracy (9-class) | 65.0% |
| macro-F1 / weighted-F1 | 0.194 / 0.580 |
| severity within-1 | 76.3% (MAE 0.90) |
| adversarial defense suite | **12 / 12 pass** |

This is the deterministic **baseline** (rules + defenses, no model) — the bar the
tune must beat. The tuned-model numbers on the same 300 are produced by
`remote/validate_tune.sh 300`, which also reports the share of verdicts the model
actually drove (a model emitting invalid JSON can't hide behind the heuristic).

## Defense layer (model-independent)

Verdicts are guarded by ground-truth checks the model can't talk past:

1. **Prompt-injection isolation** — the report is untrusted data, never instructions.
2. **Claim-level verification** — fabricated code symbols → `slop`; real symbols → supported.
3. **Threat-intel corroboration** — CVE/KEV/OSV match → `corroborated_surge`, never spam.
4. **Confidence gating** — confidence is bounded by a claim-reliability score.
5. **No-PoC calibration** — a report with real repro evidence (steps/request/payload/code/URL) is never `theoretical_no_poc`; it's reclassified by severity.

Offline adversarial suite: **12/12** (6 end-to-end + 6 unit overrides). The same
defenses ship in the browser engine (`docs/engine.mjs`) and are parity-tested with
`node docs/engine.test.mjs`.

## Training data & provenance

~18k bug-bounty / vulnerability-disclosure reports compiled from **publicly
disclosed** sources — primarily disclosed **HackerOne** reports plus additional
public bug-bounty and **Web3** disclosure corpora. Every example's label is
derived from the **real adjudicated outcome** recorded in the data (HackerOne
`substate`, severity, bounty amount, vote count, and any associated CVE) and
mapped onto the 9-class disposition taxonomy — the labels are **not synthetic**.
Each report is rendered as chat **exactly as the inference pipeline renders it**
(system + user report → assistant verdict JSON). Two data-hygiene rules keep the
training signal honest: (1) empty `Steps to reproduce` / `Impact` sections are
**omitted** rather than emitted as blank headers, so a body-only report is never
read as a false "no-PoC" signal; (2) for `corroborated_surge` examples the CVE id
is surfaced into the report text so the corroboration signal is visible to the
model (not metadata-only). When a CVE is present, a live threat-intel corroboration
block is rendered exactly as inference emits it. ~300 reports are held out for eval.

## Academic grounding

The triage flow and its defenses are grounded in recent literature:

- **VibeThinker** (arXiv:2606.16140) — small-model verifiable reasoning; the base model + the claim-level-reliability idea behind confidence gating.
- **From Reviewers' Lens: Bug Bounty Invalid Reasons with LLMs** (arXiv:2511.18608) — predicting *why* a report is invalid; informs the disposition taxonomy + rationale output.
- **Triage in SE: A Systematic Review** (arXiv:2511.08607) — metadata + retrieval beats text-only → we blend report metadata and threat-intel corroboration.
- **CaSey: Streamlining Vulnerability Triage with LLMs** (arXiv:2501.18908) — realistic LLM CWE/severity accuracy; keeps expectations honest.
- **JudgeDeceiver** (arXiv:2403.17710), **Adversarial Attacks on LLM-as-a-Judge** (arXiv:2504.18333), **CUA/JMA** (arXiv:2505.13348), **RobustJudge** (arXiv:2506.09443) — LLM judges (incl. 3B) are injectable → the prompt-injection guard + **model-independent ground-truth overrides**.
- **Stumbling Blocks** (arXiv:2402.11638) + paraphrase-attack results (Krishna et al. 2023; Sadasivan et al.) — AI-text detectors collapse under paraphrase → we **ground via retrieval / claim verification** (fabricated code symbols → `slop`), not detection.

## Intended use & limitations

Decision-support "sidecar" for analysts, not an autonomous adjudicator. It reflects
the biases of the disclosure outcomes it was trained on; always keep a human in the
loop for accept/reject and severity. License inherits from the base model — verify
before redistribution.

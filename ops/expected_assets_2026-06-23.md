# Expected Assets - 2026-06-23 Trace-Aligned Tune

Every item below must be created or explicitly marked missing before the Lambda
instance is terminated.

## Input Assets

- `data/sft/train.jsonl`: original processed SFT train split.
- `data/sft/valid.jsonl`: original processed validation split.
- `data/sft/test.jsonl`: held-out 300-report eval split.
- `data/sft/train_trace_seed.jsonl`: deterministic corrective seed mix.
- `ops/train_trace_seed_manifest.json`: counts, targets, hash, and shortfalls
  for the seed mix.
- `data/sft/train_traces.jsonl`: teacher-generated thinking traces used for
  training.
- `ops/trace_tune_gate_report.json` or `ops/<run_id>_trace_gate.json`: gate
  report proving trace count, class support, `<think>` blocks, no leakage, and
  hash.

## Training Assets

- `adapters/_smoke_trace_today/`: smoke-train adapter proving the trainer path
  works before the full run.
- `adapters/trace-aligned-today/`: final LoRA adapter directory.
- `adapters/trace-aligned-today/adapter_config.json`.
- `adapters/trace-aligned-today/adapter_model.safetensors` or equivalent PEFT
  weight shard.
- `logs/trace_gen_today.log`: trace generation log.
- `logs/trace_tune_today.log`: guarded train/merge log.
- `ops/<run_id>_artifact_manifest.json`: run provenance.

## Model Assets

- `$HOME/models/VibeThinker-3B/`: base model snapshot used for merge.
- `$HOME/models/vibethinker-bbtriage-trace-aligned-today/`: merged Hugging Face
  model directory.
- merged model `config.json`, tokenizer files, and safetensors weight shards.

## Eval Assets

- `eval/report_trace_aligned_today.json`: held-out eval report.
- `eval/report_trace_aligned_today.md`: markdown eval report.
- `eval/scoreboard.jsonl`: append-only comparison row.
- `~/serve_vllm.log`: vLLM server log for the evaluated model.

## Pull-Back Assets

Pull these back to the laptop into a timestamped directory before shutdown:

- `data/sft/train_trace_seed.jsonl`
- `ops/train_trace_seed_manifest.json`
- `data/sft/train_traces.jsonl`
- `ops/*trace_gate*.json`
- `ops/*artifact_manifest*.json`
- `adapters/trace-aligned-today/`
- `eval/report_trace_aligned_today.*`
- `eval/scoreboard.jsonl`
- `logs/trace_gen_today.log`
- `logs/trace_tune_today.log`
- `~/serve_vllm.log`

The fused model can be pulled if there is time and disk room; the LoRA adapter
plus base-model id is sufficient to recreate it.

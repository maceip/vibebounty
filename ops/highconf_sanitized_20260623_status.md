# Highconf Sanitized Tune Status - 2026-06-23

## Outcome

- Remote instance: `ubuntu@192.222.50.29` (GH200).
- Base model: `/home/ubuntu/models/VibeThinker-3B`.
- Final adapter: `/home/ubuntu/bbverifier/adapters/highconf-sanitized-20260623`.
- Final merged model: `/home/ubuntu/models/vibethinker-bbtriage-highconf-sanitized-20260623`.
- Local pullback archive: `mac_pull/highconf_sanitized_20260623/highconf_sanitized_20260623_artifacts_slim.tgz`.
- Local extracted artifacts: `mac_pull/highconf_sanitized_20260623/extracted/`.

## Data Gate

- Source: `data/sft/train_traces_highconf.jsonl`.
- Sanitized output: `data/sft/train_traces_highconf_sanitized.jsonl`.
- Rows: 474 clean rows; 3 malformed final-JSON rows dropped.
- Assistant leakage before: 182 rows.
- Assistant leakage after: 0 rows.
- Sanitized data sha256: `be15104896b32ee8dc7902582eabc50c04aa95adc67e06f0df794e0cf61274ca`.

## Eval60

Fixed parser baseline, same first 60 held-out rows:

- 9-class accuracy: 60.0%.
- accept/reject accuracy: 98.3%.
- macro-F1: 0.247.
- corroborated_surge recall: 0.0%.

Tuned model, uncalibrated, same first 60 held-out rows:

- model_drove_share: 100.0%.
- 9-class accuracy: 43.3%.
- accept/reject accuracy: 75.0%.
- macro-F1: 0.400.
- corroborated_surge recall: 100.0%.

Tuned model plus deterministic PoC-rescue calibration, posthoc on same completed model predictions:

- changed rows: 8.
- 9-class accuracy: 53.3%.
- accept/reject accuracy: 88.3%.
- macro-F1: 0.428.
- corroborated_surge recall: 100.0%.

## Browser Demo

Working local demo path:

1. Keep the Lambda model server running on remote port `8080`.
2. Local SSH tunnel is running as:
   `ssh -i C:\Users\mac\.ssh\id_ed25519 -N -L 18080:127.0.0.1:8080 ubuntu@192.222.50.29`
3. Local docs server is running at `http://127.0.0.1:8767/`.
4. In the gate, choose `Connect a local model`:
   - URL: `http://127.0.0.1:18080/v1`
   - model: `VibeThinker-3B-BugBounty-Triage`

Verified harness:

```powershell
node docs/e2e_local_endpoint.mjs
```

Result: `PASS verdict="Valid · Impactful" engine="engine: VibeThinker-3B-BugBounty-Triage (local)"`.

## WebGPU / MLC Status

Not complete in this run.

- `macmacmacmac/VibeThinker-3B-BugBounty-Triage-MLC` returns 404 even with the provided token.
- No local MLC/WebLLM artifact was found on the laptop or Lambda box.
- The ARM Lambda MLC pip install created placeholder packages but did not provide `mlc_llm`.
- Official MLC docs expect `import mlc_llm` to work after install; this host does not satisfy that.

Next best WebGPU path:

- Run MLC conversion on an x86_64 Linux or Windows machine with a working `mlc_llm` install.
- Source model: `/home/ubuntu/models/vibethinker-bbtriage-highconf-sanitized-20260623`.
- Quantization/config target: `q4f16_1`, `qwen2`, context `8192`, prefill chunk `2048`.
  This replaces the inherited `4096`/`1024` browser target, which was too tight
  for VibeThinker reasoning output and referenced a stale WebLLM wasm URL.
- Then create/upload `macmacmacmac/VibeThinker-3B-BugBounty-Triage-MLC` with `mlc-chat-config.json`, `ndarray-cache.json`, and `params_shard_*.bin`.

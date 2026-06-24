# VibeBounty repo structure

**VibeBounty** is a demo of a **VibeThinker-3B adapter tuned with [emberglass-tune](../emberglass-tune)** for bug-bounty triage, plus the HackerOne-style app surface.

```
~/emberglass/          ← WebGPU inference (browser)
~/emberglass-tune/     ← train + MLX/CUDA eval
~/vibebounty/          ← this repo (demo + domain data + serve)
```

## In this repo

| Path | Purpose |
|---|---|
| `app/` | FastAPI live console + defense layer |
| `docs/` | HackerOne-style static demo |
| `feeds/` | Threat-intel corroboration (KEV/OSV/NVD) |
| `eval/` | Held-out triage metrics + adversarial suite |
| `data/sft/` | Bug-bounty labeled JSONL + traces |
| `configs/bugbounty_lora.yaml` | MLX LoRA hyperparams for this product |
| `remote/serve_vibethinker.py` | OpenAI-compatible **serve** for demos |
| `scripts/serve_local.ps1` | Windows local demo server |
| `scripts/train_gpu_bugbounty.sh` | Calls `emberglass-tune` on VibeBounty data |

## Train

```bash
cd ~/vibebounty
pip install -r requirements-train.txt    # installs ~/emberglass-tune
emberglass-tune traces --in data/sft/train.jsonl --out data/sft/train_traces.jsonl
bash scripts/train_gpu_bugbounty.sh
```

## Demo

```powershell
powershell -File scripts/serve_local.ps1
cd docs; python -m http.server 8767 --bind 127.0.0.1
# Connect → http://127.0.0.1:8080/v1  model: VibeThinker-3B-BugBounty-Triage
```

## Related

- [emberglass-tune](../emberglass-tune) — training
- [emberglass](../emberglass) — WebGPU inference

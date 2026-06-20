#!/usr/bin/env python3
"""Step 2c: generate synthetic bug bounty submissions to scale the dataset.

Talks to any OpenAI-compatible endpoint (mlx_lm.server, vLLM, Ollama,
llama.cpp server). Use a STRONG model here (a big general model gives more
realistic submissions) - this is data generation, not the triage model.

Example:
  python synthesize.py --n-per-class 20 \
    --base-url http://localhost:8080/v1 --model gpt-4o-ish \
    --out data/synthetic.jsonl
"""
import argparse
import json
import pathlib
import re
import sys

from openai import OpenAI

DISPOSITIONS = [
    "valid_impactful",
    "valid_low",
    "likely_duplicate",
    "out_of_scope",
    "theoretical_no_poc",
    "self_inflicted",
    "accepted_risk",
    "slop",
]

HERE = pathlib.Path(__file__).parent
SYNTH_SYSTEM = (HERE / "prompts" / "synthesis_system.txt").read_text(encoding="utf-8")


def extract_json(text: str):
    """Return the last balanced {...} object in text, parsed."""
    depth = 0
    start = None
    candidate = None
    for i, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start is not None:
                candidate = text[start : i + 1]
    if candidate is None:
        raise ValueError("no JSON object found")
    return json.loads(candidate)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default="http://localhost:8080/v1")
    ap.add_argument("--api-key", default="not-needed")
    ap.add_argument("--model", required=True)
    ap.add_argument("--n-per-class", type=int, default=10)
    ap.add_argument("--temperature", type=float, default=1.0)
    ap.add_argument("--out", default=str(HERE / "data" / "synthetic.jsonl"))
    args = ap.parse_args()

    client = OpenAI(base_url=args.base_url, api_key=args.api_key)
    out_path = pathlib.Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    written = 0
    with out_path.open("w", encoding="utf-8") as f:
        for disp in DISPOSITIONS:
            for k in range(args.n_per_class):
                user = (
                    f"TARGET DISPOSITION: {disp}\n"
                    f"Generate submission #{k + 1}. Make it distinct from typical "
                    f"examples; vary product type, asset, vuln class, and reporter voice."
                )
                try:
                    resp = client.chat.completions.create(
                        model=args.model,
                        temperature=args.temperature,
                        messages=[
                            {"role": "system", "content": SYNTH_SYSTEM},
                            {"role": "user", "content": user},
                        ],
                    )
                    obj = extract_json(resp.choices[0].message.content)
                    obj.setdefault("label", {})["disposition"] = disp
                    obj["id"] = f"synth-{disp}-{k + 1:03d}"
                    f.write(json.dumps(obj, ensure_ascii=False) + "\n")
                    f.flush()
                    written += 1
                    print(f"[ok] {obj['id']}", file=sys.stderr)
                except Exception as e:  # noqa: BLE001
                    print(f"[skip] {disp} #{k + 1}: {e}", file=sys.stderr)

    print(f"Wrote {written} synthetic examples to {out_path}")


if __name__ == "__main__":
    main()

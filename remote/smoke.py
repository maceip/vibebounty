"""Prove the tuned model asset works: load it and triage held-out test reports.

Run on the Mac:
    cd ~/bbverifier && .venv/bin/python smoke.py [MODEL_DIR] [N]
"""
import json
import sys
from pathlib import Path

from mlx_lm import generate, load

MODEL = sys.argv[1] if len(sys.argv) > 1 else "vibethinker-bbtriage"
N = int(sys.argv[2]) if len(sys.argv) > 2 else 5

ROOT = Path(__file__).resolve().parent
TEST = ROOT / "data" / "sft" / "test.jsonl"


def gold_disposition(assistant_content: str) -> str:
    line = assistant_content.strip().splitlines()[-1]
    try:
        return json.loads(line).get("disposition", "?")
    except Exception:  # noqa: BLE001
        return "?"


def main() -> None:
    model, tok = load(MODEL)
    rows = [json.loads(l) for l in TEST.read_text(encoding="utf-8").splitlines()[:N]]
    correct = 0
    for i, row in enumerate(rows):
        msgs = row["messages"]
        gold = gold_disposition(msgs[-1]["content"])
        prompt = tok.apply_chat_template(msgs[:-1], add_generation_prompt=True)
        out = generate(model, tok, prompt=prompt, max_tokens=400, verbose=False)
        pred = "?"
        for line in reversed(out.strip().splitlines()):
            line = line.strip()
            if line.startswith("{") and line.endswith("}"):
                try:
                    pred = json.loads(line).get("disposition", "?")
                    break
                except Exception:  # noqa: BLE001
                    pass
        correct += int(pred == gold)
        print(f"\n===== test {i} =====")
        print(f"GOLD: {gold}   PRED: {pred}   {'OK' if pred == gold else 'x'}")
        print(out.strip()[-600:])
    print(f"\n[smoke] disposition match: {correct}/{len(rows)}")


if __name__ == "__main__":
    main()

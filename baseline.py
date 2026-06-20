#!/usr/bin/env python3
"""Step 3: baseline the triage model against labeled examples.

Runs each submission through VibeThinker-3B (or any OpenAI-compatible endpoint)
using the triage prompt, parses the JSON verdict, and scores disposition
accuracy plus a confusion breakdown. No fine-tuning required - this tells you
how good the model is zero-shot and gives you a number to beat.

Serve VibeThinker locally first, e.g.:
  mlx_lm.server --model WeiboAI/VibeThinker-3B --port 8080
then:
  python baseline.py --base-url http://localhost:8080/v1 --model WeiboAI/VibeThinker-3B
"""
import argparse
import collections
import json
import pathlib
import sys

from openai import OpenAI

HERE = pathlib.Path(__file__).parent
TRIAGE_SYSTEM = (HERE / "prompts" / "triage_system.txt").read_text(encoding="utf-8")

try:
    from feeds.enrich import enrich, format_for_prompt
except Exception:  # noqa: BLE001 - enrichment is optional
    enrich = None
    format_for_prompt = None

# Group dispositions into accept/reject to also report a coarse, decision-level
# accuracy (often what actually matters operationally).
ACCEPT = {"valid_impactful", "valid_low"}


def extract_json(text: str):
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


def render_submission(sub: dict, corroboration_block: str = None) -> str:
    text = (
        f"Title: {sub.get('title','')}\n"
        f"Claimed severity: {sub.get('severity_claimed','')}\n"
        f"Asset: {sub.get('asset','')}\n\n"
        f"Description:\n{sub.get('description','')}\n\n"
        f"Steps to reproduce:\n{sub.get('steps_to_reproduce','')}\n\n"
        f"Impact:\n{sub.get('impact','')}\n"
    )
    if corroboration_block:
        text += f"\n---\n{corroboration_block}\n"
    return text


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default="http://localhost:8080/v1")
    ap.add_argument("--api-key", default="not-needed")
    ap.add_argument("--model", default="WeiboAI/VibeThinker-3B")
    ap.add_argument("--data", default=str(HERE / "data" / "seed_examples.jsonl"))
    ap.add_argument("--temperature", type=float, default=1.0)
    ap.add_argument("--top-p", type=float, default=0.95)
    ap.add_argument("--max-tokens", type=int, default=40000)
    ap.add_argument("--enrich", action="store_true",
                    help="Inject EXTERNAL CORROBORATION from feeds/enrich.py.")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    if args.enrich and enrich is None:
        print("[warn] --enrich requested but feeds.enrich could not be imported; "
              "run from the bb-triage/ directory.", file=sys.stderr)

    client = OpenAI(base_url=args.base_url, api_key=args.api_key)
    rows = [
        json.loads(line)
        for line in pathlib.Path(args.data).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    correct = 0
    coarse_correct = 0
    scored = 0
    errors = 0
    confusion = collections.Counter()  # (gold, pred)

    for row in rows:
        gold = row["label"]["disposition"]
        corr_block = None
        if args.enrich and enrich is not None:
            corr_block = format_for_prompt(
                row.get("external_corroboration") or enrich(row["submission"])
            )
        prompt = render_submission(row["submission"], corr_block)
        try:
            resp = client.chat.completions.create(
                model=args.model,
                temperature=args.temperature,
                top_p=args.top_p,
                max_tokens=args.max_tokens,
                messages=[
                    {"role": "system", "content": TRIAGE_SYSTEM},
                    {"role": "user", "content": prompt},
                ],
            )
            verdict = extract_json(resp.choices[0].message.content)
            pred = verdict.get("disposition", "PARSE_FAIL")
        except Exception as e:  # noqa: BLE001
            errors += 1
            pred = "PARSE_FAIL"
            if args.verbose:
                print(f"[err] {row['id']}: {e}", file=sys.stderr)

        scored += 1
        confusion[(gold, pred)] += 1
        if pred == gold:
            correct += 1
        if (pred in ACCEPT) == (gold in ACCEPT) and pred != "PARSE_FAIL":
            coarse_correct += 1
        mark = "OK " if pred == gold else "XX "
        print(f"{mark}{row['id']:<10} gold={gold:<18} pred={pred}")

    print("\n=== Summary ===")
    print(f"examples:            {scored}")
    print(f"exact disposition:   {correct}/{scored} = {correct / scored:.1%}")
    print(f"accept/reject coarse:{coarse_correct}/{scored} = {coarse_correct / scored:.1%}")
    print(f"parse/api errors:    {errors}")

    print("\n=== Confusion (gold -> pred), mismatches only ===")
    for (gold, pred), n in sorted(confusion.items()):
        if gold != pred:
            print(f"  {gold:<18} -> {pred:<18} x{n}")


if __name__ == "__main__":
    main()

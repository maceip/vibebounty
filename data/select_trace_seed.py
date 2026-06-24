#!/usr/bin/env python3
"""Select a deterministic trace-generation seed set from the SFT train split.

The prior tune over-predicted the majority `valid_low` class. This selector
builds a deliberately corrective seed mix for teacher trace generation:
enough valid_low examples to preserve calibration, but extra support for the
classes the old model missed on held-out eval.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
from collections import Counter, defaultdict
from pathlib import Path

DEFAULT_TARGETS = {
    "valid_low": 350,
    "valid_impactful": 450,
    "corroborated_surge": 350,
    "likely_duplicate": 150,
    "out_of_scope": 150,
    "slop": 50,
}


def extract_json(text: str) -> dict:
    depth = 0
    start = None
    cand = None
    for i, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start is not None:
                cand = text[start : i + 1]
    return json.loads(cand) if cand else {}


def disposition(row: dict) -> str:
    for msg in row.get("messages", []):
        if msg.get("role") == "assistant":
            return str(extract_json(msg.get("content", "")).get("disposition", ""))
    return ""


def user_hash(row: dict) -> str:
    user = next((m.get("content", "") for m in row.get("messages", []) if m.get("role") == "user"), "")
    return hashlib.sha1(user.encode("utf-8")).hexdigest()


def parse_targets(raw: str) -> dict[str, int]:
    if not raw:
        return dict(DEFAULT_TARGETS)
    out: dict[str, int] = {}
    for part in raw.split(","):
        if not part.strip():
            continue
        key, val = part.split("=", 1)
        out[key.strip()] = int(val)
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", default="data/sft/train.jsonl")
    ap.add_argument("--out", dest="out", default="data/sft/train_trace_seed.jsonl")
    ap.add_argument("--manifest", default="ops/train_trace_seed_manifest.json")
    ap.add_argument("--seed", type=int, default=13)
    ap.add_argument(
        "--targets",
        default="",
        help="comma list like valid_low=350,valid_impactful=450; defaults are corrective for old eval collapse",
    )
    args = ap.parse_args()

    src = Path(args.inp)
    out = Path(args.out)
    manifest = Path(args.manifest)
    targets = parse_targets(args.targets)
    rng = random.Random(args.seed)

    by_class: dict[str, list[dict]] = defaultdict(list)
    malformed = 0
    duplicates = 0
    seen_users: set[str] = set()

    for line in src.read_text(encoding="utf-8").split("\n"):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
            disp = disposition(row)
        except Exception:
            malformed += 1
            continue
        if not disp:
            malformed += 1
            continue
        h = user_hash(row)
        if h in seen_users:
            duplicates += 1
            continue
        seen_users.add(h)
        by_class[disp].append(row)

    selected: list[dict] = []
    available = {k: len(v) for k, v in sorted(by_class.items())}
    selected_counts: Counter[str] = Counter()
    shortfalls: dict[str, dict[str, int]] = {}

    for disp, target in targets.items():
        rows = list(by_class.get(disp, []))
        rng.shuffle(rows)
        take = min(target, len(rows))
        selected.extend(rows[:take])
        selected_counts[disp] += take
        if take < target:
            shortfalls[disp] = {"target": target, "selected": take, "available": len(rows)}

    rng.shuffle(selected)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as f:
        for row in selected:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    sha = hashlib.sha256(out.read_bytes()).hexdigest()
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(
        json.dumps(
            {
                "source": str(src),
                "output": str(out),
                "sha256": sha,
                "seed": args.seed,
                "targets": targets,
                "available_counts": available,
                "selected_counts": dict(selected_counts),
                "selected_total": len(selected),
                "malformed_skipped": malformed,
                "duplicate_user_rows_skipped": duplicates,
                "shortfalls": shortfalls,
                "purpose": (
                    "Correct the prior tune's valid_low collapse by generating long "
                    "teacher traces for valid_impactful, corroborated_surge, duplicate, "
                    "and out_of_scope examples while retaining valid_low calibration."
                ),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    print(f"wrote {out} ({len(selected)} rows, sha256={sha})")
    print(json.dumps(dict(selected_counts), indent=2, sort_keys=True))
    if shortfalls:
        print("[warn] target shortfalls: " + json.dumps(shortfalls, sort_keys=True))


if __name__ == "__main__":
    main()

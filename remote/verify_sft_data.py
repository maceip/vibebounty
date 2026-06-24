#!/usr/bin/env python3
"""Preflight check: tokenize trace JSONL without loading the model onto GPU.

Exit 0 if enough usable training examples exist; exit 1 otherwise.
"""
import argparse
import json
import sys
from pathlib import Path

from transformers import AutoTokenizer

IGNORE = -100


def read_jsonl(path):
    rows = []
    for ln in Path(path).read_text(encoding="utf-8").split("\n"):
        ln = ln.strip()
        if ln:
            try:
                rows.append(json.loads(ln))
            except json.JSONDecodeError:
                pass
    return rows


def shrink_user(msgs, user_idx, fraction=0.85):
    content = msgs[user_idx]["content"]
    if len(content) < 400:
        return False
    keep = max(400, int(len(content) * fraction))
    msgs[user_idx]["content"] = content[:keep] + "\n...[truncated for length]...\n"
    return True


def tokenize_one(msgs, tok, max_len):
    """Return (full_ids, labels) or None if unusable."""
    msgs = [dict(m) for m in msgs]
    user_idx = next((i for i, m in enumerate(msgs) if m["role"] == "user"), None)
    if user_idx is None:
        return None

    for _ in range(24):
        full_text = tok.apply_chat_template(
            msgs, tokenize=False, add_generation_prompt=False,
        )
        full_ids = tok.encode(full_text, add_special_tokens=False)
        if len(full_ids) <= max_len:
            break
        if not shrink_user(msgs, user_idx):
            break

    prompt_text = tok.apply_chat_template(
        msgs[:-1], tokenize=False, add_generation_prompt=True,
    )
    full_text = tok.apply_chat_template(
        msgs, tokenize=False, add_generation_prompt=False,
    )
    prompt_ids = tok.encode(prompt_text, add_special_tokens=False)
    full_ids = tok.encode(full_text, add_special_tokens=False)

    assistant_start = len(prompt_ids)
    if len(full_ids) > max_len:
        assistant_ids = full_ids[assistant_start:]
        if not assistant_ids:
            return None
        if len(assistant_ids) >= max_len:
            assistant_ids = assistant_ids[-(max_len - 512):]
            prompt_ids = full_ids[: min(512, assistant_start)]
        else:
            room = max_len - len(assistant_ids)
            prompt_ids = full_ids[:assistant_start][-room:]
        full_ids = prompt_ids + assistant_ids
        assistant_start = len(prompt_ids)

    labels = list(full_ids)
    for i in range(min(assistant_start, len(labels))):
        labels[i] = IGNORE
    trainable = sum(1 for x in labels if x != IGNORE)
    if trainable < 32:
        return None
    return full_ids, labels, trainable


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--data", required=True)
    ap.add_argument("--max-len", type=int, default=8192)
    ap.add_argument("--min-usable", type=int, default=100)
    ap.add_argument("--sample", type=int, default=0, help="0 = all rows")
    args = ap.parse_args()

    rows = read_jsonl(args.data)
    if args.sample:
        rows = rows[: args.sample]
    if not rows:
        print("[verify] FATAL: no rows in data file", flush=True)
        sys.exit(1)

    tok = AutoTokenizer.from_pretrained(args.model, trust_remote_code=True)
    usable = 0
    trainable_tokens = []
    lengths = []
    failures = {"no_user": 0, "no_trainable": 0}

    for r in rows:
        msgs = r.get("messages")
        if not msgs:
            failures["no_user"] += 1
            continue
        out = tokenize_one(msgs, tok, args.max_len)
        if out is None:
            failures["no_trainable"] += 1
            continue
        full_ids, labels, n_train = out
        usable += 1
        trainable_tokens.append(n_train)
        lengths.append(len(full_ids))

    print(f"[verify] rows={len(rows)} usable={usable} dropped={len(rows)-usable}", flush=True)
    print(f"[verify] failures={failures}", flush=True)
    if usable:
        print(
            f"[verify] seq_len avg={sum(lengths)/len(lengths):.0f} "
            f"max={max(lengths)} trainable_tok avg={sum(trainable_tokens)/len(trainable_tokens):.0f}",
            flush=True,
        )

    if usable < args.min_usable:
        print(
            f"[verify] FATAL: need >={args.min_usable} usable examples, got {usable}",
            flush=True,
        )
        sys.exit(1)

    print("[verify] OK", flush=True)


if __name__ == "__main__":
    main()

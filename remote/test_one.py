#!/usr/bin/env python3
"""Test the SERVED model one report at a time. NO heuristic fallback.

Sends each held-out report (exact training message shape: system+user) to the
local mlx_lm server and inspects the LITERAL response: finish_reason, completion
tokens, message.content AND message.reasoning. Tries to parse a JSON verdict
from content first, then reasoning. Stops after NEED clean successes.

  MAXTOK=3072 NEED=5 MODEL_BASE_URL=http://localhost:8080/v1 \
    DATA=~/bbverifier/data/sft/test.jsonl python remote/test_one.py
"""
import json
import os
import pathlib
import urllib.request

BASE = os.environ.get("MODEL_BASE_URL", "http://localhost:8080/v1").rstrip("/")
MODEL = os.environ.get("MODEL_NAME", "WeiboAI/VibeThinker-3B")
MAXTOK = int(os.environ.get("MAXTOK", "3072"))
NEED = int(os.environ.get("NEED", "5"))
DATA = os.path.expanduser(os.environ.get("DATA", "~/bbverifier/data/sft/test.jsonl"))


def extract_json(text):
    depth, start, cand = 0, None, None
    for i, ch in enumerate(text or ""):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start is not None:
                cand = text[start:i + 1]
    if cand is None:
        raise ValueError("no json object")
    return json.loads(cand)


def post(messages):
    body = {"model": MODEL, "messages": messages, "max_tokens": MAXTOK, "temperature": 0}
    req = urllib.request.Request(BASE + "/chat/completions",
                                 data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=600) as r:
        return json.loads(r.read())


def main():
    rows = [json.loads(l) for l in pathlib.Path(DATA).read_text(encoding="utf-8").split("\n") if l.strip()]
    print(f"server={BASE} model={MODEL} maxtok={MAXTOK} need={NEED} data={DATA} rows={len(rows)}")
    succ = att = 0
    for row in rows:
        if succ >= NEED:
            break
        att += 1
        msgs = [m for m in row["messages"] if m["role"] in ("system", "user")]
        o = post(msgs)
        ch = o["choices"][0]
        msg = ch.get("message", {}) or {}
        content = msg.get("content")
        reasoning = msg.get("reasoning")
        fr = ch.get("finish_reason")
        usage = o.get("usage", {})
        parsed, src = None, None
        for name, txt in (("content", content), ("reasoning", reasoning)):
            if txt:
                try:
                    parsed = extract_json(txt)
                    src = name
                    break
                except Exception:  # noqa: BLE001
                    pass
        ok = bool(parsed and parsed.get("disposition"))
        succ += int(ok)
        print(f"\n--- attempt {att} | finish={fr} | comp_tokens={usage.get('completion_tokens')} "
              f"| msg_keys={list(msg.keys())} | parse={'OK from ' + src if ok else 'FAIL'} ---")
        print("content repr:", repr(content)[:220])
        if not content and reasoning:
            print("reasoning tail:", repr(reasoning[-280:]))
        if ok:
            print("VERDICT:", json.dumps(parsed, ensure_ascii=False)[:400])
    print(f"\n==== successes {succ}/{att} (needed {NEED}) ====")


if __name__ == "__main__":
    main()

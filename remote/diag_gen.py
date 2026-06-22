#!/usr/bin/env python3
"""Diagnose why the served (base+adapter) model returns zero-length output.

Hits the local mlx_lm server directly (urllib, no openai client) and dumps the
FULL response for several cases so we can localize the fault:

  1. trivial chat, greedy            (is generation empty for ANY prompt?)
  2. trivial chat, temp=0.7          (is it greedy degeneracy?)
  3. raw /v1/completions, greedy     (bypass the chat template entirely)
  4. real triage chat, greedy        (the production prompt)

  BASE=http://localhost:8080/v1 python remote/diag_gen.py
"""
import json
import os
import sys
import urllib.request

BASE = os.environ.get("BASE", "http://localhost:8080/v1").rstrip("/")
MODEL = os.environ.get("MODEL_NAME", "WeiboAI/VibeThinker-3B")


def post(path, body):
    req = urllib.request.Request(BASE + path, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=180) as r:
        return json.loads(r.read())


def show(tag, o):
    print(f"\n================ {tag} ================")
    try:
        ch = o["choices"][0]
        msg = ch.get("message", {})
        txt = msg.get("content", ch.get("text"))
        print("finish_reason:", ch.get("finish_reason"))
        print("usage        :", o.get("usage"))
        print("message keys :", list(msg.keys()) if msg else "(no message; completions)")
        print("content repr :", repr(txt)[:600])
        # surface any non-standard fields that might hold the text
        for k in ("reasoning_content", "reasoning", "thinking"):
            if isinstance(msg, dict) and k in msg:
                print(f"** {k} repr :", repr(msg[k])[:600])
    except Exception as e:  # noqa: BLE001
        print("PARSE OF RESPONSE FAILED:", e)
        print(json.dumps(o, indent=1)[:1500])


def main():
    print(f"server: {BASE}  model: {MODEL}")
    try:
        show("1. trivial chat greedy", post("/chat/completions", {
            "model": MODEL, "max_tokens": 48, "temperature": 0,
            "messages": [{"role": "user", "content": "Say hello."}]}))
    except Exception as e:  # noqa: BLE001
        print("case1 error:", e)
    try:
        show("2. trivial chat temp=0.7", post("/chat/completions", {
            "model": MODEL, "max_tokens": 48, "temperature": 0.7, "top_p": 0.9,
            "messages": [{"role": "user", "content": "Say hello."}]}))
    except Exception as e:  # noqa: BLE001
        print("case2 error:", e)
    try:
        show("3. raw completions greedy (no chat template)", post("/completions", {
            "model": MODEL, "max_tokens": 48, "temperature": 0,
            "prompt": "The capital of France is"}))
    except Exception as e:  # noqa: BLE001
        print("case3 error:", e)
    try:
        sub = ("Title: IDOR in invoices\nClaimed severity: High\nAsset: api.x.com\n\n"
               "Description:\nGET /api/v1/invoices/{id} returns other tenants' invoices.\n\n"
               "Steps to reproduce:\n\n\nImpact:\n\n\n---\n"
               "EXTERNAL CORROBORATION: none found (no matching CVE/advisory/package).\n")
        show("4. triage chat greedy", post("/chat/completions", {
            "model": MODEL, "max_tokens": 256, "temperature": 0,
            "messages": [
                {"role": "system", "content": "You are a bug bounty triage analyst. Output a single JSON object with key disposition."},
                {"role": "user", "content": sub}]}))
    except Exception as e:  # noqa: BLE001
        print("case4 error:", e)


if __name__ == "__main__":
    main()

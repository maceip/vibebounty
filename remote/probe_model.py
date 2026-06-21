#!/usr/bin/env python3
"""Isolated single-request probe of the SERVED tuned model. No eval harness.

Sends ONE triage prompt (exact production system prompt + GUARD + rendered
report) to the local mlx_lm server and prints:
  - latency, output length, and finish_reason  (length => CoT got truncated)
  - the RAW model output verbatim
  - whether app.triage._extract_json() can recover a JSON verdict

Goal: prove the model itself responds with a parseable verdict before any eval.

  MAXTOK=3072 python remote/probe_model.py
"""
import json
import os
import pathlib
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("MODEL_BASE_URL", "http://localhost:8080/v1")

from feeds.enrich import enrich, format_for_prompt  # noqa: E402
from app import triage  # noqa: E402
from openai import OpenAI  # noqa: E402

SUB = {
    "title": "IDOR in invoice download",
    "severity_claimed": "High",
    "asset": "api.acme.com",
    "description": "GET /api/v2/invoices/{id} returns other tenants' invoices; "
                   "incrementing the id walks the whole table.",
    "steps_to_reproduce": "Authenticated as user 1001, GET /api/v2/invoices/1002 "
                          "returns user 1002's invoice.",
    "impact": "Cross-tenant disclosure of financial documents.",
}

corr = enrich(SUB, use_osv=False)
user_msg = triage._render(SUB, format_for_prompt(corr))
maxtok = int(os.environ.get("MAXTOK", "3072"))

client = OpenAI(base_url=os.environ["MODEL_BASE_URL"], api_key="x", timeout=300)
print(f"== probing {os.environ['MODEL_BASE_URL']}  max_tokens={maxtok} greedy ==")
t = time.time()
resp = client.chat.completions.create(
    model=os.environ.get("MODEL_NAME", "WeiboAI/VibeThinker-3B"),
    temperature=0, top_p=1.0, max_tokens=maxtok,
    messages=[
        {"role": "system", "content": triage.TRIAGE_SYSTEM + triage.GUARD},
        {"role": "user", "content": user_msg},
    ],
)
dt = time.time() - t
choice = resp.choices[0]
txt = choice.message.content or ""
print(f"== latency {dt:.1f}s   output {len(txt)} chars   finish_reason={choice.finish_reason}")
print("================ RAW OUTPUT START ================")
print(txt)
print("================ RAW OUTPUT END ==================")
try:
    v = triage._extract_json(txt)
    print("PARSE: OK ->", json.dumps(v, ensure_ascii=False))
except Exception as e:  # noqa: BLE001
    print(f"PARSE: FAILED -> {type(e).__name__}: {e}")
    if choice.finish_reason == "length":
        print("DIAGNOSIS: hit token cap mid-reasoning; never emitted the JSON. "
              "Raise MAXTOK or constrain the prompt to answer sooner.")

#!/usr/bin/env python3
import json, sys
from pathlib import Path
from transformers import AutoTokenizer
model, path = sys.argv[1], sys.argv[2]
row = json.loads(Path(path).read_text(encoding="utf-8").splitlines()[0])
msgs = row["messages"]
tok = AutoTokenizer.from_pretrained(model, trust_remote_code=True)
print("has_chat_template:", bool(getattr(tok, "chat_template", None)))
prompt_ids = tok.apply_chat_template(msgs[:-1], tokenize=True, add_generation_prompt=True)
full_ids = tok.apply_chat_template(msgs, tokenize=True, add_generation_prompt=False)
print("prompt_ids:", len(prompt_ids), "full_ids:", len(full_ids), "delta:", len(full_ids)-len(prompt_ids))
asst = next(m["content"] for m in msgs if m["role"]=="assistant")
print("assistant_chars:", len(asst), "assistant_tokens:", len(tok.encode(asst, add_special_tokens=False)))

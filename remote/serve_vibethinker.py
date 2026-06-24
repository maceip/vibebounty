#!/usr/bin/env python3
"""Minimal OpenAI-compatible chat server for VibeThinker (transformers; CUDA or CPU)."""
import argparse
import os
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout

import torch
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from transformers import AutoModelForCausalLM, AutoTokenizer, StoppingCriteria, StoppingCriteriaList

# Hard cap — must match remote/constants.sh TRIAGE_MAX_TOKENS / SERVE_MAX_NEW_TOKENS.
MAX_NEW_CAP = int(os.environ.get("SERVE_MAX_NEW_TOKENS", "4096"))
GEN_TIMEOUT = float(os.environ.get("SERVE_GEN_TIMEOUT", "240"))

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
MODEL = None
TOK = None
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"
DTYPE = torch.bfloat16 if DEVICE == "cuda" else torch.float32
SERVED_NAME = os.environ.get("SERVE_MODEL_NAME") or os.environ.get("MODEL_NAME") or "VibeThinker-3B-BugBounty-Triage"


class ChatReq(BaseModel):
    model: str = SERVED_NAME
    messages: list
    max_tokens: int = Field(default=4096, le=4096)
    temperature: float = 0.0
    top_p: float = 1.0


def _generate(inputs, gen_kw):
    with torch.no_grad():
        return MODEL.generate(**inputs, **gen_kw)


def _has_complete_json(text: str) -> bool:
    depth = 0
    start = None
    in_str = False
    esc = False
    for i, ch in enumerate(text):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            if depth:
                depth -= 1
                if depth == 0 and start is not None:
                    return True
    return False


class StopAfterVerdictJson(StoppingCriteria):
    def __init__(self, tok, prompt_len: int, min_new_tokens: int = 48):
        self.tok = tok
        self.prompt_len = prompt_len
        self.min_new_tokens = min_new_tokens

    def __call__(self, input_ids, scores, **kwargs) -> bool:
        new_ids = input_ids[0][self.prompt_len:]
        if new_ids.numel() < self.min_new_tokens:
            return False
        text = self.tok.decode(new_ids, skip_special_tokens=False)
        if "</think>" not in text:
            return False
        return _has_complete_json(text.split("</think>", 1)[1])


@app.post("/v1/chat/completions")
def chat(req: ChatReq):
    text = TOK.apply_chat_template(
        req.messages, tokenize=False, add_generation_prompt=True,
    )
    inputs = TOK(text, return_tensors="pt").to(DEVICE)
    new_budget = min(int(req.max_tokens), MAX_NEW_CAP)
    gen_kw = dict(
        max_new_tokens=new_budget,
        do_sample=req.temperature > 0,
        pad_token_id=TOK.pad_token_id or TOK.eos_token_id,
        stopping_criteria=StoppingCriteriaList([
            StopAfterVerdictJson(TOK, inputs["input_ids"].shape[1]),
        ]),
    )
    if req.temperature > 0:
        gen_kw["temperature"] = req.temperature
        gen_kw["top_p"] = req.top_p
    t0 = time.time()
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            fut = pool.submit(_generate, inputs, gen_kw)
            out = fut.result(timeout=GEN_TIMEOUT)
    except FuturesTimeout:
        raise HTTPException(
            status_code=504,
            detail=f"generation exceeded {GEN_TIMEOUT}s (max_new_tokens={new_budget})",
        )
    new = out[0][inputs["input_ids"].shape[1]:]
    content = TOK.decode(new, skip_special_tokens=False)
    return {
        "id": f"chatcmpl-{uuid.uuid4().hex[:12]}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": req.model,
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": content, "reasoning": content},
            "finish_reason": "stop",
        }],
        "usage": {
            "prompt_tokens": inputs["input_ids"].shape[1],
            "completion_tokens": len(new),
            "wall_seconds": round(time.time() - t0, 2),
        },
    }


@app.get("/v1/models")
def models():
    return {"data": [{"id": SERVED_NAME, "object": "model"}]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True, help="Base or merged HF model directory")
    ap.add_argument("--adapter", help="Optional PEFT LoRA adapter directory")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args()
    global MODEL, TOK, DEVICE, DTYPE
    if os.environ.get("SERVE_DEVICE"):
        DEVICE = os.environ["SERVE_DEVICE"]
        DTYPE = torch.bfloat16 if DEVICE == "cuda" else torch.float32
    TOK = AutoTokenizer.from_pretrained(args.model, trust_remote_code=True)
    if TOK.pad_token is None:
        TOK.pad_token = TOK.eos_token
    MODEL = AutoModelForCausalLM.from_pretrained(
        args.model, torch_dtype=DTYPE, trust_remote_code=True,
        attn_implementation="sdpa" if DEVICE == "cuda" else "eager",
        low_cpu_mem_usage=True,
    )
    if args.adapter:
        from peft import PeftModel
        MODEL = PeftModel.from_pretrained(MODEL, args.adapter)
        MODEL = MODEL.merge_and_unload()
    MODEL = MODEL.to(DEVICE)
    MODEL.eval()
    where = f"{args.model}" + (f" + adapter {args.adapter}" if args.adapter else "")
    print(f"[serve] loaded {where} as {SERVED_NAME} on {DEVICE} cap={MAX_NEW_CAP} timeout={GEN_TIMEOUT}s", flush=True)
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()

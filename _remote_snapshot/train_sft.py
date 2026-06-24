#!/usr/bin/env python3
"""Phase-1 cold-start SFT: LoRA fine-tune VibeThinker-3B on faithful reasoning traces."""
import argparse
import json
import sys
from pathlib import Path

from datasets import Dataset
from peft import LoraConfig, get_peft_model
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    DataCollatorForSeq2Seq,
    Trainer,
    TrainingArguments,
)

IGNORE = -100


def read_jsonl(path):
    rows = []
    for ln in Path(path).read_text(encoding="utf-8").splitlines():
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


def build_examples(rows, tok, max_len):
    """Tokenize conversations; mask prompt tokens; preserve assistant tail on truncation."""
    keep = []
    dropped = {"no_user": 0, "no_trainable": 0}

    for r in rows:
        msgs = [dict(m) for m in r["messages"]]
        user_idx = next((i for i, m in enumerate(msgs) if m["role"] == "user"), None)
        if user_idx is None:
            dropped["no_user"] += 1
            continue

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
                dropped["no_trainable"] += 1
                continue
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
            dropped["no_trainable"] += 1
            continue

        keep.append({
            "input_ids": full_ids,
            "labels": labels,
            "attention_mask": [1] * len(full_ids),
        })

    return keep, dropped


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--data", required=True)
    ap.add_argument("--valid", default="")
    ap.add_argument("--out", required=True)
    ap.add_argument("--max-len", type=int, default=8192)
    ap.add_argument("--epochs", type=float, default=3.0)
    ap.add_argument("--max-steps", type=int, default=-1)
    ap.add_argument("--bs", type=int, default=4)
    ap.add_argument("--grad-accum", type=int, default=8)
    ap.add_argument("--lr", type=float, default=1e-4)
    ap.add_argument("--warmup-ratio", type=float, default=0.03)
    ap.add_argument("--lora-r", type=int, default=32)
    ap.add_argument("--lora-alpha", type=int, default=64)
    ap.add_argument("--lora-dropout", type=float, default=0.05)
    ap.add_argument("--valid-frac", type=float, default=0.04)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--save-steps", type=int, default=200)
    ap.add_argument("--seed", type=int, default=13)
    args = ap.parse_args()

    tok = AutoTokenizer.from_pretrained(args.model, trust_remote_code=True)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token

    rows = read_jsonl(args.data)
    if args.limit:
        rows = rows[: args.limit]
    print(f"[sft] loaded {len(rows)} trace rows", flush=True)

    examples, dropped = build_examples(rows, tok, args.max_len)
    print(
        f"[sft] tokenized {len(examples)} usable examples "
        f"(dropped {len(rows)-len(examples)}: {dropped})",
        flush=True,
    )
    if len(examples) < 10:
        print("[sft] FATAL: too few usable examples to train", flush=True)
        sys.exit(1)

    if args.valid:
        valid_rows = read_jsonl(args.valid)
        valid_ex, _ = build_examples(valid_rows, tok, args.max_len)
        train_ex = examples
    else:
        n_val = max(1, int(len(examples) * args.valid_frac))
        valid_ex = examples[:n_val]
        train_ex = examples[n_val:]
    print(f"[sft] train={len(train_ex)} valid={len(valid_ex)}", flush=True)

    train_ds = Dataset.from_list(train_ex)
    valid_ds = Dataset.from_list(valid_ex)

    model = AutoModelForCausalLM.from_pretrained(
        args.model,
        torch_dtype="auto",
        trust_remote_code=True,
        attn_implementation="sdpa",
    )
    model.config.use_cache = False
    if hasattr(model, "enable_input_require_grads"):
        model.enable_input_require_grads()

    lora = LoraConfig(
        r=args.lora_r,
        lora_alpha=args.lora_alpha,
        lora_dropout=args.lora_dropout,
        bias="none",
        task_type="CAUSAL_LM",
        target_modules=[
            "q_proj", "k_proj", "v_proj", "o_proj",
            "gate_proj", "up_proj", "down_proj",
        ],
    )
    model = get_peft_model(model, lora)
    model.print_trainable_parameters()

    collator = DataCollatorForSeq2Seq(tok, padding="longest", label_pad_token_id=IGNORE)

    targs = TrainingArguments(
        output_dir=args.out,
        num_train_epochs=args.epochs,
        max_steps=args.max_steps,
        per_device_train_batch_size=args.bs,
        per_device_eval_batch_size=args.bs,
        gradient_accumulation_steps=args.grad_accum,
        learning_rate=args.lr,
        lr_scheduler_type="cosine",
        warmup_ratio=args.warmup_ratio,
        bf16=True,
        logging_steps=5,
        save_steps=args.save_steps,
        save_total_limit=4,
        eval_strategy="steps",
        eval_steps=args.save_steps,
        report_to=[],
        gradient_checkpointing=True,
        remove_unused_columns=False,
        seed=args.seed,
    )

    trainer = Trainer(
        model=model,
        args=targs,
        train_dataset=train_ds,
        eval_dataset=valid_ds,
        data_collator=collator,
    )
    trainer.train()
    trainer.save_model(args.out)
    tok.save_pretrained(args.out)
    print(f"[sft] DONE -> {args.out}", flush=True)


if __name__ == "__main__":
    main()

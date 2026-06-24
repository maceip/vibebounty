#!/usr/bin/env python3
from transformers import AutoTokenizer
t = AutoTokenizer.from_pretrained("/home/ubuntu/models/VibeThinker-3B", trust_remote_code=True)
text = "<|im_start|>system\nhi\n<|im_start|>user\nquestion\n<|im_start|>assistant\nanswer\n"
print("encode manual:", len(t.encode(text)))
print("ids manual:", t.encode(text)[:30])
msgs = [
    {"role": "system", "content": "hi"},
    {"role": "user", "content": "question"},
    {"role": "assistant", "content": "answer"},
]
full = t.apply_chat_template(msgs, tokenize=False, add_generation_prompt=False)
print("rendered repr:", repr(full))
print("encode rendered:", len(t.encode(full)))
print("apply tokenized:", len(t.apply_chat_template(msgs, tokenize=True, add_generation_prompt=False)))
print("vocab size:", t.vocab_size)
print("added tokens sample:", list(t.added_tokens_encoder.keys())[:20])

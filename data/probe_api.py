import os
from pathlib import Path


def load_env():
    if os.environ.get("ANTHROPIC_API_KEY"):
        return
    p = Path.home() / ".env"
    if p.exists():
        for ln in p.read_text(encoding="utf-8", errors="ignore").split("\n"):
            ln = ln.strip()
            if ln and not ln.startswith("#") and "=" in ln:
                k, v = ln.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


load_env()
print("base_url env:", os.environ.get("ANTHROPIC_BASE_URL"))
print("key prefix:", (os.environ.get("ANTHROPIC_API_KEY") or "")[:12])
import anthropic

c = anthropic.Anthropic()
print("client base_url:", c.base_url)
def trial(name, **kw):
    base = dict(model="claude-opus-4-8", max_tokens=64,
                messages=[{"role": "user", "content": "Say OK."}])
    base.update(kw)
    try:
        r = c.messages.create(**base)
        print(f"[{name}] OK:", "".join(b.text for b in r.content if b.type == "text"))
    except Exception as e:
        print(f"[{name}] ERR {type(e).__name__}:", str(e)[:300])


trial("plain")
trial("temp0.4", temperature=0.4)
trial("system", system="You are a helpful analyst.")
trial("temp+system", temperature=0.4, system="You are a helpful analyst.")
trial("maxtok1200", max_tokens=1200)

import os
from pathlib import Path

p = Path.home() / ".env"
if p.exists():
    for ln in p.read_text(encoding="utf-8", errors="ignore").split("\n"):
        ln = ln.strip()
        if ln and not ln.startswith("#") and ln.startswith("ANTHROPIC_API_KEY="):
            os.environ.setdefault("ANTHROPIC_API_KEY", ln.split("=", 1)[1].strip().strip('"').strip("'"))

k = os.environ.get("ANTHROPIC_API_KEY", "")
print("KEY_PREFIX", k[:20] if k else "MISSING", "len", len(k))
import anthropic

c = anthropic.Anthropic()
try:
    c.messages.create(model="claude-opus-4-8", max_tokens=8, messages=[{"role": "user", "content": "ok"}])
    print("API", "OK")
except Exception as e:
    print("API", str(e)[:300])

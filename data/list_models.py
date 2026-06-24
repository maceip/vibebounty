import os
from pathlib import Path


def load_env():
    p = Path.home() / ".env"
    if p.exists():
        for ln in p.read_text(encoding="utf-8", errors="ignore").split("\n"):
            ln = ln.strip()
            if not ln or ln.startswith("#") or "=" not in ln:
                continue
            k, v = ln.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


load_env()
import anthropic

client = anthropic.Anthropic()
for m in client.models.list(limit=50).data:
    print(m.id, "|", getattr(m, "display_name", ""))

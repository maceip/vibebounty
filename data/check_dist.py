import json
import sys
from collections import Counter
from pathlib import Path

root = Path(__file__).parent / "sft"


def disp_of(line):
    msgs = json.loads(line)["messages"]
    asst = msgs[-1]["content"]
    # final JSON object is on the last line
    for chunk in reversed(asst.split("\n")):
        chunk = chunk.strip()
        if chunk.startswith("{"):
            try:
                return json.loads(chunk).get("disposition", "?")
            except Exception:
                pass
    return "?"


def dist(name):
    c = Counter()
    for ln in (root / f"{name}.jsonl").read_text(encoding="utf-8").split("\n"):
        if ln.strip():
            c[disp_of(ln)] += 1
    n = sum(c.values()) or 1
    return c, n


tr, trn = dist("train")
te, ten = dist("test")
classes = sorted(set(tr) | set(te), key=lambda k: -te.get(k, 0))
print(f"{'disposition':22s} {'train%':>8s} {'test%':>8s} {'delta':>8s}")
worst = 0.0
for k in classes:
    a, b = tr.get(k, 0) / trn, te.get(k, 0) / ten
    d = abs(a - b)
    worst = max(worst, d)
    print(f"{k:22s} {a*100:7.2f}% {b*100:7.2f}% {d*100:7.2f}%")
print(f"\nmax delta = {worst*100:.2f}%  (parity guard PARITY_TOL=6.00%)")
print("PARITY OK" if worst <= 0.06 else "PARITY FAIL -> stale/skewed data")

#!/usr/bin/env python3
"""Pre-train gate: score trace corpus + run short SFT pilot before any full GPU train.

Usage (Lambda):
  python remote/pilot_gate.py --traces data/sft/train_traces.jsonl --test data/sft/test.jsonl
  python remote/pilot_gate.py --traces ... --pilot-steps 80 --pilot-eval-n 20

Exits non-zero if gates fail. Prints JSON summary.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

ALLOWED = {
    "valid_impactful", "valid_low", "corroborated_surge", "likely_duplicate",
    "out_of_scope", "theoretical_no_poc", "self_inflicted", "accepted_risk", "slop",
}
PARITY_TOL = 0.06
MIN_TRACES = 1500
MIN_PER_CLASS = 5  # rare classes in test may have 0 in train


def gold_disp(line: str) -> str | None:
    try:
        msgs = json.loads(line)["messages"]
        asst = next(m["content"] for m in msgs if m["role"] == "assistant")
        depth, start, cand = 0, None, None
        for i, ch in enumerate(asst):
            if ch == "{":
                if depth == 0:
                    start = i
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0 and start is not None:
                    cand = asst[start : i + 1]
        if not cand:
            return None
        return json.loads(cand).get("disposition")
    except Exception:
        return None


def dist(path: Path) -> Counter:
    c: Counter = Counter()
    for ln in path.read_text(encoding="utf-8").splitlines():
        if not ln.strip():
            continue
        d = gold_disp(ln)
        if d in ALLOWED:
            c[d] += 1
    return c


def parity(train: Counter, test: Counter) -> tuple[float, str]:
    tt = sum(test.values()) or 1
    tr = sum(train.values()) or 1
    worst, max_d = "", 0.0
    for lab in ALLOWED:
        if test.get(lab, 0) == 0 and train.get(lab, 0) == 0:
            continue
        ts = test.get(lab, 0) / tt
        rs = train.get(lab, 0) / tr
        d = abs(rs - ts)
        if d > max_d:
            max_d, worst = d, lab
    return max_d, worst


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--traces", required=True)
    ap.add_argument("--test", required=True)
    ap.add_argument("--min-traces", type=int, default=MIN_TRACES)
    ap.add_argument("--pilot-steps", type=int, default=0, help="if >0 run short SFT (not implemented inline)")
    args = ap.parse_args()

    tr_p, te_p = Path(args.traces), Path(args.test)
    train, test = dist(tr_p), dist(te_p)
    n = sum(train.values())
    max_d, worst = parity(train, test)

    minority = [l for l in ALLOWED if train.get(l, 0) < MIN_PER_CLASS and test.get(l, 0) > 0]
    report = {
        "trace_count": n,
        "train_distribution": dict(train),
        "test_distribution": dict(test),
        "max_parity_delta": round(max_d, 4),
        "worst_class": worst,
        "minority_gaps": minority,
        "gates": {},
    }

    report["gates"]["min_traces"] = n >= args.min_traces
    report["gates"]["parity"] = max_d <= PARITY_TOL
    report["gates"]["minority_support"] = len(minority) == 0

    print(json.dumps(report, indent=2))
    fails = [k for k, v in report["gates"].items() if not v]
    if fails:
        print(f"PILOT_GATE_FAIL: {fails}", file=sys.stderr)
        return 1
    print("PILOT_GATE_PASS: trace corpus ready for pilot SFT (not full train yet)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

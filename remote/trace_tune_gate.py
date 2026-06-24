#!/usr/bin/env python3
"""Fail-closed gate for the thinking-trace-aligned tune.

This script is intentionally stricter than the generic pilot gate: it verifies
that the training file is made of long `<think>` traces, not the old short
outcome-rationale examples that produced the failed cold-start adapter.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import statistics
from collections import Counter
from pathlib import Path

ALLOWED = {
    "valid_impactful",
    "valid_low",
    "corroborated_surge",
    "likely_duplicate",
    "out_of_scope",
    "theoretical_no_poc",
    "self_inflicted",
    "accepted_risk",
    "slop",
}

LEAKAGE_PATTERNS = [
    r"\b(gold|ground[\s-]?truth)\b",
    r"\b(was|were|been|am|being)\s+(told|given|provided|informed|instructed)\b",
    r"\bthe (provided|given|correct|target|intended|expected) "
    r"(answer|outcome|label|verdict|disposition)\b",
    r"\bas (instructed|provided|given|specified|directed)\b",
    r"\bresolved as\b",
    r"\b(was|were|ended up|eventually|ultimately)\s+"
    r"(accepted|awarded|paid|rewarded|resolved|marked|closed|triaged|bountied)\b",
    r"\bthe program (accepted|awarded|paid|rewarded|closed|marked|resolved)\b",
]
LEAKAGE = [re.compile(p, re.I) for p in LEAKAGE_PATTERNS]


def extract_json(text: str) -> dict:
    depth = 0
    start = None
    cand = None
    for i, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start is not None:
                cand = text[start : i + 1]
    return json.loads(cand) if cand else {}


def assistant(row: dict) -> str:
    return next((m.get("content", "") for m in row.get("messages", []) if m.get("role") == "assistant"), "")


def think_text(text: str) -> str:
    m = re.search(r"<think>\s*(.*?)\s*</think>", text, re.S | re.I)
    return m.group(1).strip() if m else ""


def dist(path: Path) -> Counter[str]:
    c: Counter[str] = Counter()
    if not path.exists():
        return c
    for line in path.read_text(encoding="utf-8").split("\n"):
        if not line.strip():
            continue
        try:
            d = extract_json(assistant(json.loads(line))).get("disposition", "")
        except Exception:
            continue
        if d in ALLOWED:
            c[d] += 1
    return c


def pct(vals: list[int], q: float) -> int:
    if not vals:
        return 0
    vals = sorted(vals)
    return vals[int((len(vals) - 1) * q)]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--traces", required=True)
    ap.add_argument("--test", default="data/sft/test.jsonl")
    ap.add_argument("--out", default="ops/trace_tune_gate_report.json")
    ap.add_argument("--min-traces", type=int, default=1000)
    ap.add_argument("--min-think-p50", type=int, default=900)
    ap.add_argument("--min-per-tested-class", type=int, default=40)
    ap.add_argument("--max-leakage-rate", type=float, default=0.0)
    args = ap.parse_args()

    trace_path = Path(args.traces)
    out_path = Path(args.out)
    failures: list[str] = []
    counts: Counter[str] = Counter()
    evidence_pred: Counter[str] = Counter()
    faithful: Counter[str] = Counter()
    think_lens: list[int] = []
    parse_fail = 0
    no_think = 0
    leakage = 0
    rows = 0

    if not trace_path.exists():
        failures.append(f"missing trace file: {trace_path}")
    else:
        for line in trace_path.read_text(encoding="utf-8").split("\n"):
            if not line.strip():
                continue
            rows += 1
            try:
                row = json.loads(line)
                text = assistant(row)
                verdict = extract_json(text)
            except Exception:
                parse_fail += 1
                continue
            disp = verdict.get("disposition", "")
            if disp in ALLOWED:
                counts[disp] += 1
            else:
                parse_fail += 1
            body = think_text(text)
            if not body:
                no_think += 1
            else:
                think_lens.append(len(body))
                if any(rx.search(body) for rx in LEAKAGE):
                    leakage += 1
            if "_evidence_pred" in row:
                evidence_pred[str(row.get("_evidence_pred"))] += 1
            if "_faithful" in row:
                faithful[str(row.get("_faithful"))] += 1

    test_counts = dist(Path(args.test))
    tested_classes = [c for c, n in test_counts.items() if n > 0]
    minority_gaps = {
        c: {"train": counts.get(c, 0), "test": test_counts.get(c, 0)}
        for c in tested_classes
        if counts.get(c, 0) < args.min_per_tested_class
    }
    leakage_rate = leakage / rows if rows else 0.0
    think_p50 = pct(think_lens, 0.5)

    if rows < args.min_traces:
        failures.append(f"trace_count {rows} < {args.min_traces}")
    if parse_fail:
        failures.append(f"parse_fail rows: {parse_fail}")
    if no_think:
        failures.append(f"rows missing <think> block: {no_think}")
    if think_p50 < args.min_think_p50:
        failures.append(f"think p50 {think_p50} chars < {args.min_think_p50}")
    if leakage_rate > args.max_leakage_rate:
        failures.append(f"leakage rate {leakage_rate:.2%} > {args.max_leakage_rate:.2%}")
    if minority_gaps:
        failures.append(f"not enough trace support for tested classes: {minority_gaps}")

    report = {
        "trace_file": str(trace_path),
        "trace_sha256": hashlib.sha256(trace_path.read_bytes()).hexdigest() if trace_path.exists() else "",
        "rows": rows,
        "disposition_counts": dict(counts),
        "test_counts": dict(test_counts),
        "minority_gaps": minority_gaps,
        "parse_fail": parse_fail,
        "no_think": no_think,
        "think_chars": {
            "p50": think_p50,
            "p90": pct(think_lens, 0.9),
            "avg": round(statistics.mean(think_lens), 1) if think_lens else 0,
            "min": min(think_lens) if think_lens else 0,
            "max": max(think_lens) if think_lens else 0,
        },
        "leakage_rows": leakage,
        "leakage_rate": round(leakage_rate, 6),
        "evidence_pred_counts": dict(evidence_pred),
        "faithful_counts": dict(faithful),
        "gates": {
            "min_traces": rows >= args.min_traces,
            "parse_clean": parse_fail == 0,
            "all_thinking_traces": no_think == 0,
            "long_reasoning": think_p50 >= args.min_think_p50,
            "no_outcome_leakage": leakage_rate <= args.max_leakage_rate,
            "tested_class_support": not minority_gaps,
        },
        "failures": failures,
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    if failures:
        print("TRACE_TUNE_GATE_FAIL")
        return 1
    print("TRACE_TUNE_GATE_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

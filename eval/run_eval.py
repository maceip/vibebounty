"""Offline evaluation of the triage pipeline against the held-out test set.

Runs the EXACT production path (`app.triage.run`) over `data/sft/test.jsonl`
and scores predicted dispositions/severities against the real disclosure
outcomes baked into each example. Works fully offline:

  - the model endpoint is forced unreachable -> the transparent heuristic +
    ground-truth defense layers run (this is the baseline the tuned model beats);
  - OSV network lookups are stubbed out so corroboration uses only the local
    KEV/NVD cache.

Point it at a live model later to score the fine-tuned VibeThinker instead:

    # offline heuristic+defense baseline (no network, no model):
    uv run --with pandas --with pyarrow python eval/run_eval.py

    # score the served model:
    uv run python eval/run_eval.py --model-base-url http://localhost:8080/v1

Writes eval/report.json and eval/report.md.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

SEV_ORD = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
DISPOSITIONS = [
    "valid_impactful", "valid_low", "corroborated_surge", "likely_duplicate",
    "out_of_scope", "theoretical_no_poc", "self_inflicted", "accepted_risk", "slop",
]
# coarse accept/reject view (is the report worth a human's time?)
ACCEPT = {"valid_impactful", "valid_low", "corroborated_surge"}


def parse_user(content: str) -> dict:
    sub = {"title": "", "severity_claimed": "", "asset": "",
           "description": "", "steps_to_reproduce": "", "impact": ""}
    body, in_body = [], False
    for ln in content.splitlines():
        if ln.startswith("Title: "):
            sub["title"] = ln[len("Title: "):].strip()
        elif ln.startswith("Asset type: "):
            sub["asset"] = ln[len("Asset type: "):].strip()
        elif ln.startswith("Severity claimed: "):
            sub["severity_claimed"] = ln[len("Severity claimed: "):].strip()
        elif ln.startswith("Program: "):
            continue
        elif ln.strip() == "Report:":
            in_body = True
        elif in_body:
            body.append(ln)
    sub["description"] = "\n".join(body).strip()
    return sub


def extract_gold(assistant: str) -> dict:
    """The assistant message is `reasoning\n{json verdict}`; grab the JSON."""
    depth, start, cand = 0, None, None
    for i, ch in enumerate(assistant):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start is not None:
                cand = assistant[start:i + 1]
    return json.loads(cand) if cand else {}


def load_test(path: pathlib.Path, n: int | None) -> list[dict]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        msgs = json.loads(line)["messages"]
        user = next(m["content"] for m in msgs if m["role"] == "user")
        asst = next(m["content"] for m in msgs if m["role"] == "assistant")
        gold = extract_gold(asst)
        rows.append({"submission": parse_user(user), "gold": gold})
        if n and len(rows) >= n:
            break
    return rows


def prf(cm: dict, labels: list[str]) -> dict:
    out = {}
    for lab in labels:
        tp = cm.get(lab, {}).get(lab, 0)
        fp = sum(cm.get(g, {}).get(lab, 0) for g in labels if g != lab)
        fn = sum(cm.get(lab, {}).get(p, 0) for p in labels if p != lab)
        support = sum(cm.get(lab, {}).values())
        p = tp / (tp + fp) if (tp + fp) else 0.0
        r = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * p * r / (p + r) if (p + r) else 0.0
        out[lab] = {"precision": p, "recall": r, "f1": f1, "support": support}
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=str(ROOT / "data" / "sft" / "test.jsonl"))
    ap.add_argument("--n", type=int, default=None)
    ap.add_argument("--model-base-url", default=None,
                    help="serve a model here to score it; omit for offline baseline")
    args = ap.parse_args()

    # Offline by default: unreachable model -> heuristic+defense; stub OSV network.
    os.environ["MODEL_BASE_URL"] = args.model_base_url or "http://127.0.0.1:9"
    import feeds.enrich as fe
    if not args.model_base_url:
        fe._osv_lookup = lambda *a, **k: []  # no network on the plane
    from app import triage

    rows = load_test(pathlib.Path(args.data), args.n)
    engine = None
    cm: dict = {}                       # cm[gold][pred] = count
    sev_abs_err, sev_exact = [], 0
    accept_correct = 0
    surge_tp = surge_fn = 0             # did we catch corroborated reports?
    n = 0
    for row in rows:
        res = triage.run(row["submission"])
        engine = res["engine"]
        pred = res["verdict"].get("disposition", "?")
        g = row["gold"].get("disposition", "?")
        cm.setdefault(g, {}).setdefault(pred, 0)
        cm[g][pred] += 1
        # severity
        gs = SEV_ORD.get(row["gold"].get("severity_estimate", "none"), 0)
        ps = SEV_ORD.get(res["verdict"].get("severity_estimate", "none"), 0)
        sev_abs_err.append(abs(gs - ps))
        sev_exact += int(gs == ps)
        # coarse accept/reject
        if (g in ACCEPT) == (pred in ACCEPT):
            accept_correct += 1
        if g == "corroborated_surge":
            surge_tp += int(pred == "corroborated_surge")
            surge_fn += int(pred != "corroborated_surge")
        n += 1

    labels = [l for l in DISPOSITIONS if l in cm or any(l in v for v in cm.values())]
    correct = sum(cm.get(l, {}).get(l, 0) for l in labels)
    acc = correct / n if n else 0.0
    per = prf(cm, labels)
    sup_labels = [l for l in labels if per[l]["support"] > 0]
    macro_f1 = sum(per[l]["f1"] for l in sup_labels) / len(sup_labels) if sup_labels else 0.0
    weighted_f1 = (sum(per[l]["f1"] * per[l]["support"] for l in sup_labels) / n) if n else 0.0
    sev_mae = sum(sev_abs_err) / len(sev_abs_err) if sev_abs_err else 0.0
    sev_within1 = sum(e <= 1 for e in sev_abs_err) / len(sev_abs_err) if sev_abs_err else 0.0

    report = {
        "engine": engine,
        "n": n,
        "disposition_accuracy": round(acc, 4),
        "accept_reject_accuracy": round(accept_correct / n, 4) if n else 0.0,
        "macro_f1": round(macro_f1, 4),
        "weighted_f1": round(weighted_f1, 4),
        "severity_exact": round(sev_exact / n, 4) if n else 0.0,
        "severity_within_1": round(sev_within1, 4),
        "severity_mae": round(sev_mae, 4),
        "corroborated_surge_recall": round(surge_tp / (surge_tp + surge_fn), 4) if (surge_tp + surge_fn) else None,
        "per_class": {l: {k: (round(v, 4) if isinstance(v, float) else v)
                          for k, v in per[l].items()} for l in labels},
        "confusion": cm,
    }
    (ROOT / "eval" / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    write_md(report, labels)

    # console summary
    print(f"\nengine: {engine}    examples: {n}")
    print(f"disposition accuracy : {acc:6.1%}")
    print(f"accept/reject acc    : {accept_correct / n:6.1%}")
    print(f"macro-F1             : {macro_f1:6.3f}")
    print(f"weighted-F1          : {weighted_f1:6.3f}")
    print(f"severity exact / <=1 : {sev_exact / n:6.1%} / {sev_within1:6.1%}   (MAE {sev_mae:.2f})")
    if report["corroborated_surge_recall"] is not None:
        print(f"corroborated_surge R : {report['corroborated_surge_recall']:6.1%}")
    print(f"\n{'disposition':<20}{'P':>7}{'R':>7}{'F1':>7}{'n':>6}")
    for l in labels:
        m = per[l]
        print(f"{l:<20}{m['precision']:>7.2f}{m['recall']:>7.2f}{m['f1']:>7.2f}{m['support']:>6}")
    print(f"\nwrote eval/report.json and eval/report.md")


def write_md(r: dict, labels: list[str]) -> None:
    L = []
    L.append("# Triage evaluation report\n")
    L.append(f"- engine: `{r['engine']}`")
    L.append(f"- examples: **{r['n']}** (held-out test split, real disclosure outcomes)\n")
    L.append("## Headline metrics\n")
    L.append("| metric | value |")
    L.append("|---|---|")
    L.append(f"| disposition accuracy (9-class) | **{r['disposition_accuracy']:.1%}** |")
    L.append(f"| accept / reject accuracy | **{r['accept_reject_accuracy']:.1%}** |")
    L.append(f"| macro-F1 | {r['macro_f1']:.3f} |")
    L.append(f"| weighted-F1 | {r['weighted_f1']:.3f} |")
    L.append(f"| severity exact | {r['severity_exact']:.1%} |")
    L.append(f"| severity within 1 | {r['severity_within_1']:.1%} (MAE {r['severity_mae']:.2f}) |")
    if r["corroborated_surge_recall"] is not None:
        L.append(f"| corroborated_surge recall | {r['corroborated_surge_recall']:.1%} |")
    L.append("\n## Per-class\n")
    L.append("| disposition | precision | recall | F1 | support |")
    L.append("|---|---|---|---|---|")
    for l in labels:
        m = r["per_class"][l]
        L.append(f"| {l} | {m['precision']:.2f} | {m['recall']:.2f} | {m['f1']:.2f} | {m['support']} |")
    L.append("\n## Confusion (gold rows -> predicted cols)\n")
    L.append("| gold \\ pred | " + " | ".join(labels) + " |")
    L.append("|" + "---|" * (len(labels) + 1))
    for g in labels:
        cells = [str(r["confusion"].get(g, {}).get(p, 0)) for p in labels]
        L.append(f"| **{g}** | " + " | ".join(cells) + " |")
    (ROOT / "eval" / "report.md").write_text("\n".join(L) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()

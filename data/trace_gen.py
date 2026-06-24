#!/usr/bin/env python3
"""Generate faithful, label-conditioned reasoning traces for Phase-1 cold-start SFT.

For each SFT record (system / user-report / assistant-gold-JSON) we ask a frontier
teacher (Claude) to write the step-by-step reasoning a skilled analyst would think
through BEFORE reaching the gold verdict -- reasoning forward from the report
evidence, never backward from the outcome and never revealing it was given the
answer. The trace is then gated by three quality filters and, on pass, emitted as
a new SFT target of the form:

    <think>
    {reasoning}
    </think>
    {gold_json}

Quality gates (fail-closed -> retry up to --retries, then DROP and log):
  1. consistency : teacher's own 'VERDICT:' line must equal the gold disposition.
  2. leakage     : trace must not reference being given the answer or the outcome.
  3. necessity   : trace must be long enough AND grounded in THIS report's tokens
                   (>= MIN_GROUNDING distinct content words shared with the report).

Idempotent / resumable: output is append-only JSONL keyed by a stable hash of the
user prompt; re-running skips records already present in --out.

Usage:
  # pilot (cheap, eyeball quality first)
  python trace_gen.py --in data/sft/train.jsonl --out data/sft/train_traces.jsonl \
      --sample-per-class 3 --workers 4

  # full run
  python trace_gen.py --in data/sft/train.jsonl --out data/sft/train_traces.jsonl \
      --workers 8
"""
import argparse
import hashlib
import json
import os
import re
import sys
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ALLOWED = {
    "valid_impactful", "valid_low", "corroborated_surge", "likely_duplicate",
    "out_of_scope", "theoretical_no_poc", "self_inflicted", "accepted_risk", "slop",
}

# --- leakage: trace must NOT say it was handed the answer or cite the outcome ----
LEAKAGE = [
    re.compile(p, re.I) for p in (
        r"\b(gold|ground[\s-]?truth)\b",
        r"\b(was|were|been|am|being)\s+(told|given|provided|informed|instructed)\b",
        r"\bthe (provided|given|correct|target|intended|expected) "
        r"(answer|label|disposition|outcome|verdict|classification)\b",
        r"\bas (instructed|provided|given|specified|directed)\b",
        r"\bpre-?determined\b",
        r"\bthe answer is\b",
        r"\bresolved as\b",
        r"\b(was|were|ended up|eventually|ultimately)\s+"
        r"(accepted|awarded|paid|rewarded|resolved|marked|closed|triaged|bountied)\b",
        r"\bthe program (accepted|awarded|paid|rewarded|closed|marked|resolved)\b",
        r"\bbounty (was|of|amount|paid)\b",
        r"\bturned out\b",
        r"\bin hindsight\b",
        r"\bwe now know\b",
    )
]

MIN_TRACE_CHARS = 200
MIN_GROUNDING = 3
_WORD = re.compile(r"[a-zA-Z][a-zA-Z0-9_]{5,}")
# generic triage vocabulary that shouldn't count as report-specific grounding
STOP = {
    "report", "reports", "reporter", "researcher", "submission", "submissions",
    "triage", "severity", "impact", "vulnerability", "vulnerabilities", "security",
    "disposition", "should", "because", "however", "without", "evidence",
    "attacker", "appears", "concrete", "boundary", "trust", "before", "actual",
    "claimed", "really", "either", "neither", "another", "external",
}

TEACHER_SYSTEM = (
    "You are an expert bug bounty triage analyst writing your own private reasoning "
    "notes as you decide how to triage a single researcher submission. Write the "
    "step-by-step reasoning a skilled analyst thinks through before reaching a verdict.\n\n"
    "Rules:\n"
    "- Reason ONLY from evidence inside the submission: reproducibility / PoC quality, "
    "claimed vs. actual impact, whether a real trust or privilege boundary is crossed, "
    "scope, red flags, and any 'EXTERNAL CORROBORATION' block (treat that block as live "
    "threat-intel ground truth).\n"
    "- Reason FORWARD from the evidence. Do NOT reference how the report was eventually "
    "resolved, accepted, rewarded, paid, or closed -- that is not known at triage time.\n"
    "- Do NOT reveal or hint that you were given any answer. Never use words like 'gold', "
    "'label', 'ground truth', or say you were told/given the outcome.\n"
    "- Be concrete: cite specific details from THIS report (vuln class, endpoint, observed "
    "behavior, the actual evidence) rather than generic statements.\n"
    "- 4-10 sentences, first person, present tense, analytical.\n"
    "- End with a final line EXACTLY of the form: VERDICT: <disposition>\n\n"
    "Allowed dispositions: valid_impactful, valid_low, corroborated_surge, "
    "likely_duplicate, out_of_scope, theoretical_no_poc, self_inflicted, "
    "accepted_risk, slop."
)


def load_env() -> None:
    if os.environ.get("ANTHROPIC_API_KEY"):
        return
    p = Path.home() / ".env"
    if p.exists():
        for ln in p.read_text(encoding="utf-8", errors="ignore").split("\n"):
            ln = ln.strip()
            if ln and not ln.startswith("#") and "=" in ln:
                k, v = ln.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def gold_of(messages: list):
    """Return (system, user, gold_json_str, gold_disp) from an SFT record."""
    sys_c = user_c = asst = ""
    for m in messages:
        if m["role"] == "system":
            sys_c = m["content"]
        elif m["role"] == "user":
            user_c = m["content"]
        elif m["role"] == "assistant":
            asst = m["content"]
    gold = None
    for chunk in reversed(asst.split("\n")):
        chunk = chunk.strip()
        if chunk.startswith("{"):
            try:
                gold = json.loads(chunk)
                break
            except Exception:
                continue
    if gold is None:
        return None
    return sys_c, user_c, json.dumps(gold, ensure_ascii=False), gold.get("disposition", "")


# A "toxic contradiction": the label asserts a real / impactful finding, but the
# evidence-only judge sees nothing there. Training a trace on these teaches the
# model to hallucinate impact from an empty body. These (and only these) get dropped.
_REAL = {"valid_impactful", "corroborated_surge"}
_EMPTY = {"theoretical_no_poc", "slop", "self_inflicted"}


def is_toxic(gold_disp: str, pred: str) -> bool:
    if gold_disp in _REAL and pred in _EMPTY:
        return True
    if gold_disp == "valid_low" and pred == "slop":
        return True
    return False


def grounding(report: str, trace: str) -> int:
    rt = {w.lower() for w in _WORD.findall(report)} - STOP
    tt = {w.lower() for w in _WORD.findall(trace)} - STOP
    return len(rt & tt)


def check(trace: str, report: str, gold_disp: str):
    """Return (ok, reason). Splits off the VERDICT line before grounding/leakage."""
    lines = [ln for ln in trace.strip().split("\n")]
    verdict = ""
    body = []
    for ln in lines:
        m = re.match(r"\s*VERDICT:\s*([a-z_]+)\s*$", ln, re.I)
        if m:
            verdict = m.group(1).lower()
        else:
            body.append(ln)
    body_txt = "\n".join(body).strip()
    if verdict not in ALLOWED:
        return None, "no_verdict_line"
    if verdict != gold_disp:
        return None, f"verdict_mismatch({verdict}!={gold_disp})"
    if len(body_txt) < MIN_TRACE_CHARS:
        return None, f"too_short({len(body_txt)})"
    for rx in LEAKAGE:
        if rx.search(body_txt):
            return None, f"leakage({rx.pattern[:24]})"
    g = grounding(report, body_txt)
    if g < MIN_GROUNDING:
        return None, f"ungrounded({g})"
    return body_txt, "ok"


def make_client():
    import anthropic
    return anthropic.Anthropic()


def probe_api(client, model: str) -> None:
    """Fail fast on billing/auth errors instead of burning thousands of calls."""
    try:
        client.messages.create(
            model=model, max_tokens=8,
            messages=[{"role": "user", "content": "ok"}],
        )
    except Exception as e:
        msg = str(e).lower()
        if "credit balance" in msg or "authentication" in msg or "invalid x-api-key" in msg:
            sys.exit(f"[trace_gen] FATAL: Anthropic API unavailable: {e}")
        raise


def _fatal_api(err: Exception) -> None:
    msg = str(err).lower()
    if "credit balance" in msg or "authentication" in msg or "invalid x-api-key" in msg:
        sys.exit(f"[trace_gen] FATAL: Anthropic API unavailable: {err}")


PREDICT_SYSTEM = (
    "You are an expert bug bounty triage analyst. Read ONE researcher submission and "
    "decide the single most likely triage disposition based ONLY on the evidence in the "
    "submission as written -- its reproducibility/PoC quality, claimed vs. actual impact, "
    "whether a real trust boundary is crossed, scope, red flags, and any 'EXTERNAL "
    "CORROBORATION' block (treat that block as live threat-intel ground truth). Do not "
    "assume facts not present. Reply with EXACTLY one disposition word and nothing else.\n"
    "Allowed: valid_impactful, valid_low, corroborated_surge, likely_duplicate, "
    "out_of_scope, theoretical_no_poc, self_inflicted, accepted_risk, slop."
)


def predict_evidence_only(client, model, report, max_report_chars=8000):
    """Evidence-only disposition (no gold shown) -> faithfulness signal."""
    try:
        resp = client.messages.create(
            model=model, max_tokens=16, system=PREDICT_SYSTEM,
            messages=[{"role": "user", "content": "SUBMISSION:\n" + report[:max_report_chars]}],
        )
        raw = "".join(b.text for b in resp.content if b.type == "text").strip().lower()
    except Exception as e:
        _fatal_api(e)
        return f"err:{type(e).__name__}"
    m = re.search(r"[a-z_]+", raw)
    return m.group(0) if m else "none"


def gen_one(client, model, sys_c, report, gold_json, gold_disp, retries, max_tokens):
    sev = ""
    try:
        sev = json.loads(gold_json).get("severity_estimate", "")
    except Exception:
        pass
    base_user = (
        f"SUBMISSION:\n{report}\n\n"
        f"The correct triage outcome for this submission is {gold_disp}"
        + (f" (severity: {sev})" if sev else "")
        + ". Write the analyst reasoning that lands on this outcome, following every "
        "rule. Do not reveal the outcome was provided; derive it from the evidence."
    )
    last = "drop"
    for attempt in range(retries + 1):
        user = base_user
        if attempt:
            user += ("\n\nYour previous attempt failed quality checks. Be more specific "
                     "to THIS report's concrete details and never reference any outcome "
                     "or that an answer was provided.")
        try:
            resp = client.messages.create(
                model=model, max_tokens=max_tokens,
                system=TEACHER_SYSTEM,
                messages=[{"role": "user", "content": user}],
            )
            raw = "".join(b.text for b in resp.content if b.type == "text")
        except Exception as e:
            _fatal_api(e)
            last = f"api_error:{type(e).__name__}"
            time.sleep(1.5 * (attempt + 1))
            continue
        body, reason = check(raw, report, gold_disp)
        if body:
            return body, "ok"
        last = reason
    return None, last


_lock = threading.Lock()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True)
    ap.add_argument("--out", dest="out", required=True)
    ap.add_argument("--model", default="claude-opus-4-8")
    ap.add_argument("--predict-model", default="",
                    help="model for the evidence-only faithfulness check "
                         "(default: same as --model)")
    ap.add_argument("--verify", action="store_true",
                    help="run evidence-only prediction; record gold-vs-evidence agreement")
    ap.add_argument("--drop-unfaithful", action="store_true",
                    help="with --verify, DROP records where evidence-only prediction "
                         "disagrees with gold (unfaithful / outcome-derived labels)")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--retries", type=int, default=2)
    ap.add_argument("--max-tokens", type=int, default=1200)
    ap.add_argument("--max-report-chars", type=int, default=8000)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--sample-per-class", type=int, default=0,
                    help="if >0, sample N records per gold disposition (pilot mode)")
    args = ap.parse_args()

    load_env()
    if not os.environ.get("ANTHROPIC_API_KEY"):
        sys.exit("ANTHROPIC_API_KEY not set (and not in ~/.env)")

    src = Path(args.inp)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)

    # resume: collect hashes already done
    done = set()
    if out.exists():
        for ln in out.read_text(encoding="utf-8").split("\n"):
            ln = ln.strip()
            if ln:
                try:
                    done.add(json.loads(ln).get("_h"))
                except Exception:
                    pass

    # load + parse source
    records = []
    for ln in src.read_text(encoding="utf-8").split("\n"):
        ln = ln.strip()
        if not ln:
            continue
        try:
            msgs = json.loads(ln)["messages"]
        except Exception:
            continue
        g = gold_of(msgs)
        if not g:
            continue
        sys_c, user_c, gold_json, gold_disp = g
        if gold_disp not in ALLOWED:
            continue
        report = user_c[:args.max_report_chars]
        h = hashlib.sha1(user_c.encode("utf-8")).hexdigest()[:16]
        records.append((h, sys_c, report, gold_json, gold_disp))

    # pilot sampling per class
    if args.sample_per_class:
        by = {}
        for r in records:
            by.setdefault(r[4], []).append(r)
        picked = []
        for disp, items in by.items():
            picked.extend(items[:args.sample_per_class])
        records = picked
    if args.limit:
        records = records[:args.limit]

    todo = [r for r in records if r[0] not in done]
    print(f"[trace_gen] model={args.model} total={len(records)} "
          f"already_done={len(records)-len(todo)} todo={len(todo)} workers={args.workers}",
          flush=True)
    if not todo:
        print("[trace_gen] nothing to do.")
        return

    client = make_client()
    probe_api(client, args.model)
    pred_model = args.predict_model or args.model
    stats = Counter()
    disagree = Counter()  # "gold->pred" for faithfulness misses
    fout = out.open("a", encoding="utf-8")
    t0 = time.time()
    n_done = 0

    def work(rec):
        h, sys_c, report, gold_json, gold_disp = rec
        pred = ""
        if args.verify:
            pred = predict_evidence_only(client, pred_model, report, args.max_report_chars)
        body, reason = gen_one(client, args.model, sys_c, report, gold_json,
                               gold_disp, args.retries, args.max_tokens)
        return h, sys_c, report, gold_json, gold_disp, body, reason, pred

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = [ex.submit(work, r) for r in todo]
        for fut in as_completed(futs):
            h, sys_c, report, gold_json, gold_disp, body, reason, pred = fut.result()
            n_done += 1
            faithful = (not args.verify) or (pred == gold_disp)
            if args.verify:
                stats["agree" if faithful else "disagree"] += 1
                if not faithful:
                    disagree[f"{gold_disp}->{pred}"] += 1
            stats[reason] += 1
            drop_unfaithful = (args.verify and args.drop_unfaithful
                               and is_toxic(gold_disp, pred))
            if drop_unfaithful:
                stats["dropped_toxic"] += 1
            if body and not drop_unfaithful:
                assistant = f"<think>\n{body}\n</think>\n{gold_json}"
                rec = {
                    "_h": h,
                    "messages": [
                        {"role": "system", "content": sys_c},
                        {"role": "user", "content": report},
                        {"role": "assistant", "content": assistant},
                    ],
                }
                if args.verify:
                    rec["_evidence_pred"] = pred
                    rec["_faithful"] = faithful
                with _lock:
                    fout.write(json.dumps(rec, ensure_ascii=False) + "\n")
                    fout.flush()
            if n_done % 25 == 0 or n_done == len(todo):
                rate = n_done / max(1e-6, time.time() - t0)
                print(f"[trace_gen] {n_done}/{len(todo)} ok={stats['ok']} "
                      f"rate={rate:.1f}/s stats={dict(stats)}", flush=True)

    fout.close()
    print(f"[trace_gen] DONE ok={stats['ok']}/{len(todo)} stats={dict(stats)}", flush=True)
    if args.verify:
        agree = stats["agree"]
        tot = agree + stats["disagree"]
        print(f"[trace_gen] FAITHFULNESS: evidence==gold {agree}/{tot} "
              f"({100*agree/max(1,tot):.0f}%)", flush=True)
        if disagree:
            print("[trace_gen] top disagreements (gold->evidence_pred):", flush=True)
            for k, v in disagree.most_common(12):
                print(f"    {k}: {v}", flush=True)


if __name__ == "__main__":
    main()

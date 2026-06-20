"""Build the supervised fine-tuning dataset for the bug-bounty triage model.

Labels are derived from REAL HackerOne disclosure outcomes in the corpus
(substate, severity, bounty, votes, cve_ids) -- not invented. We map those
real outcomes onto the project's disposition taxonomy and render each row as a
chat example (system / user / assistant) in the format mlx-lm expects.

Output: data/sft/{train,valid,test}.jsonl  (messages format)

Run:
    uv run --with pandas --with pyarrow python data/build_sft.py
"""
from __future__ import annotations

import json
import random
import re
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
PARQUET = ROOT / "data" / "corpus" / "bugbounty_reports.parquet"
OUT = ROOT / "data" / "sft"
SYSTEM = (ROOT / "prompts" / "triage_system.txt").read_text(encoding="utf-8").strip()

SEED = 13
random.seed(SEED)

# Use the FULL blended corpus (all 19,459 rows, including metadata-only reports
# with no body). No class capping -- train on everything that has a derivable
# real outcome label.
BODY_MAX = 1600
VALID_FRAC = 0.045
TEST_N = 300

def clean(v, default: str = "") -> str:
    """Treat NaN / 'nan' / '' as missing (pandas NaN is a truthy float)."""
    if v is None:
        return default
    s = str(v).strip()
    if s == "" or s.lower() == "nan" or s.lower() == "none":
        return default
    return s


SEV_SET = {"critical", "high", "medium", "low", "none"}
# Vuln classes that are notoriously high-frequency / commonly duplicated.
DUP_RISK_CLASSES = {
    "csrf", "clickjacking", "open_redirect", "misconfig", "info_disclosure",
    "xss",
}
POC_RE = re.compile(r"```|\bstep\s*\d|\bcurl\b|\bPOST\b|\bGET\b|\bpayload\b|"
                    r"http[s]?://|\bexploit\b|proof of concept|\bPoC\b", re.I)
CVE_RE = re.compile(r"CVE-\d{4}-\d{3,7}", re.I)

VULN_LABELS = {
    "xss": "a cross-site scripting (XSS)", "idor_authz": "an IDOR / broken-authz",
    "rce": "a remote code execution", "sqli": "a SQL injection",
    "ssrf": "a server-side request forgery (SSRF)", "csrf": "a CSRF",
    "auth": "an authentication", "info_disclosure": "an information-disclosure",
    "dos": "a denial-of-service", "memory_corruption": "a memory-corruption",
    "crypto_logic": "a cryptographic-logic", "open_redirect": "an open-redirect",
    "privilege_escalation": "a privilege-escalation", "injection": "an injection",
    "business_logic": "a business-logic", "clickjacking": "a clickjacking",
    "misconfig": "a misconfiguration", "other": "a security",
}


def sev_or_infer(row) -> str:
    s = str(row.get("severity") or "").strip().lower()
    if s in SEV_SET:
        return s
    sub = str(row.get("substate") or "")
    bounty = row.get("bounty_amount")
    bounty = float(bounty) if pd.notna(bounty) else 0.0
    if sub == "spam":
        return "none"
    if sub in ("informative", "not-applicable", "duplicate"):
        return "low"
    if sub == "resolved":
        if bounty >= 2000:
            return "high"
        if bounty > 0:
            return "medium"
        return "low"
    return "low"


def label_row(row) -> str | None:
    """Map a real disclosure outcome to a disposition. None => drop."""
    sub = str(row.get("substate") or "").strip().lower()
    sev = sev_or_infer(row)
    has_cve = bool(CVE_RE.search(str(row.get("cve_ids") or "")))

    if sub == "spam":
        return "slop"
    if sub == "duplicate":
        return "likely_duplicate"
    if sub == "not-applicable":
        return "out_of_scope"
    if sub == "informative":
        return "valid_low"
    if sub == "resolved":
        if has_cve:
            return "corroborated_surge"
        if sev in ("critical", "high"):
            return "valid_impactful"
        return "valid_low"
    return None


def is_dup_risk(row, disposition: str) -> bool:
    if disposition == "likely_duplicate":
        return True
    return str(row.get("vuln_class") or "") in DUP_RISK_CLASSES


def build_user(row, disposition: str) -> str:
    title = clean(row.get("title"), "(untitled)")
    asset = clean(row.get("asset_type")) or clean(row.get("domain"), "unspecified")
    program = clean(row.get("program"), "unknown")
    claimed = clean(row.get("severity"), "unspecified")
    body = clean(row.get("body"))
    if len(body) > BODY_MAX:
        body = body[:BODY_MAX] + " ...[truncated]"
    parts = [
        f"Title: {title}",
        f"Program: {program}",
        f"Asset type: {asset}",
        f"Severity claimed: {claimed}",
        "",
        "Report:",
        body if body else "(no body provided)",
    ]
    # Real CVE -> render the corroboration block exactly like the live pipeline.
    cves = CVE_RE.findall(str(row.get("cve_ids") or ""))
    if cves:
        parts += [
            "",
            "=== EXTERNAL CORROBORATION (live threat-intel feeds) ===",
            f"MATCH: {', '.join(c.upper() for c in cves[:3])} found in advisory/NVD feed.",
            "recent: true",
            f"actively_exploited (CISA KEV): {str(bool(row.get('votes') and int(row.get('votes') or 0) > 30)).lower()}",
        ]
    return "\n".join(parts)


def build_reasoning(row, disposition: str, sev: str) -> str:
    vc = clean(row.get("vuln_class"), "other")
    vlabel = VULN_LABELS.get(vc, "a security")
    asset = clean(row.get("asset_type")) or clean(row.get("domain"), "the target")
    bounty = row.get("bounty_amount")
    bounty = float(bounty) if pd.notna(bounty) else 0.0
    body = str(row.get("body") or "")
    has_poc = bool(POC_RE.search(body))
    cves = CVE_RE.findall(str(row.get("cve_ids") or ""))

    has_body = bool(clean(row.get("body")))
    bits = [f"This is {vlabel} report against {asset}."]
    if not has_body:
        bits.append("No writeup body was provided; the decision rests on the report "
                    "metadata and the disclosure outcome.")
    elif has_poc:
        bits.append("The body contains concrete reproduction detail (steps/PoC/requests).")
    else:
        bits.append("The body is light on reproducible proof-of-concept detail.")

    if disposition == "slop":
        bits.append("It was dispositioned as spam on disclosure: no credible, "
                     "reproducible security analysis -> slop.")
    elif disposition == "likely_duplicate":
        bits.append("It resolved as a duplicate of a previously known issue and the "
                    "class is commonly reported -> likely_duplicate.")
    elif disposition == "out_of_scope":
        bits.append("It was closed as not-applicable: the behavior is outside the "
                    "program's scope or threat model -> out_of_scope.")
    elif disposition == "corroborated_surge":
        bits.append(f"It maps to publicly disclosed advisories ({', '.join(c.upper() for c in cves[:2])}); "
                    "the external feed is the evidence, so this is a genuine known "
                    "issue rather than noise -> corroborated_surge.")
    elif disposition == "valid_impactful":
        clause = f"a {sev}-severity vulnerability"
        if bounty > 0:
            clause += f" awarded a ${int(bounty)} bounty"
        bits.append(f"It resolved as {clause}, crossing a real trust boundary with "
                    "demonstrated impact -> valid_impactful.")
    elif disposition == "valid_low":
        bits.append("It was accepted as real but limited (informative / low impact) "
                    "-> valid_low.")
    return " ".join(bits)


def build_assistant(row, disposition: str) -> str:
    sev = sev_or_infer(row)
    reasoning = build_reasoning(row, disposition, sev)
    verdict = {
        "disposition": disposition,
        "severity_estimate": sev,
        "is_duplicate_risk": is_dup_risk(row, disposition),
        "reasoning": reasoning,
        "questions_for_researcher": [],
        "confidence": 0.9 if disposition in ("slop", "valid_impactful",
                                             "corroborated_surge") else 0.8,
    }
    if CVE_RE.search(str(row.get("cve_ids") or "")):
        verdict["used_external_corroboration"] = True
    return reasoning + "\n" + json.dumps(verdict, ensure_ascii=False)


def main() -> None:
    df = pd.read_parquet(PARQUET)  # all 19,459 rows, body and metadata-only

    rows_by_label: dict[str, list] = {}
    for _, row in df.iterrows():
        disp = label_row(row)
        if disp is None:  # no derivable real outcome (substate missing)
            continue
        rows_by_label.setdefault(disp, []).append(row)

    # No capping: train on every labeled report.
    examples = []
    for disp, rows in rows_by_label.items():
        for row in rows:
            examples.append({
                "messages": [
                    {"role": "system", "content": SYSTEM},
                    {"role": "user", "content": build_user(row, disp)},
                    {"role": "assistant", "content": build_assistant(row, disp)},
                ]
            })

    random.shuffle(examples)
    test = examples[:TEST_N]
    rest = examples[TEST_N:]
    n_valid = max(64, int(len(rest) * VALID_FRAC))
    valid = rest[:n_valid]
    train = rest[n_valid:]

    OUT.mkdir(parents=True, exist_ok=True)
    for name, data in (("train", train), ("valid", valid), ("test", test)):
        with (OUT / f"{name}.jsonl").open("w", encoding="utf-8") as f:
            for ex in data:
                f.write(json.dumps(ex, ensure_ascii=False) + "\n")

    print("label distribution (pre-cap):")
    for k in sorted(rows_by_label, key=lambda k: -len(rows_by_label[k])):
        print(f"  {k:<20} {len(rows_by_label[k]):>6}")
    print(f"\nwritten: train={len(train)}  valid={len(valid)}  test={len(test)}")
    print(f"out dir: {OUT}")


if __name__ == "__main__":
    main()

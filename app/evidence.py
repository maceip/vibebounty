"""Claim-level evidence verification — the core differentiator.

Instead of judging a report by how it *reads*, decompose it into discrete
security claims and check each against ground truth the model cannot bluff:

  - the real codebase symbol table  -> catches fabricated/hallucinated functions
                                       (the "AI-slop" signal; cf. curl/Honeyslop)
  - the threat-intel feeds          -> confirms real CVEs / vulnerable packages

A verdict's confidence is then gated on how many claims survive verification
(a CLR-style reliability score), so polished-but-fabricated reports score low
and externally-corroborated ones score high. This is VibeThinker's claim-level
reliability idea applied to triage.
"""
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
SYMBOLS_FILE = ROOT / "data" / "codebase_symbols.txt"

# function-call-like internal symbols: snake_case with >=1 underscore + "("
SYM_CALL_RE = re.compile(r"\b([a-z][a-z0-9]*(?:_[a-z0-9]+)+)\s*\(")
BACKTICK_RE = re.compile(r"`([a-z][a-z0-9]*(?:_[a-z0-9]+)+)`", re.I)
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)

SECURITY_HINTS = (
    "vuln", "inject", "xss", "rce", "ssrf", "idor", "bypass", "overflow",
    "leak", "exploit", "csrf", "pollution", "traversal", "deserial", "auth",
    "token", "execute", "crash", "memory", "function", "cve", "privilege",
    "escalat", "redirect", "disclosure", "credential", "header", "rate limit",
)


def load_codebase() -> tuple[set, set]:
    symbols, prefixes = set(), set()
    if SYMBOLS_FILE.exists():
        for line in SYMBOLS_FILE.read_text(encoding="utf-8").splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            symbols.add(s)
            if "_" in s:
                prefixes.add(s.split("_", 1)[0])
    return symbols, prefixes


_SYMBOLS, _PREFIXES = load_codebase()


def extract_claims(submission: dict) -> list[str]:
    text = " \n".join(str(submission.get(k, "")) for k in
                      ("title", "description", "steps_to_reproduce", "impact"))
    parts = re.split(r"(?<=[.!?])\s+|\n+", text)
    claims = []
    for p in parts:
        p = p.strip()
        if len(p) < 15:
            continue
        low = p.lower()
        if (any(h in low for h in SECURITY_HINTS)
                or SYM_CALL_RE.search(p) or BACKTICK_RE.search(p) or CVE_RE.search(p)):
            claims.append(p)
    if not claims:
        claims = [text.strip()[:300]] if text.strip() else []
    return claims[:8]


def _symbols_in(claim: str) -> list[str]:
    found = {m.group(1) for m in SYM_CALL_RE.finditer(claim)}
    found |= {m.group(1).lower() for m in BACKTICK_RE.finditer(claim)}
    return sorted(found)


def assess(submission: dict, corroboration: dict) -> dict:
    """Return per-claim verdicts + an aggregate reliability score + a hint."""
    claims_out = []
    for claim in extract_claims(submission):
        status, kind, evidence = "unverifiable", "", "no checkable, ground-truthable assertion"
        for sym in _symbols_in(claim):
            if sym in _SYMBOLS:
                status, kind, evidence = "supported", "code", f"`{sym}` exists in the codebase"
                break
            if any(sym.startswith(p) for p in _PREFIXES):
                status, kind, evidence = ("refuted", "code",
                                          f"`{sym}` is not present in the codebase (likely fabricated)")
                break
        if status == "unverifiable":
            cves = CVE_RE.findall(claim)
            if cves and corroboration.get("matched"):
                status, kind, evidence = "supported", "feed", f"{cves[0].upper()} confirmed by threat-intel feed"
            elif corroboration.get("matched") and any(
                    (p.get("name") or "").lower() in claim.lower()
                    for p in corroboration.get("packages", [])):
                status, kind, evidence = "supported", "feed", "package vuln confirmed by OSV/feed"
        claims_out.append({"claim": claim[:240], "status": status, "kind": kind, "evidence": evidence})

    n_sup = sum(c["status"] == "supported" for c in claims_out)
    n_ref = sum(c["status"] == "refuted" for c in claims_out)
    n_unv = sum(c["status"] == "unverifiable" for c in claims_out)
    total = max(1, len(claims_out))
    # CLR-style: reward supported, punish refuted hard.
    reliability = round(max(0.0, (n_sup - 1.5 * n_ref)) / total, 2)

    hint = None
    if n_ref > 0 and n_sup == 0:
        hint = "fabricated"          # references symbols that don't exist -> slop
    elif n_sup > 0 and corroboration.get("matched"):
        hint = "corroborated"

    return {
        "claims": claims_out,
        "n_supported": n_sup,
        "n_refuted": n_ref,
        "n_unverifiable": n_unv,
        "reliability": reliability,
        "hint": hint,
    }

"""Platform-agnostic ingestion: make the triage sidecar usable by ANY analyst,
on ANY bug-bounty platform.

Different platforms expose reports with different field names and payload shapes
(HackerOne, Bugcrowd, Intigriti, YesWeHack, internal VDPs, plain email). This
module normalizes any of them - or a block of pasted free text - into the one
canonical submission shape the triage engine understands:

    {title, severity_claimed, asset, description, steps_to_reproduce, impact}

So the same model + defense harness sits as a "sidecar" next to whatever queue
the analyst already lives in, instead of forcing them onto a new platform.
"""
from __future__ import annotations

import re

CANONICAL = ("title", "severity_claimed", "asset", "description",
             "steps_to_reproduce", "impact")

# Map the many field names platforms/exports use onto our canonical fields.
FIELD_ALIASES = {
    "title": ["title", "name", "summary", "subject", "report_title", "headline"],
    "severity_claimed": ["severity_claimed", "severity", "severity_rating",
                          "vulnerability_severity", "rating", "cvss_severity",
                          "priority", "criticality"],
    "asset": ["asset", "asset_identifier", "target", "scope", "structured_scope",
              "affected_asset", "domain", "host", "url", "endpoint", "bug_url",
              "affected_url", "location"],
    "description": ["description", "details", "vulnerability_information",
                    "writeup", "body", "summary_details", "bug_description",
                    "vulnerability_details"],
    "steps_to_reproduce": ["steps_to_reproduce", "steps", "reproduction_steps",
                           "repro", "poc", "proof_of_concept",
                           "steps_to_reproduce_the_issue", "how_to_reproduce"],
    "impact": ["impact", "business_impact", "security_impact", "consequences",
               "impact_details"],
    "reporter": ["reporter", "researcher", "submitter", "username", "author",
                 "hacker", "reported_by"],
}

# Heuristic platform fingerprints from payload keys.
PLATFORM_SIGNATURES = {
    "hackerone": {"structured_scope", "vulnerability_information", "weakness", "bounty"},
    "bugcrowd": {"vrt", "priority", "bug_url", "submission"},
    "intigriti": {"domain", "endpoint", "programId", "type", "cvss"},
    "yeswehack": {"bug_type", "scope", "cvss_vector", "report_id"},
}


def _get_alias(d: dict, field: str):
    low = {str(k).lower(): v for k, v in d.items()}
    for alias in FIELD_ALIASES.get(field, []):
        if alias in low and low[alias] not in (None, ""):
            return low[alias]
    return None


def _stringify(v) -> str:
    if v is None:
        return ""
    if isinstance(v, (list, tuple)):
        return ", ".join(_stringify(x) for x in v)
    if isinstance(v, dict):
        # common nested shapes: {"asset_identifier": "..."} / {"name": "..."}
        for k in ("asset_identifier", "username", "handle", "name", "value",
                  "url", "email", "id"):
            if k in v:
                return _stringify(v[k])
        return ", ".join(f"{k}={_stringify(val)}" for k, val in v.items())
    return str(v)


def detect_platform(payload: dict) -> str:
    keys = {str(k).lower() for k in payload}
    best, score = "generic", 0
    for name, sig in PLATFORM_SIGNATURES.items():
        s = len(keys & {x.lower() for x in sig})
        if s > score:
            best, score = name, s
    return best if score else "generic"


def normalize(payload: dict, platform: str | None = None) -> dict:
    """Normalize any platform payload -> {submission, platform, reporter}."""
    platform = platform or detect_platform(payload)
    sub = {}
    for field in CANONICAL:
        sub[field] = _stringify(_get_alias(payload, field))
    reporter = _stringify(_get_alias(payload, "reporter")) or "external_researcher"
    if not sub["title"]:
        sub["title"] = (sub["description"][:80] or "Untitled report").strip()
    return {"submission": sub, "platform": platform, "reporter": reporter}


# --- free-text / pasted-report parsing --------------------------------------
# Analysts can paste a raw report (markdown/email/plain) copied from any portal.
_SECTION_PATTERNS = {
    "steps_to_reproduce": r"(steps\s*to\s*reproduce|reproduction|repro steps|poc|proof[\s-]*of[\s-]*concept)",
    "impact": r"(impact|business impact|security impact|consequence)",
    "description": r"(description|summary|details|overview|vulnerability)",
}
_SEV_RE = re.compile(r"\b(critical|high|medium|low|informational|info|none)\b", re.I)
_ASSET_RE = re.compile(r"\b((?:https?://)?[a-z0-9.-]+\.[a-z]{2,}(?:/[^\s)]*)?)", re.I)
_HEADING_RE = re.compile(r"^\s*#{0,4}\s*\**\s*([A-Za-z][A-Za-z /._-]{2,40})\s*\**\s*:?\s*$")


def parse_text(raw: str) -> dict:
    """Best-effort parse of a pasted report into the canonical submission."""
    raw = (raw or "").strip()
    lines = raw.splitlines()
    title = ""
    for ln in lines:
        s = ln.strip().lstrip("#").strip()
        if s:
            title = re.sub(r"^(title|report)\s*:?\s*", "", s, flags=re.I)[:160]
            break

    # Split into sections by headings.
    sections: dict[str, list[str]] = {"_pre": []}
    current = "_pre"
    for ln in lines:
        m = _HEADING_RE.match(ln)
        if m:
            head = m.group(1).lower()
            matched = None
            for canon, pat in _SECTION_PATTERNS.items():
                if re.search(pat, head):
                    matched = canon
                    break
            current = matched or "_other_" + head
            sections.setdefault(current, [])
            continue
        sections.setdefault(current, []).append(ln)

    def sec(name: str) -> str:
        return "\n".join(sections.get(name, [])).strip()

    body = sec("_pre")
    description = sec("description") or body or raw[:1200]
    steps = sec("steps_to_reproduce")
    impact = sec("impact")

    sev_m = _SEV_RE.search(raw)
    severity = sev_m.group(1).title() if sev_m else "Unknown"
    asset_m = _ASSET_RE.search(raw)
    asset = asset_m.group(1) if asset_m else ""

    return {
        "submission": {
            "title": title or "Pasted report",
            "severity_claimed": severity,
            "asset": asset,
            "description": description,
            "steps_to_reproduce": steps,
            "impact": impact,
        },
        "platform": "paste",
        "reporter": "pasted_by_analyst",
    }

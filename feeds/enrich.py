#!/usr/bin/env python3
"""Corroborate a bug bounty submission against external threat-intel sources.

Given a submission, extract entities (CVE ids, GHSA ids, package@version) and
check them against:
  - local cache : CISA KEV (actively exploited), NVD recent, GHSA recent
  - live         : OSV.dev (per-package vuln lookup, covers npm/PyPI/etc + GHSA)

Returns an `external_corroboration` object the triage model can reason over, so
a flood of genuine reports about a freshly disclosed library CVE is NOT mistaken
for spam/duplicates.

CLI (enrich every row of a JSONL and print a summary):
  python feeds/enrich.py --data data/seed_examples.jsonl
  python feeds/enrich.py --data data/incoming.jsonl --out data/incoming.enriched.jsonl
"""
import argparse
import datetime as dt
import json
import pathlib
import re
import urllib.request

HERE = pathlib.Path(__file__).parent
CACHE = HERE / "cache"

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
GHSA_RE = re.compile(r"\bGHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}\b", re.I)
# package@version, npm-style incl. scoped (@scope/name@1.2.3)
PKG_AT_VER_RE = re.compile(r"(?P<name>@?[a-z0-9][a-z0-9._-]*(?:/[a-z0-9._-]+)?)@(?P<ver>\d+\.\d+(?:\.\d+)?[\w.+-]*)", re.I)

RECENCY_DAYS = 30
OSV_QUERY = "https://api.osv.dev/v1/query"
UA = {"User-Agent": "bb-triage-enrich/1.0"}

# Optional: extend this with packages your org actually ships, to catch
# bare mentions ("vulnerability in lodash") with no explicit version.
WATCHLIST = {
    "lodash", "express", "react", "next", "axios", "moment", "jquery",
    "minimist", "node-fetch", "ws", "vue", "webpack", "babel", "left-pad",
}


def _load(name):
    p = CACHE / name
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            return {}
    return {}


def _osv_lookup(name, ecosystem="npm", version=None, timeout=20):
    pkg = {"name": name, "ecosystem": ecosystem}
    body = {"package": pkg}
    if version:
        body["version"] = version
    req = urllib.request.Request(
        OSV_QUERY, data=json.dumps(body).encode(), method="POST",
        headers={**UA, "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read()).get("vulns", [])
    except Exception:  # noqa: BLE001
        return []


def _is_recent(iso, days=RECENCY_DAYS):
    if not iso:
        return False
    try:
        ts = dt.datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return False
    return (dt.datetime.now(dt.timezone.utc) - ts).days <= days


def submission_text(sub: dict) -> str:
    return " \n".join(str(sub.get(k, "")) for k in
                      ("title", "description", "steps_to_reproduce", "impact", "asset"))


def enrich(submission: dict, use_osv: bool = True) -> dict:
    text = submission_text(submission)
    cve_ids = sorted({m.upper() for m in CVE_RE.findall(text)})
    ghsa_ids = sorted({m.upper() for m in GHSA_RE.findall(text)})

    packages = []
    seen = set()
    for m in PKG_AT_VER_RE.finditer(text):
        key = (m.group("name").lower(), m.group("ver"))
        if key not in seen:
            seen.add(key)
            packages.append({"name": m.group("name"), "version": m.group("ver")})
    for w in WATCHLIST:
        if re.search(rf"\b{re.escape(w)}\b", text, re.I) and not any(p["name"].lower() == w for p in packages):
            packages.append({"name": w, "version": None})

    kev = _load("kev.json").get("by_cve", {})
    nvd = _load("nvd_recent.json").get("by_cve", {})
    ghsa_cache = _load("ghsa_recent.json").get("by_ghsa", {})

    sources = []
    in_kev = False
    pub_dates = []

    for cve in cve_ids:
        if cve in kev:
            in_kev = True
            k = kev[cve]
            sources.append({"type": "KEV", "cve": cve, "date_added": k["date_added"],
                            "ransomware": k["ransomware"], "name": k["name"]})
        if cve in nvd:
            n = nvd[cve]
            pub_dates.append(n["published"])
            sources.append({"type": "NVD", "cve": cve, "published": n["published"],
                            "summary": n["description"][:200]})

    for gid in ghsa_ids:
        if gid in ghsa_cache:
            g = ghsa_cache[gid]
            pub_dates.append(g["published"])
            sources.append({"type": "GHSA", "ghsa": gid, "published": g["published"],
                            "severity": g["severity"], "summary": g["summary"][:200]})

    if use_osv:
        for p in packages:
            vulns = _osv_lookup(p["name"], "npm", p["version"])
            for v in vulns[:3]:
                aliases = v.get("aliases", [])
                pub = v.get("published", "")
                if pub:
                    pub_dates.append(pub)
                # KEV escalation via OSV's CVE aliases
                for a in aliases:
                    if a.upper() in kev:
                        in_kev = True
                sources.append({
                    "type": "OSV", "package": p["name"], "version": p["version"],
                    "id": v.get("id", ""), "aliases": aliases[:4],
                    "published": pub, "summary": (v.get("summary") or "")[:200],
                })

    most_recent = max(pub_dates) if pub_dates else None
    matched = bool(sources)
    recent = any(_is_recent(d) for d in pub_dates)

    return {
        "matched": matched,
        "in_kev": in_kev,
        "recent": recent,
        "most_recent_publication": most_recent,
        "cve_ids": cve_ids,
        "ghsa_ids": ghsa_ids,
        "packages": packages,
        "sources": sources[:12],
    }


def format_for_prompt(corr: dict) -> str:
    """Render corroboration as a compact block to inject into the triage prompt."""
    if not corr.get("matched"):
        return "EXTERNAL CORROBORATION: none found (no matching CVE/advisory/package)."
    lines = ["EXTERNAL CORROBORATION: MATCH FOUND."]
    lines.append(f"- actively_exploited (CISA KEV): {corr['in_kev']}")
    lines.append(f"- recently_published (<= {RECENCY_DAYS}d): {corr['recent']}"
                 f" (latest {corr.get('most_recent_publication')})")
    if corr["cve_ids"]:
        lines.append(f"- CVEs cited/matched: {', '.join(corr['cve_ids'])}")
    if corr["ghsa_ids"]:
        lines.append(f"- GHSA cited: {', '.join(corr['ghsa_ids'])}")
    for s in corr["sources"][:6]:
        if s["type"] == "OSV":
            lines.append(f"- OSV {s['id']} for {s['package']}@{s.get('version')} "
                         f"(aliases {s.get('aliases')}, published {s.get('published')})")
        elif s["type"] == "KEV":
            lines.append(f"- KEV {s['cve']} added {s['date_added']} ransomware={s['ransomware']}")
        elif s["type"] == "NVD":
            lines.append(f"- NVD {s['cve']} published {s['published']}")
        elif s["type"] == "GHSA":
            lines.append(f"- GHSA {s['ghsa']} ({s['severity']}) published {s['published']}")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--out", default=None)
    ap.add_argument("--no-osv", action="store_true")
    args = ap.parse_args()

    rows = [json.loads(l) for l in
            pathlib.Path(args.data).read_text(encoding="utf-8").splitlines() if l.strip()]
    out = open(args.out, "w", encoding="utf-8") if args.out else None
    n_match = 0
    for row in rows:
        corr = enrich(row["submission"], use_osv=not args.no_osv)
        row["external_corroboration"] = corr
        if corr["matched"]:
            n_match += 1
        flag = "MATCH" if corr["matched"] else "  -  "
        kev = " KEV!" if corr["in_kev"] else ""
        print(f"[{flag}{kev}] {row.get('id','?'):<14} "
              f"cve={corr['cve_ids']} pkgs={[p['name'] for p in corr['packages']]}")
        if out:
            out.write(json.dumps(row, ensure_ascii=False) + "\n")
    if out:
        out.close()
        print(f"\nwrote enriched -> {args.out}")
    print(f"\n{n_match}/{len(rows)} submissions had external corroboration")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Refresh the local threat-intel cache used to corroborate bug bounty reports.

Pulls (all anonymous / no account required):
  - CISA KEV    : full catalog of actively-exploited CVEs
  - NVD         : CVEs published in the last --days window (recent disclosures)
  - GHSA (opt)  : recent GitHub advisories, if --github-token is provided

Per-package lookups (e.g. "is left-pad@1.3.0 vulnerable?") are done live in
enrich.py via OSV.dev, so they are not cached here.

Usage:
  python feeds/fetch_feeds.py --days 14
  python feeds/fetch_feeds.py --days 30 --github-token ghp_xxx
"""
import argparse
import datetime as dt
import json
import pathlib
import time
import urllib.parse
import urllib.request

HERE = pathlib.Path(__file__).parent
CACHE = HERE / "cache"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GHSA_GRAPHQL = "https://api.github.com/graphql"

UA = {"User-Agent": "bb-triage-feeds/1.0"}


def _get(url, headers=None, timeout=60, retries=3, backoff=8):
    last = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={**UA, **(headers or {})})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read())
        except Exception as e:  # noqa: BLE001
            last = e
            if attempt < retries - 1:
                time.sleep(backoff * (attempt + 1))
    raise last


def fetch_kev() -> dict:
    raw = _get(KEV_URL)
    by_cve = {}
    for v in raw.get("vulnerabilities", []):
        by_cve[v["cveID"].upper()] = {
            "cve": v["cveID"].upper(),
            "name": v.get("vulnerabilityName", ""),
            "vendor": v.get("vendorProject", ""),
            "product": v.get("product", ""),
            "date_added": v.get("dateAdded", ""),
            "ransomware": v.get("knownRansomwareCampaignUse", "Unknown"),
        }
    return {
        "catalog_version": raw.get("catalogVersion", ""),
        "count": len(by_cve),
        "by_cve": by_cve,
    }


def fetch_nvd_recent(days: int) -> dict:
    end = dt.datetime.now(dt.timezone.utc)
    start = end - dt.timedelta(days=days)
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    by_cve = {}
    start_index = 0
    # NVD: <=2000 results/page; unauthenticated rate limit ~5 req / 30s.
    while True:
        params = urllib.parse.urlencode({
            "pubStartDate": start.strftime(fmt),
            "pubEndDate": end.strftime(fmt),
            "resultsPerPage": 2000,
            "startIndex": start_index,
        })
        data = _get(f"{NVD_URL}?{params}")
        vulns = data.get("vulnerabilities", [])
        for item in vulns:
            cve = item.get("cve", {})
            cid = cve.get("id", "").upper()
            if not cid:
                continue
            descs = cve.get("descriptions", [])
            desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")
            keywords = set()
            for cfg in cve.get("configurations", []):
                for node in cfg.get("nodes", []):
                    for m in node.get("cpeMatch", []):
                        # cpe:2.3:a:vendor:product:version:...
                        parts = m.get("criteria", "").split(":")
                        if len(parts) > 4:
                            keywords.update(p for p in parts[3:5] if p not in ("*", "-", ""))
            by_cve[cid] = {
                "cve": cid,
                "published": cve.get("published", ""),
                "description": desc[:500],
                "keywords": sorted(keywords),
            }
        total = data.get("totalResults", 0)
        start_index += len(vulns)
        if start_index >= total or not vulns:
            break
        time.sleep(6)  # stay under unauthenticated rate limit
    return {"window_days": days, "count": len(by_cve), "by_cve": by_cve}


def fetch_ghsa_recent(token: str, days: int, limit: int = 200) -> dict:
    query = """
    query($first:Int!){
      securityAdvisories(first:$first, orderBy:{field:PUBLISHED_AT,direction:DESC}){
        nodes{ ghsaId summary severity publishedAt
          identifiers{ type value }
          vulnerabilities(first:10){ nodes{ package{ ecosystem name } } } }
      }
    }"""
    body = json.dumps({"query": query, "variables": {"first": min(limit, 100)}}).encode()
    req = urllib.request.Request(
        GHSA_GRAPHQL, data=body, method="POST",
        headers={**UA, "Authorization": f"bearer {token}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=60) as r:
        data = json.loads(r.read())
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)
    by_ghsa = {}
    for n in data.get("data", {}).get("securityAdvisories", {}).get("nodes", []):
        pub = n.get("publishedAt", "")
        try:
            if dt.datetime.fromisoformat(pub.replace("Z", "+00:00")) < cutoff:
                continue
        except ValueError:
            pass
        pkgs = [
            {"ecosystem": v["package"]["ecosystem"], "name": v["package"]["name"]}
            for v in n.get("vulnerabilities", {}).get("nodes", [])
            if v.get("package")
        ]
        by_ghsa[n["ghsaId"]] = {
            "ghsa": n["ghsaId"],
            "summary": n.get("summary", ""),
            "severity": n.get("severity", ""),
            "published": pub,
            "aliases": [i["value"] for i in n.get("identifiers", []) if i["type"] == "CVE"],
            "packages": pkgs,
        }
    return {"window_days": days, "count": len(by_ghsa), "by_ghsa": by_ghsa}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=14)
    ap.add_argument("--github-token", default=None)
    ap.add_argument("--skip-nvd", action="store_true")
    args = ap.parse_args()

    CACHE.mkdir(parents=True, exist_ok=True)
    meta = {"refreshed_at": dt.datetime.now(dt.timezone.utc).isoformat()}

    print("[kev] downloading CISA KEV catalog ...")
    kev = fetch_kev()
    (CACHE / "kev.json").write_text(json.dumps(kev), encoding="utf-8")
    meta["kev_count"] = kev["count"]
    print(f"[kev] {kev['count']} CVEs (catalog {kev['catalog_version']})")

    if not args.skip_nvd:
        print(f"[nvd] downloading CVEs published in last {args.days} days ...")
        try:
            nvd = fetch_nvd_recent(args.days)
            (CACHE / "nvd_recent.json").write_text(json.dumps(nvd), encoding="utf-8")
            meta["nvd_count"] = nvd["count"]
            print(f"[nvd] {nvd['count']} recent CVEs")
        except Exception as e:  # noqa: BLE001 - NVD is flaky; degrade gracefully
            meta["nvd_error"] = str(e)
            print(f"[nvd] WARNING: skipped (NVD unreachable/throttled): {e}\n"
                  f"      KEV + OSV.dev still provide corroboration. Retry later or "
                  f"use --skip-nvd, optionally with an NVD API key for reliability.")

    if args.github_token:
        print("[ghsa] downloading recent GitHub advisories ...")
        ghsa = fetch_ghsa_recent(args.github_token, args.days)
        (CACHE / "ghsa_recent.json").write_text(json.dumps(ghsa), encoding="utf-8")
        meta["ghsa_count"] = ghsa["count"]
        print(f"[ghsa] {ghsa['count']} recent advisories")
    else:
        print("[ghsa] skipped (no --github-token). OSV.dev still covers GHSA at lookup time.")

    (CACHE / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"[done] cache written to {CACHE}")


if __name__ == "__main__":
    main()

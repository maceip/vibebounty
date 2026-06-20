"""Validate platform-agnostic normalization + paste parsing."""
from app import connectors

# HackerOne-shaped payload
h1 = {
    "title": "IDOR in invoice download",
    "vulnerability_information": "acme_invoice_get() lacks an ownership check.",
    "severity": "high",
    "structured_scope": {"asset_identifier": "api.acme.com"},
    "weakness": "IDOR",
    "reporter": {"username": "recon_raj"},
    "impact": "Cross-tenant invoice disclosure.",
}
# Bugcrowd-shaped payload
bc = {
    "submission": "Stored XSS in profile name",
    "priority": "P2",
    "bug_url": "https://app.example.com/profile",
    "vrt": "xss.stored",
    "description": "Payload <script> persists and executes for other users.",
}

print("=== detect + normalize ===")
for name, p in (("hackerone", h1), ("bugcrowd", bc)):
    n = connectors.normalize(p)
    print(f"[{name}] detected={n['platform']} reporter={n['reporter']}")
    for k, v in n["submission"].items():
        print(f"    {k:20} {str(v)[:70]}")

print("\n=== paste parse ===")
raw = """Title: SSRF in webhook validator
Severity: High
Asset: https://api.example.com/webhooks

Description:
The webhook URL validator can be bypassed to reach internal metadata.

Steps to reproduce:
1. Set webhook to http://169.254.169.254/latest/meta-data/
2. Trigger validation

Impact:
Read cloud instance credentials (SSRF -> credential theft)."""
parsed = connectors.parse_text(raw)
print(f"platform={parsed['platform']}")
for k, v in parsed["submission"].items():
    print(f"    {k:20} {str(v)[:80]}")

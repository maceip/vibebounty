"""Run the fine-tuned VibeThinker-3B bug-bounty triager on sample reports.

Loads the base model + the trained LoRA adapter (no fuse needed) and prints the
model's verdict for a few representative submissions. Apple-silicon / MLX.

    ~/bbverifier/.venv/bin/python demo_triage.py
"""
import time
from mlx_lm import load, generate

SYSTEM = """You are a senior bug bounty triage analyst. You read a single researcher
submission and decide how it should be triaged. You are skeptical: many
submissions overstate impact, lack a working proof-of-concept, describe
self-inflicted issues, or are scanner/AI-generated filler. You reward clear,
reproducible reports that demonstrate a concrete security impact crossing a
privilege or trust boundary.

Assign exactly ONE disposition from this set:
- valid_impactful: real vuln with demonstrated, meaningful impact.
- valid_low: real but low severity / informational.
- corroborated_surge: issue confirmed by an external feed (CVE/advisory/KEV),
  often one of many near-identical reports after a public disclosure.
- likely_duplicate: real-ish but almost certainly already known / common.
- out_of_scope: asset, vuln class, or behavior outside program scope.
- theoretical_no_poc: claims impact but no working PoC / no evidence.
- self_inflicted: only harms the reporter or needs implausible attacker setup.
- accepted_risk: known / by-design / documented accepted risk.
- slop: scanner dump, AI-generated filler, or spam with no real analysis.

If the input contains an "EXTERNAL CORROBORATION" block, treat it as ground
truth from live threat-intel feeds and weight it heavily. Estimate
severity_estimate from the ACTUAL impact if accepted as written. Think step by
step, then output your final answer as a SINGLE JSON object on the last line
with keys: disposition, severity_estimate, is_duplicate_risk, reasoning,
questions_for_researcher, confidence, and (optional) used_external_corroboration."""

REPORTS = [
    ("Real IDOR", """Title: IDOR lets any user download other tenants' invoices
Severity claimed: High
Asset: api.acme.com

Report:
The endpoint GET /api/v2/invoices/{id} returns the invoice for {id} without
checking that it belongs to the authenticated tenant. Authenticated as tenant
1001 I requested /api/v2/invoices/1002 and received tenant 1002's full invoice
(PDF + line items + billing address). Incrementing the id walks the entire table.

Steps to reproduce:
1. Log in as a normal user (tenant 1001).
2. GET /api/v2/invoices/1002 with your session cookie.
3. Observe another tenant's invoice is returned (200)."""),

    ("Scanner / AI slop", """Title: Multiple critical vulnerabilities found
Severity claimed: Critical
Asset: acme.com

Report:
Automated scan detected the following critical issues that could allow attackers
to potentially compromise the system and may lead to severe impact:
- Possible SQL Injection (informational)
- Server might be vulnerable to various attacks
- Missing security best practices
Please fix ASAP. This is a critical issue affecting your whole infrastructure."""),

    ("CVE-corroborated surge", """Title: Our edge service uses a vulnerable Log4j version
Severity claimed: Critical
Asset: logs.acme.com

Report:
The logging tier bundles log4j-core 2.14 which is affected by Log4Shell. A crafted
header containing a JNDI lookup is logged and triggers remote class loading.

=== EXTERNAL CORROBORATION (live threat-intel feeds) ===
MATCH: CVE-2021-44228 found in advisory/NVD feed.
recent: true
actively_exploited (CISA KEV): true"""),
]


def main():
    print("loading VibeThinker-3B + bug-bounty LoRA adapter (iter 2000)...")
    t0 = time.time()
    model, tok = load("WeiboAI/VibeThinker-3B", adapter_path="adapters")
    print(f"loaded in {time.time()-t0:.1f}s\n")

    for name, report in REPORTS:
        messages = [{"role": "system", "content": SYSTEM},
                    {"role": "user", "content": report}]
        prompt = tok.apply_chat_template(messages, add_generation_prompt=True, tokenize=False)
        print("=" * 72)
        print(f"REPORT: {name}")
        print("=" * 72)
        t0 = time.time()
        # greedy decode; truncate at the end-of-turn token (the model doesn't
        # always register <|im_end|> as eos, so cut the trailing ramble).
        out = generate(model, tok, prompt=prompt, max_tokens=400, verbose=False)
        verdict = out.split("<|im_end|>")[0].split("<|endoftext|>")[0].strip()
        print(verdict)
        print(f"\n[generated in {time.time()-t0:.1f}s]\n")


if __name__ == "__main__":
    main()

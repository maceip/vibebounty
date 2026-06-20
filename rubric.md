# Bug Bounty Triage Rubric (Step 0)

This rubric is the *spec* for the triage model. It defines what counts as
"interesting / valid" vs "bullshit / not interesting." The model's job is to
read a single submission and assign exactly one `disposition`, estimate
severity, flag duplicate risk, and justify it.

## Disposition taxonomy (the label set)

| disposition          | meaning                                                                 |
|----------------------|-------------------------------------------------------------------------|
| `valid_impactful`    | Real vulnerability with a demonstrated, meaningful security impact.     |
| `valid_low`          | Real issue but low severity / informational (best-practice, hardening). |
| `corroborated_surge` | Real issue confirmed by an external feed (CVE/advisory/KEV); often one of many near-identical reports after a public disclosure. |
| `likely_duplicate`   | Real-ish but almost certainly already known / commonly reported.        |
| `out_of_scope`       | Target asset, vuln class, or behavior is outside the program scope.     |
| `theoretical_no_poc` | Claims impact but provides no working proof-of-concept / no evidence.   |
| `self_inflicted`     | "Vuln" only harms the reporter themselves or needs implausible setup.   |
| `accepted_risk`      | Known/by-design behavior or documented accepted risk.                   |
| `slop`               | Scanner dump, AI-generated filler, or spam with no real analysis.       |

Exactly one disposition per submission. When two could apply, pick the one that
most determines the triage *decision* (e.g. a self-XSS that is also low severity
is `self_inflicted`, because that is why you reject it).

## Severity estimate

`critical | high | medium | low | none`

Estimate the *actual* impact if the finding were accepted as written — not the
severity the reporter claimed. A mismatch between claimed and estimated severity
is itself a strong signal of `slop` / `theoretical_no_poc` / `self_inflicted`.

## Duplicate risk

`is_duplicate_risk: true` when the issue is a high-frequency, commonly reported
class on common endpoints (e.g. login rate-limiting, missing security headers,
SPF/DMARC, clickjacking on non-sensitive pages). This is a heuristic flag, not a
claim that a specific prior report exists.

## Red flags for BS / non-interesting submissions

The model should weight these heavily toward `slop`, `theoretical_no_poc`,
`self_inflicted`, or `accepted_risk`:

- Severity claimed (e.g. "Critical / P1") with no working PoC or no real impact.
- PoC requires the victim to paste code into their own console (self-XSS).
- "CSRF" on actions with no security consequence (e.g. logout, theme toggle).
- Raw scanner output (nuclei/nmap/Burp) pasted with no human analysis.
- Generic, templated prose that never references the actual target behavior.
- "Could allow an attacker to..." with no demonstration that it actually does.
- Missing rate limit reported as "DoS" on a non-sensitive, non-auth endpoint.
- Clickjacking / missing headers framed as high severity.
- Requires an attacker who already has MITM / already has the victim's session.

## What "interesting" looks like (bias toward `valid_*`)

- Clear, reproducible steps that a triager could follow.
- A concrete impact crossing a privilege or trust boundary
  (another user's data, server-side execution, auth bypass, etc.).
- Evidence: request/response, screenshots, a working payload, IDs that differ.

## External corroboration (overrides the BS red flags)

Some submissions arrive with an `EXTERNAL CORROBORATION` block produced by
`feeds/enrich.py`, which checks the report's CVEs / GHSA ids / packages against
live threat-intel sources (CISA KEV, NVD, OSV.dev/GHSA). This is a *grounded*
signal and takes precedence over surface-level BS heuristics:

- If corroboration `matched` is true AND the disclosure is `recent`, the report
  is about a genuinely known issue. It MUST NOT be labeled `slop` or
  `theoretical_no_poc` on the grounds of "looks generic / no PoC" — the external
  feed is the proof. Prefer `corroborated_surge` (or `valid_*` if the single
  report itself clearly demonstrates impact).
- This is the anti-false-negative guard for the classic scenario: a CVE drops in
  a popular library and hundreds of legitimate reports flood in at once. They are
  duplicates *of each other*, but they are real — triage them seriously, dedupe
  for payout, never trash them as spam.
- `in_kev` (actively exploited per CISA KEV) is an escalation signal: raise
  severity/priority accordingly.
- Corroboration does NOT save a report that is out of scope, self-inflicted, or
  describes a different issue than the one the feed matched. Use judgment.

When corroboration influenced the verdict, set
`used_external_corroboration: true`.

## Output

The model must emit reasoning, then a single JSON object conforming to
`schema.json`. See `prompts/triage_system.txt`.

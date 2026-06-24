// VibeBounty static console — runs the triage MODEL in the browser (WebGPU)
// or against a local OpenAI-compatible endpoint (MLX / Ollama / vLLM).
// The deterministic defense layer (claim verification + threat-intel
// corroboration) is ported from the Python app and ALWAYS applied on top of
// the model's verdict, so an adversary can't flip it with prose.
import * as webllm from "https://esm.run/@mlc-ai/web-llm@0.2.84";
import { enrich, assess, heuristic, normalizeVerdict, extractJson, applyDefenses,
         SYSTEM, GUARD, corrBlock, renderUser } from "./engine.mjs";

/* ============================ data ============================ */
const SEEDS = [
  {title:"IDOR: download any user's invoice PDF via sequential id", severity_claimed:"High", asset:"api.example.com", description:"The endpoint GET /api/v1/invoices/{id}/pdf returns the invoice for any id without checking ownership. Invoice ids are sequential integers.", steps_to_reproduce:"1. Log in as user A, open my invoice at /api/v1/invoices/48213/pdf. 2. Decrement id to 48212, 48211. 3. Each request returns another customer's invoice PDF with name, address, line items. Attached: two PDFs belonging to other accounts plus the raw HTTP requests showing only my own session cookie.", impact:"Any authenticated user can enumerate and download every customer's invoices (PII + purchase history)."},
  {title:"Stored XSS in display name renders on every viewer's dashboard", severity_claimed:"High", asset:"app.example.com", description:"Setting display name to <img src=x onerror=alert(document.domain)> stores it unsanitized. It executes for any user who views the team members list.", steps_to_reproduce:"1. Profile > display name = <img src=x onerror=alert(document.domain)>. 2. Save. 3. Have a second account open /team. 4. Alert fires in the second account's session. Screenshot + HAR attached.", impact:"Cross-user script execution in authenticated context; can hijack sessions of teammates/admins who view the list."},
  {title:"SSRF in URL preview reaches cloud metadata endpoint", severity_claimed:"Critical", asset:"app.example.com", description:"The link-preview feature fetches arbitrary URLs server-side. Supplying http://169.254.169.254/latest/meta-data/iam/security-credentials/ returns IAM role credentials in the preview body.", steps_to_reproduce:"1. Paste http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name into a comment. 2. The rendered preview contains AccessKeyId/SecretAccessKey/Token. Redacted screenshot + raw response attached.", impact:"Server-side request forgery exposing cloud IAM credentials, enabling pivot into the account's cloud environment."},
  {title:"Verbose stack trace on malformed JSON reveals framework versions", severity_claimed:"Medium", asset:"api.example.com", description:"POSTing malformed JSON to /api/v1/orders returns a 500 with a full stack trace including framework and library versions and internal file paths.", steps_to_reproduce:"1. curl -X POST /api/v1/orders -d '{bad'. 2. Response body contains stack trace, version strings, and /srv/app/... paths.", impact:"Information disclosure that could aid an attacker in fingerprinting the stack."},
  {title:"Missing security headers (CSP, X-Frame-Options, HSTS)", severity_claimed:"Medium", asset:"www.example.com", description:"The marketing site does not set Content-Security-Policy, X-Frame-Options, or Strict-Transport-Security headers.", steps_to_reproduce:"1. curl -I https://www.example.com. 2. Note absent headers. nuclei output attached.", impact:"Lack of defense-in-depth headers."},
  {title:"No rate limiting on /login allows brute force", severity_claimed:"High", asset:"app.example.com", description:"The login endpoint accepts unlimited password attempts with no lockout or rate limit.", steps_to_reproduce:"1. Send 500 login attempts with Burp Intruder. 2. All return 200 with no throttling.", impact:"Credential brute force / account takeover possible."},
  {title:"XSS on partner blog hosted at blog.partner-thirdparty.com", severity_claimed:"High", asset:"blog.partner-thirdparty.com", description:"Reflected XSS in the search parameter of the partner blog.", steps_to_reproduce:"1. Visit blog.partner-thirdparty.com/?q=<script>alert(1)</script>. 2. Script executes.", impact:"XSS on a domain linked from the main site."},
  {title:"Critical SQL injection in product search", severity_claimed:"Critical", asset:"app.example.com", description:"The search box is likely vulnerable to SQL injection because it talks to a database. An attacker could dump all tables.", steps_to_reproduce:"Search for a product. The results come from a database, so SQLi is probably possible.", impact:"Full database compromise."},
  {title:"Account takeover via XSS (PoC included)", severity_claimed:"Critical", asset:"app.example.com", description:"I can run JavaScript in my account by pasting code into the browser developer console, proving XSS and full account takeover.", steps_to_reproduce:"1. Open DevTools console. 2. Paste document.cookie and the provided fetch() snippet. 3. It runs and exfiltrates my own cookie.", impact:"Full account takeover via arbitrary JavaScript execution."},
  {title:"CSRF on logout endpoint", severity_claimed:"Medium", asset:"app.example.com", description:"The /logout endpoint has no CSRF token, so an attacker can forcibly log a user out.", steps_to_reproduce:"1. Host a page with an auto-submitting form/img to /logout. 2. Victim visits, gets logged out.", impact:"Attacker can log victims out (denial of service)."},
  {title:"Multiple critical vulnerabilities found", severity_claimed:"Critical", asset:"example.com", description:"[*] nuclei results:\n[ssl-dns-names] example.com\n[http-missing-security-headers] example.com\n[tech-detect:nginx] example.com\nPlease fix these critical issues ASAP.", steps_to_reproduce:"Run nuclei -u https://example.com.", impact:"Various."},
  {title:"Security vulnerability in your website", severity_claimed:"Critical", asset:"example.com", description:"Dear team, I am a security researcher. I found a critical vulnerability that could allow attackers to compromise your system and steal user data. This is a serious issue. Please reward me.", steps_to_reproduce:"The vulnerability can be exploited by an attacker remotely.", impact:"Complete compromise of the system."},
  {title:"Open redirect in /go?url= used to phish", severity_claimed:"Medium", asset:"www.example.com", description:"/go?url=https://evil.example redirects users off-site without validation.", steps_to_reproduce:"1. Visit https://www.example.com/go?url=https://evil.example. 2. 302 redirect to evil.example. Raw response with Location header attached.", impact:"Open redirect usable in phishing and to bypass referrer checks."},
  {title:"Auth bypass: admin panel accessible by changing role cookie", severity_claimed:"Critical", asset:"app.example.com", description:"Setting the cookie role=admin grants access to /admin without any server-side check. Attached: requests showing role=user denied (403) and role=admin allowed (200) with the same account.", steps_to_reproduce:"1. Log in as a normal user. 2. Edit cookie role=user to role=admin. 3. GET /admin now returns the admin dashboard and exposes user management.", impact:"Trivial privilege escalation to admin for any authenticated user."},
];
const REPORTERS = ["h4x0r_jane","nullbyte","recon_raj","0xsam","bountyhunterX","ctrl_alt_pwn","sleepless_soc","anon_researcher"];
const DEMO_LEAD = SEEDS[0]; // IDOR invoice PDF — canonical "real bug" demo beat

const SURGE_LIB = {title:"Prototype pollution in lodash@4.17.15 shipped in your web bundle", severity_claimed:"High", asset:"app.example.com", description:"Your production bundle includes lodash@4.17.15, affected by a known prototype pollution vulnerability. Attackers can inject properties via crafted input processed by merge/set.", steps_to_reproduce:"Inspect main.js in the bundle; lodash version is 4.17.15. Payload {\"__proto__\":{\"polluted\":true}} pollutes Object.prototype.", impact:"Prototype pollution -> potential XSS / logic bypass depending on sink."};
const SURGE_VARIANTS = ["lodash 4.17.15 prototype pollution in your app","CVE in lodash dependency (4.17.15) - prototype pollution","Vulnerable lodash@4.17.15 bundled on app.example.com","lodash prototype pollution - please patch 4.17.15","Outdated lodash 4.17.15 = prototype pollution risk","Security: lodash@4.17.15 known vuln in production bundle","Prototype pollution via lodash 4.17.15","Your site ships vulnerable lodash 4.17.15"];

/* ============================ model wiring ============================ */
// The deterministic engine (enrich/assess/heuristic/defenses/prompt) lives in
// engine.mjs — single source shared with the node tests (engine.test.mjs).

let modelMode = null;        // "demo" | "webgpu" | "emberglass" | "local"
let llmEngine = null;        // WebLLM engine
let emberglassEngine = null; // Emberglass bridge engine
let localBase = "", localModel = "";
let engineLabel = "—";

// VibeThinker is a REASONING model: it emits a long <think> phase and the JSON
// answer only AFTER it. A small budget truncates it mid-think (-> empty answer),
// and some servers (mlx_lm) route the think text to message.reasoning with an
// empty message.content. So: give a real budget and read content || reasoning.
const MAX_TOKENS = 4096;
function pickText(msg){ return (msg && (msg.content || msg.reasoning)) || ""; }
async function chatComplete(messages){
  if(modelMode==="webgpu"){
    const r = await llmEngine.chat.completions.create({messages, temperature:0, max_tokens:MAX_TOKENS});
    return pickText(r.choices[0].message);
  }
  if(modelMode==="emberglass"){
    return emberglassEngine.chatComplete(messages, { maxTokens: MAX_TOKENS, temperature: 0 });
  }
  const r = await fetch(localBase.replace(/\/$/,"")+"/chat/completions", {
    method:"POST", headers:{"Content-Type":"application/json"},
    body: JSON.stringify({model: localModel, messages, temperature:0, max_tokens:MAX_TOKENS, stream:false}),
  });
  if(!r.ok) throw new Error("HTTP "+r.status);
  const j = await r.json();
  return pickText(j.choices[0].message);
}

// the full production path: enrich -> verify -> model verdict -> defense layer
async function run(sub){
  const corr = enrich(sub);
  const ev = assess(sub, corr);
  let verdict, engine;
  if(modelMode==="demo"){
    verdict = heuristic(sub, corr);
    verdict.reasoning = (verdict.reasoning||"") + "  [instant demo: deterministic browser-side sidecar]";
    engine = engineLabel;
  } else {
    try {
    const out = await chatComplete([{role:"system",content:SYSTEM+GUARD},{role:"user",content:renderUser(sub, corrBlock(corr))}]);
    verdict = normalizeVerdict(extractJson(out));
    engine = engineLabel;
    } catch(e){
      verdict = heuristic(sub, corr);
      verdict.reasoning = (verdict.reasoning||"") + `  [model error: ${e.message} — heuristic fallback]`;
      engine = "heuristic (model error)";
    }
  }
  verdict = applyDefenses(verdict, corr, ev, sub);
  return {engine, verdict, corroboration:corr, evidence:ev};
}

/* ============================ UI ============================ */
const reports = new Map();
let selectedId = null, platform = "hackerone", query = "";
const $ = (s) => document.querySelector(s);
const inboxList = $("#inbox-list");
const detail = $("#detail");
let idc = 0; const newId = () => "r" + (++idc) + Date.now().toString(36);

const DISPO_LABEL = {valid_impactful:"Valid · Impactful", valid_low:"Valid · Low", corroborated_surge:"Corroborated Surge", likely_duplicate:"Likely Duplicate", out_of_scope:"Out of Scope", theoretical_no_poc:"No PoC", self_inflicted:"Self-Inflicted", accepted_risk:"Accepted Risk", slop:"Slop / Spam"};
const PLATFORM_LABEL = {hackerone:"HackerOne", bugcrowd:"Bugcrowd", intigriti:"Intigriti", yeswehack:"YesWeHack", generic:"Generic / VDP", paste:"Paste", "":"—"};

const esc = (s) => (s ?? "").toString().replace(/[&<>"]/g, (c)=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
function ago(ts){ const s=Math.max(0,Math.floor(Date.now()/1000-ts)); if(s<60)return s+"s ago"; if(s<3600)return Math.floor(s/60)+"m ago"; return Math.floor(s/3600)+"h ago"; }
function toast(msg){ let t=$("#toast"); if(!t){ t=document.createElement("div"); t.id="toast"; t.className="toast"; document.body.appendChild(t); } t.textContent=msg; t.classList.add("show"); clearTimeout(t._h); t._h=setTimeout(()=>t.classList.remove("show"),1800); }

function triageBadge(r){
  if(r.status==="queued") return `<span class="pill queued">queued</span>`;
  if(r.status==="triaging") return `<span class="pill triaging"><span class="spin"></span>triaging…</span>`;
  if(r.status==="error") return `<span class="pill d-slop">error</span>`;
  const v=r.verdict||{}, d=v.disposition||"unknown", sev=v.severity_estimate||"none";
  return `<span class="pill d-${d}">${DISPO_LABEL[d]||d}</span><span class="sev sev-${sev}">${sev}</span>`+
    (r.corroboration&&r.corroboration.in_kev?`<span class="tag kev">KEV</span>`:"");
}
function renderInbox(){
  let list=[...reports.values()].sort((a,b)=>b.received_at-a.received_at);
  if(query){ list=list.filter(r=>(`${r.title} ${r.reporter} ${r.asset} ${PLATFORM_LABEL[r.platform]||r.platform||""} ${(r.verdict&&r.verdict.disposition)||""} ${(r.corroboration&&(r.corroboration.cve_ids||[]).join(" "))||""}`).toLowerCase().includes(query)); }
  $("#inbox-count").textContent=list.length;
  inboxList.innerHTML=list.map(r=>`
    <div class="card ${r.id===selectedId?"selected":""}" data-id="${r.id}">
      <div class="card-title">${esc(r.title)}</div>
      <div class="card-meta"><span class="src-chip">${esc(PLATFORM_LABEL[r.platform]||r.platform||"generic")}</span><span>@${esc(r.reporter)}</span><span>·</span><span>${esc(r.asset)}</span><span>·</span><span>${ago(r.received_at)}</span></div>
      <div class="card-badges">${triageBadge(r)}</div>
    </div>`).join("");
  inboxList.querySelectorAll(".card").forEach(el=>el.addEventListener("click",()=>select(el.dataset.id)));
}
function evidenceHtml(ev){
  if(!ev||!ev.claims) return "";
  const rel=typeof ev.reliability==="number"?ev.reliability:0, pct=Math.round(rel*100);
  const col=rel>=0.66?"var(--low)":rel>=0.34?"var(--med)":"var(--crit)";
  const relLabel = (pct===0 && (ev.n_unverifiable||0)>0 && !ev.n_supported && !ev.n_refuted)
    ? "demo assets (no codebase match)"
    : `${pct}%`;
  const claims=ev.claims.map(c=>`<div class="claim"><span class="cst ${c.status}">${c.status}</span><div class="claim-body"><div class="ctext">${esc(c.claim)}</div>${c.evidence?`<div class="cev">${esc(c.evidence)}</div>`:""}</div></div>`).join("");
  return `<div class="evidence"><h4>Claim verification (ground truth, model-independent)</h4><div class="rel-row"><span class="rel-num" style="color:${col}">${relLabel}</span><div class="rel-meter"><div style="width:${pct}%;background:${col}"></div></div><span class="none">${ev.n_supported} supported · ${ev.n_refuted} refuted</span></div>${claims}</div>`;
}
function corrHtml(c){
  if(!c) return `<div class="none">enrichment pending…</div>`;
  if(!c.matched) return `<div class="none">No external corroboration (no matching CVE / advisory / package).</div>`;
  const b=[`<span class="tag match">FEED MATCH</span>`];
  if(c.in_kev) b.push(`<span class="tag kev">ACTIVELY EXPLOITED (CISA KEV)</span>`);
  if(c.recent) b.push(`<span class="tag recent">recently disclosed</span>`);
  (c.cve_ids||[]).forEach(x=>b.push(`<span class="tag">${esc(x)}</span>`));
  const srcs=(c.sources||[]).map(s=>{
    if(s.type==="OSV") return `<div class="src">OSV <code>${esc(s.id)}</code> — ${esc(s.package)}@${esc(s.version)} <span class="none">(${esc((s.aliases||[]).join(", "))})</span></div>`;
    if(s.type==="KEV") return `<div class="src">CISA KEV <code>${esc(s.cve)}</code> — added ${esc(s.date_added)} · ransomware: ${esc(s.ransomware)}</div>`;
    return "";
  }).join("");
  return `<div class="corr-badges">${b.join("")}</div>${srcs}`;
}
function renderDetail(){
  const r=reports.get(selectedId);
  if(!r){ detail.innerHTML=`<div class="empty"><div class="empty-mark">⬡</div><p>Select a submission to view the sidecar triage.</p></div>`; return; }
  const v=r.verdict||{}, conf=Math.round((v.confidence||0)*100), done=r.status==="done";
  const body = done ? `
    <div class="verdict-row"><span class="pill d-${v.disposition}">${DISPO_LABEL[v.disposition]||v.disposition}</span><span class="sev sev-${v.severity_estimate||"none"}">${v.severity_estimate||"none"}</span>
      <div class="confidence"><div class="lbl"><span>confidence</span><span>${conf}%</span></div><div class="bar"><div style="width:${conf}%"></div></div></div></div>
    <div class="reasoning">${esc(v.reasoning)}</div>
    ${(v.questions_for_researcher&&v.questions_for_researcher.length)?`<ul class="questions">${v.questions_for_researcher.map(q=>`<li>${esc(q)}</li>`).join("")}</ul>`:""}
    ${evidenceHtml(r.evidence)}
    <div class="corr"><h4>Threat-intel corroboration</h4>${corrHtml(r.corroboration)}</div>`
    : `<div class="none">${r.status==="triaging"?"<span class='spin'></span> sidecar is analyzing this report…":(modelMode?"waiting in queue…":"load a model to triage")}</div>`;
  detail.innerHTML=`
    <h2 class="report-title">${esc(r.title)}</h2>
    <div class="report-sub">from <b>${esc(PLATFORM_LABEL[r.platform]||r.platform)}</b> · by <b>@${esc(r.reporter)}</b> · target <b>${esc(r.asset)}</b> · claimed <b>${esc(r.severity_claimed)}</b> · ${ago(r.received_at)}</div>
    <div class="field"><h4>Description</h4><pre>${esc(r.description)}</pre></div>
    <div class="field"><h4>Steps to reproduce</h4><pre>${esc(r.steps_to_reproduce)}</pre></div>
    <div class="field"><h4>Impact</h4><pre>${esc(r.impact)}</pre></div>
    <div class="sidecar"><div class="sidecar-head"><span class="ai">⬡ VibeBounty Sidecar</span><span class="engine">${r.engine?"engine: "+esc(r.engine):"engine: —"}</span></div><div class="sidecar-body">${body}</div></div>`;
}
function select(id){ selectedId=id; renderInbox(); renderDetail(); document.body.classList.add("show-detail"); }
function render(r){ reports.set(r.id,r); renderInbox(); if(r.id===selectedId) renderDetail(); }

// parse a pasted free-text report (compact port of connectors.parse_text)
function parseText(raw){
  raw=(raw||"").trim(); const lines=raw.split(/\r?\n/);
  let title=""; for(const ln of lines){ const s=ln.trim().replace(/^#+/,"").trim(); if(s){ title=s.replace(/^(title|report)\s*:?\s*/i,"").slice(0,160); break; } }
  const sec={_pre:[]}; let cur="_pre"; const HEAD=/^\s*#{0,4}\s*\**\s*([A-Za-z][A-Za-z \/._-]{2,40})\s*\**\s*:?\s*$/;
  const PAT={steps_to_reproduce:/(steps\s*to\s*reproduce|reproduction|repro steps|poc|proof[\s-]*of[\s-]*concept)/i, impact:/(impact|business impact|security impact|consequence)/i, description:/(description|summary|details|overview|vulnerability)/i};
  for(const ln of lines){ const m=ln.match(HEAD); if(m){ const h=m[1].toLowerCase(); let mt=null; for(const k in PAT){ if(PAT[k].test(h)){ mt=k; break; } } cur=mt||("_o_"+h); sec[cur]=sec[cur]||[]; continue; } (sec[cur]=sec[cur]||[]).push(ln); }
  const g=(n)=>(sec[n]||[]).join("\n").trim();
  const sev=(raw.match(/\b(critical|high|medium|low|informational|info|none)\b/i)||[])[1];
  const asset=(raw.match(/\b((?:https?:\/\/)?[a-z0-9.-]+\.[a-z]{2,}(?:\/[^\s)]*)?)/i)||[])[1]||"";
  return {title:title||"Pasted report", severity_claimed:sev?sev[0].toUpperCase()+sev.slice(1):"Unknown", asset, description:g("description")||g("_pre")||raw.slice(0,1200), steps_to_reproduce:g("steps_to_reproduce"), impact:g("impact")};
}

/* ============================ ingest + triage queue ============================ */
const queue = [];
let working = false;
function ingest(sub, reporter, plat){
  const r={id:newId(), ...sub, reporter: reporter||REPORTERS[Math.floor(Math.random()*REPORTERS.length)], received_at: Date.now()/1000, platform: plat||"generic", status:"queued", verdict:null, corroboration:null, evidence:null, engine:null};
  reports.set(r.id, r); renderInbox();
  if(selectedId===null) select(r.id);
  const card=inboxList.querySelector(`[data-id="${r.id}"]`); if(card) card.classList.add("fresh");
  queue.push(r); pump();
  return r;
}
async function pump(){
  if(working || !modelMode) return;     // only triage once a model is connected
  working=true;
  while(queue.length){
    const r=queue.shift();
    r.status="triaging"; render(r);
    try { const res=await run({title:r.title,severity_claimed:r.severity_claimed,asset:r.asset,description:r.description,steps_to_reproduce:r.steps_to_reproduce,impact:r.impact});
      r.engine=res.engine; r.verdict=res.verdict; r.corroboration=res.corroboration; r.evidence=res.evidence; r.status="done";
    } catch(e){ r.status="error"; r.error=e.message; }
    render(r);
  }
  working=false;
}

/* ============================ controls ============================ */
$("#search").addEventListener("input",(e)=>{ query=e.target.value.trim().toLowerCase(); renderInbox(); });
const body=document.body;
$("#menu-toggle").addEventListener("click",()=>body.classList.toggle("nav-open"));
$("#scrim").addEventListener("click",()=>body.classList.remove("nav-open"));
$("#btn-back").addEventListener("click",()=>body.classList.remove("show-detail"));
document.querySelectorAll(".rail-item").forEach(el=>el.addEventListener("click",()=>body.classList.remove("nav-open")));
$("#platform-select").addEventListener("change",(e)=>{ platform=e.target.value; $("#ctx-platform").textContent=PLATFORM_LABEL[platform]||platform; });
$("#btn-random").addEventListener("click",()=>{ if(!modelMode) return openGate(); ingest(SEEDS[Math.floor(Math.random()*SEEDS.length)], null, platform); });
$("#btn-surge").addEventListener("click",async()=>{
  if(!modelMode) return openGate();
  ingest(SURGE_LIB, null, platform);
  for(const t of SURGE_VARIANTS){ ingest({...SURGE_LIB, title:t, description:"Quick report: app.example.com bundles lodash@4.17.15 which has a known prototype pollution vulnerability. Please update.", steps_to_reproduce:"Check bundle; lodash 4.17.15 present."}, null, platform); await new Promise(r=>setTimeout(r,250)); }
});
const pasteModal=$("#paste-modal");
$("#btn-paste").addEventListener("click",()=>pasteModal.classList.remove("hidden"));
$("#paste-submit").addEventListener("click",()=>{ const t=$("#paste-text").value.trim(); if(!t) return; if(!modelMode){ pasteModal.classList.add("hidden"); return openGate(); } ingest(parseText(t), "pasted_by_analyst", "paste"); $("#paste-text").value=""; pasteModal.classList.add("hidden"); toast("Report sent to the triage sidecar"); });
document.querySelectorAll("[data-close]").forEach(el=>el.addEventListener("click",()=>pasteModal.classList.add("hidden")));
document.querySelectorAll(".modal").forEach(m=>m.addEventListener("click",(e)=>{ if(e.target===m) m.classList.add("hidden"); }));
setInterval(renderInbox, 15000);

/* ============================ the blocking model gate ============================ */
const gate=$("#gate"), gateOptions=$("#gate-options"), gateProgress=$("#gate-progress"), gateLocal=$("#gate-local"), gateStatus=$("#gate-status");
function openGate(){
  gate.classList.remove("gone");
  gateOptions.classList.remove("hidden");
  gateProgress.classList.add("hidden");
  gateLocal.classList.add("hidden");
  setStatus(modelMode ? `Current engine: <b>${esc(engineLabel)}</b>` : "", "info");
}
function setStatus(msg, kind){ gateStatus.className="gate-status "+(kind||"info"); gateStatus.innerHTML=msg; }
function setPill(state, text){ const p=$("#model-pill"); p.className="model-pill "+(state||""); $("#model-pill-text").textContent=text; }
$("#model-pill").addEventListener("click",openGate);

$("#opt-demo").addEventListener("click",startDemo);
function startDemo(){
  llmEngine=null; emberglassEngine=null; localBase=""; localModel="";
  modelMode="demo"; engineLabel="sidecar demo (browser)";
  setPill("ready","sidecar: demo");
  $("#engine-chip").textContent="engine: "+engineLabel;
  setStatus("Demo ready — triaging the queue in this page.","ok");
  setTimeout(()=>{ gate.classList.add("gone"); }, 450);
  if(!reports.size) seedInbox();
  pump();
}

// In-browser WebGPU model (MLC). Localhost uses locally served MLC files;
// GitHub Pages uses the public Hugging Face repo.
const WEBGPU_MODEL_ID = "VibeThinker-3B-BugBounty-Triage-q4f16_1-MLC";
const HF_WEBGPU_MODEL_BASE = "https://huggingface.co/macmacmacmac/VibeThinker-3B-BugBounty-Triage-MLC/resolve/main";
const LOCAL_WEBGPU_MODEL_BASE = "http://127.0.0.1:8799";
const WEBGPU_CONTEXT_WINDOW = 8192;
const WEBGPU_MODEL_LIB = "https://raw.githubusercontent.com/mlc-ai/binary-mlc-llm-libs/main/web-llm-models/v0_2_84/base/Qwen2.5-3B-Instruct-q4f16_1_cs1k-webgpu.wasm";
function isLocalPage(){
  const h=location.hostname;
  return location.protocol==="file:" || h==="localhost" || h==="127.0.0.1" || h==="::1" || h.endsWith(".localhost");
}
function webgpuModelBase(){
  const q=new URLSearchParams(location.search).get("mlc");
  let saved="";
  try { saved=localStorage.getItem("vibebounty.mlcBase")||""; } catch(_e) { saved=""; }
  return (q || saved || (isLocalPage()?LOCAL_WEBGPU_MODEL_BASE:HF_WEBGPU_MODEL_BASE)).replace(/\/$/,"");
}
function webgpuAppConfig(modelBase){
  return {
    useIndexedDBCache:true,
    model_list:[{
      model:modelBase,
      model_id:WEBGPU_MODEL_ID,
      model_lib:WEBGPU_MODEL_LIB,
      overrides:{
        context_window_size:WEBGPU_CONTEXT_WINDOW,
      },
    }],
  };
}
function setRing(p){ const off=327-327*p; $("#gp-fg").style.strokeDashoffset=off; $("#gp-pct").textContent=Math.round(p*100)+"%"; }

const LOCAL_EMBERGLASS_BRIDGE = "http://127.0.0.1:8013/docs/emberglass-bridge.js";
const HF_EMBERGLASS_BRIDGE = "https://maceip.github.io/qwen-webgpu-lora/emberglass-bridge.js";
function emberglassBridgeUrl(){
  const q=new URLSearchParams(location.search).get("emberglass.bridge");
  let saved="";
  try { saved=localStorage.getItem("vibebounty.emberglassBridge")||""; } catch(_e) { saved=""; }
  return (q || saved || (isLocalPage()?LOCAL_EMBERGLASS_BRIDGE:HF_EMBERGLASS_BRIDGE)).replace(/\/$/,"");
}
function emberglassQuery(name, fallback=""){ return new URLSearchParams(location.search).get(name) || fallback; }
function emberglassLoadConfig(){
  const modelUrl=emberglassQuery("emberglass.model","");
  const loraUrl=emberglassQuery("emberglass.lora", isLocalPage() ? "http://127.0.0.1:8013/adapters/highconf-trace-20260623" : "");
  return {
    bridgeUrl: emberglassBridgeUrl(),
    modelUrl,
    hfRepo: emberglassQuery("emberglass.repo", "WeiboAI/VibeThinker-3B"),
    hfToken: emberglassQuery("emberglass.token", ""),
    loraUrl: loraUrl || undefined,
    loraRepo: emberglassQuery("emberglass.loraRepo", "") || undefined,
  };
}

$("#opt-emberglass").addEventListener("click", loadEmberglass);
async function loadEmberglass(){
  if(!navigator.gpu){ setStatus("This browser has no <b>WebGPU</b>. Use Chrome/Edge 121+ with the <code>subgroups</code> feature, or pick another engine.", "err"); return; }
  if(!navigator.gpu.requestAdapter){ setStatus("WebGPU is present but unavailable in this context.", "err"); return; }
  const cfg=emberglassLoadConfig();
  gateOptions.classList.add("hidden"); gateProgress.classList.remove("hidden");
  setPill("loading","model: emberglass…");
  setStatus(`Loading Emberglass bridge from <code>${esc(cfg.bridgeUrl)}</code>.`,"info"); setRing(0.02);
  try {
    const mod = await import(cfg.bridgeUrl);
    if(typeof mod.createEmberglassEngine!=="function") throw new Error("bridge missing createEmberglassEngine export");
    emberglassEngine = await mod.createEmberglassEngine({
      modelUrl: cfg.modelUrl || undefined,
      hfRepo: cfg.modelUrl ? undefined : cfg.hfRepo,
      hfToken: cfg.hfToken || undefined,
      loraUrl: cfg.loraUrl,
      loraRepo: cfg.loraRepo,
      log: (m)=>{ $("#gp-text").textContent=m; },
      onProgress: (msg, frac)=>{ if(typeof frac==="number") setRing(Math.min(0.98, frac)); $("#gp-text").textContent=msg; },
    });
    llmEngine=null; localBase=""; localModel="";
    modelMode="emberglass"; engineLabel=emberglassEngine.label || "emberglass (custom webgpu)";
    onModelReady("Emberglass · custom WebGPU");
  } catch(e){
    gateProgress.classList.add("hidden"); gateOptions.classList.remove("hidden"); setPill("error","model: failed");
    const hint=isLocalPage()
      ? `Serve <code>qwen-webgpu-lora</code> on port 8013 (<code>npm run serve</code>) with <code>/model</code> and the bridge at <code>${esc(LOCAL_EMBERGLASS_BRIDGE)}</code>, or pass <code>?emberglass.bridge=…</code>.`
      : "Publish <code>docs/emberglass-bridge.js</code> from qwen-webgpu-lora to GitHub Pages, or pass <code>?emberglass.bridge=https://…/emberglass-bridge.js</code>.";
    setStatus(`Emberglass load failed: <b>${esc(e.message||String(e))}</b><br>${hint} <button id="emberglass-demo-fallback" class="inline-action">Start instant demo</button>`, "err");
    $("#emberglass-demo-fallback")?.addEventListener("click",startDemo);
  }
}

$("#opt-webgpu").addEventListener("click", loadWebGPU);
async function loadWebGPU(){
  if(!navigator.gpu){ setStatus("This browser has no <b>WebGPU</b>. Use Chrome/Edge 121+ (or enable WebGPU), or pick <b>Connect a local model</b>.", "err"); return; }
  gateOptions.classList.add("hidden"); gateProgress.classList.remove("hidden");
  const modelBase=webgpuModelBase();
  const local=isLocalPage();
  setPill("loading",local?"model: localhost…":"model: downloading…");
  setStatus(`Loading WebGPU model from <code>${esc(modelBase)}</code>.`,"info"); setRing(0);
  try {
    llmEngine = await webllm.CreateMLCEngine(WEBGPU_MODEL_ID, {
      appConfig: webgpuAppConfig(modelBase),
      initProgressCallback: (p)=>{ if(typeof p.progress==="number") setRing(p.progress); $("#gp-text").textContent=p.text||"loading…"; },
    });
    emberglassEngine=null; modelMode="webgpu"; engineLabel="vibethinker-3b (webgpu mlc)"; onModelReady("VibeThinker-3B · WebGPU (MLC)");
  } catch(e){
    gateProgress.classList.add("hidden"); gateOptions.classList.remove("hidden"); setPill("error","model: failed");
    const hint=local
      ? `Tried <code>${esc(modelBase)}/mlc-chat-config.json</code>. Serve the MLC folder on localhost, or pass <code>?mlc=http://127.0.0.1:PORT/path</code>.`
      : "The HF MLC repo may not be public yet.";
    setStatus(`In-browser load failed: <b>${esc(e.message||String(e))}</b><br>${hint} <button id="demo-fallback" class="inline-action">Start instant demo</button>`, "err");
    $("#demo-fallback")?.addEventListener("click",startDemo);
  }
}

$("#opt-local").addEventListener("click",()=>{ gateOptions.classList.add("hidden"); gateLocal.classList.remove("hidden"); setStatus("","info"); });
$("#local-back").addEventListener("click",()=>{ gateLocal.classList.add("hidden"); gateOptions.classList.remove("hidden"); });
$("#local-connect").addEventListener("click", connectLocal);
async function connectLocal(){
  const url=$("#local-url").value.trim().replace(/\/$/,""), mdl=$("#local-model").value.trim();
  if(!url||!mdl){ setStatus("Enter the base URL and model name.","err"); return; }
  setStatus("<span class='spin'></span> contacting endpoint…","info"); setPill("loading","model: connecting…");
  try {
    const t=await fetch(url+"/chat/completions",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({model:mdl,messages:[{role:"user",content:"ping"}],max_tokens:1,stream:false})});
    if(!t.ok) throw new Error("HTTP "+t.status);
    await t.json();
    localBase=url; localModel=mdl; emberglassEngine=null; modelMode="local"; engineLabel=`${mdl} (local)`; onModelReady(`${mdl} · local endpoint`);
  } catch(e){
    setPill("error","model: failed");
    setStatus(`Couldn't reach <b>${esc(url)}</b>: ${esc(e.message||String(e))}.<br>Make sure it's running and allows CORS from <code>${esc(location.origin)}</code>. <button id="local-demo-fallback" class="inline-action">Start instant demo</button>`, "err");
    $("#local-demo-fallback")?.addEventListener("click",startDemo);
  }
}
function onModelReady(label){
  setPill("ready","model: "+label.split(" · ")[0]);
  $("#engine-chip").textContent="engine: "+engineLabel;
  setStatus("Model ready — triaging the queue.","ok");
  setTimeout(()=>{ gate.classList.add("gone"); }, 650);
  if(!reports.size) seedInbox();
  pump();   // triage everything queued behind the gate
}

const DEMO_MODE = new URLSearchParams(location.search).has("demo");
const DEMO_STEPS = [
  {
    title: "Real bug → Valid verdict",
    body: "Open the IDOR report (invoice PDF download). The sidecar reads the PoC, checks claims against ground truth, and returns Valid · Impactful — like a senior analyst, in seconds.",
    action: () => selectReportByTitle(/IDOR/i),
    lookFor: "Valid · Impactful",
  },
  {
    title: "Slop → Rejected",
    body: "Open the nuclei scanner dump. Same queue, same UI — but the sidecar classifies raw scanner output as Slop / Spam, not a payout-worthy finding.",
    action: () => selectReportByTitle(/multiple critical vulnerabilities/i),
    lookFor: "Slop",
  },
  {
    title: "Surge → Intel corroborates",
    body: "Hit Simulate surge — nine lodash duplicate reports flood the inbox. Open one: threat-intel confirms the CVE, so duplicates become Corroborated Surge instead of noise.",
    action: async () => {
      if(!reportsListHas(/lodash/i)) await runSurgeDemo();
      selectReportByTitle(/lodash/i);
    },
    lookFor: "Corroborated Surge",
  },
];
let demoStep = 0;

function reportsListHas(re){ return [...reports.values()].some(r => re.test(r.title)); }
function selectReportByTitle(re){
  const hit = [...reports.values()].find(r => re.test(r.title));
  if(hit){ select(hit.id); toast("Opened: "+hit.title.slice(0,48)); return true; }
  toast("Report not found — try Next step or pick from inbox"); return false;
}
async function runSurgeDemo(){
  ingest(SURGE_LIB, null, platform);
  for(const t of SURGE_VARIANTS){
    ingest({...SURGE_LIB, title:t, description:"Quick report: app.example.com bundles lodash@4.17.15 which has a known prototype pollution vulnerability. Please update.", steps_to_reproduce:"Check bundle; lodash 4.17.15 present."}, null, platform);
    await new Promise(r=>setTimeout(r,120));
  }
  toast("Surge queued — watch badges update");
}
function renderDemoGuide(){
  const el=$("#demo-guide"); if(!el||!DEMO_MODE) return;
  el.classList.remove("hidden");
  const s=DEMO_STEPS[demoStep];
  $("#demo-step-label").textContent=`Step ${demoStep+1} of ${DEMO_STEPS.length}`;
  $("#demo-step-title").textContent=s.title;
  $("#demo-step-body").textContent=s.body;
  $("#demo-step-next").textContent = demoStep >= DEMO_STEPS.length-1 ? "Restart demo" : "Next step →";
}
function initDemoMode(){
  gate.classList.add("demo-mode");
  $("#gate-title").textContent="3-step live demo";
  $("#gate-sub").innerHTML="Click <b>Start instant demo</b> — no download, no WebGPU wait. A floating guide walks you through three beats: real bug, slop rejection, surge + threat intel.";
  $("#demo-step-go").addEventListener("click", ()=>{ DEMO_STEPS[demoStep].action(); });
  $("#demo-step-next").addEventListener("click", ()=>{ demoStep = demoStep >= DEMO_STEPS.length-1 ? 0 : demoStep+1; renderDemoGuide(); });
  $("#demo-guide-hide").addEventListener("click", ()=>$("#demo-guide").classList.add("hidden"));
  renderDemoGuide();
  startDemo();
}

/* ============================ boot ============================ */
$("#ctx-platform").textContent=PLATFORM_LABEL[platform];
function seedInbox(){
  if(DEMO_MODE){
    ingest(DEMO_LEAD, null, platform); // IDOR
    ingest(SEEDS[10], null, platform); // nuclei slop
    return;
  }
  ingest(DEMO_LEAD, null, platform); // IDOR only — CPU model is slow
}
if(DEMO_MODE) initDemoMode();
else openGate();


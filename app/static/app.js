const reports = new Map();
let selectedId = null;
let platform = "hackerone";
let query = "";

const $ = (s) => document.querySelector(s);
const inboxList = $("#inbox-list");
const detail = $("#detail");

const DISPO_LABEL = {
  valid_impactful: "Valid · Impactful",
  valid_low: "Valid · Low",
  corroborated_surge: "Corroborated Surge",
  likely_duplicate: "Likely Duplicate",
  out_of_scope: "Out of Scope",
  theoretical_no_poc: "No PoC",
  self_inflicted: "Self-Inflicted",
  accepted_risk: "Accepted Risk",
  slop: "Slop / Spam",
};
const PLATFORM_LABEL = {
  hackerone: "HackerOne", bugcrowd: "Bugcrowd", intigriti: "Intigriti",
  yeswehack: "YesWeHack", generic: "Generic / VDP", paste: "Paste", "": "—",
};

const esc = (s) => (s ?? "").toString().replace(/[&<>"]/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
function ago(ts) {
  const s = Math.max(0, Math.floor(Date.now() / 1000 - ts));
  if (s < 60) return s + "s ago";
  if (s < 3600) return Math.floor(s / 60) + "m ago";
  return Math.floor(s / 3600) + "h ago";
}
function toast(msg) {
  let t = $("#toast");
  if (!t) { t = document.createElement("div"); t.id = "toast"; t.className = "toast"; document.body.appendChild(t); }
  t.textContent = msg; t.classList.add("show");
  clearTimeout(t._h); t._h = setTimeout(() => t.classList.remove("show"), 1800);
}

function triageBadge(r) {
  if (r.status === "queued") return `<span class="pill queued">queued</span>`;
  if (r.status === "triaging") return `<span class="pill triaging"><span class="spin"></span>triaging…</span>`;
  if (r.status === "error") return `<span class="pill d-slop">error</span>`;
  const v = r.verdict || {};
  const d = v.disposition || "unknown";
  const sev = v.severity_estimate || "none";
  return `<span class="pill d-${d}">${DISPO_LABEL[d] || d}</span>` +
         `<span class="sev sev-${sev}">${sev}</span>` +
         (r.corroboration && r.corroboration.in_kev ? `<span class="tag kev">KEV</span>` : "");
}

function renderInbox() {
  let list = [...reports.values()].sort((a, b) => b.received_at - a.received_at);
  if (query) {
    list = list.filter((r) => (
      `${r.title} ${r.reporter} ${r.asset} ${PLATFORM_LABEL[r.platform] || r.platform || ""} ` +
      `${(r.verdict && r.verdict.disposition) || ""} ${(r.corroboration && (r.corroboration.cve_ids || []).join(" ")) || ""}`
    ).toLowerCase().includes(query));
  }
  $("#inbox-count").textContent = list.length;
  inboxList.innerHTML = list.map((r) => `
    <div class="card ${r.id === selectedId ? "selected" : ""}" data-id="${r.id}">
      <div class="card-title">${esc(r.title)}</div>
      <div class="card-meta">
        <span class="src-chip">${esc(PLATFORM_LABEL[r.platform] || r.platform || "generic")}</span>
        <span>@${esc(r.reporter)}</span><span>·</span><span>${esc(r.asset)}</span><span>·</span><span>${ago(r.received_at)}</span>
      </div>
      <div class="card-badges">${triageBadge(r)}</div>
    </div>`).join("");
  inboxList.querySelectorAll(".card").forEach((el) =>
    el.addEventListener("click", () => select(el.dataset.id)));
}

function evidenceHtml(ev) {
  if (!ev || !ev.claims) return "";
  const rel = typeof ev.reliability === "number" ? ev.reliability : 0;
  const pct = Math.round(rel * 100);
  const col = rel >= 0.66 ? "var(--low)" : rel >= 0.34 ? "var(--med)" : "var(--crit)";
  const claims = ev.claims.map((c) => `
    <div class="claim">
      <span class="cst ${c.status}">${c.status}</span>
      <div class="claim-body"><div class="ctext">${esc(c.claim)}</div>
        ${c.evidence ? `<div class="cev">${esc(c.evidence)}</div>` : ""}</div>
    </div>`).join("");
  return `<div class="evidence">
    <h4>Claim verification (ground truth, model-independent)</h4>
    <div class="rel-row">
      <span class="rel-num" style="color:${col}">${pct}%</span>
      <div class="rel-meter"><div style="width:${pct}%;background:${col}"></div></div>
      <span class="none">${ev.n_supported} supported · ${ev.n_refuted} refuted</span>
    </div>${claims}</div>`;
}

function corrHtml(c) {
  if (!c) return `<div class="none">enrichment pending…</div>`;
  if (!c.matched) return `<div class="none">No external corroboration (no matching CVE / advisory / package).</div>`;
  const badges = [`<span class="tag match">FEED MATCH</span>`];
  if (c.in_kev) badges.push(`<span class="tag kev">ACTIVELY EXPLOITED (CISA KEV)</span>`);
  if (c.recent) badges.push(`<span class="tag recent">recently disclosed</span>`);
  (c.cve_ids || []).forEach((x) => badges.push(`<span class="tag">${esc(x)}</span>`));
  const srcs = (c.sources || []).map((s) => {
    if (s.type === "OSV") return `<div class="src">OSV <code>${esc(s.id)}</code> — ${esc(s.package)}@${esc(s.version)} <span class="none">(${esc((s.aliases || []).join(", "))})</span></div>`;
    if (s.type === "KEV") return `<div class="src">CISA KEV <code>${esc(s.cve)}</code> — added ${esc(s.date_added)} · ransomware: ${esc(s.ransomware)}</div>`;
    if (s.type === "NVD") return `<div class="src">NVD <code>${esc(s.cve)}</code> — ${esc(s.published)}</div>`;
    if (s.type === "GHSA") return `<div class="src">GHSA <code>${esc(s.ghsa)}</code> (${esc(s.severity)}) — ${esc(s.published)}</div>`;
    return "";
  }).join("");
  return `<div class="corr-badges">${badges.join("")}</div>${srcs}`;
}

function renderDetail() {
  const r = reports.get(selectedId);
  if (!r) { detail.innerHTML = `<div class="empty"><div class="empty-mark">⬡</div><p>Select a submission to view the sidecar triage.</p></div>`; return; }
  const v = r.verdict || {};
  const conf = Math.round((v.confidence || 0) * 100);
  const done = r.status === "done";
  const sidecarBody = done ? `
    <div class="verdict-row">
      <span class="pill d-${v.disposition}">${DISPO_LABEL[v.disposition] || v.disposition}</span>
      <span class="sev sev-${v.severity_estimate || "none"}">${v.severity_estimate || "none"}</span>
      <div class="confidence">
        <div class="lbl"><span>confidence</span><span>${conf}%</span></div>
        <div class="bar"><div style="width:${conf}%"></div></div>
      </div>
    </div>
    <div class="reasoning">${esc(v.reasoning)}</div>
    ${(v.questions_for_researcher && v.questions_for_researcher.length) ?
      `<ul class="questions">${v.questions_for_researcher.map((q) => `<li>${esc(q)}</li>`).join("")}</ul>` : ""}
    ${evidenceHtml(r.evidence)}
    <div class="corr"><h4>Threat-intel corroboration</h4>${corrHtml(r.corroboration)}</div>
  ` : `<div class="none">${r.status === "triaging" ? "<span class='spin'></span> sidecar is analyzing this report…" : "waiting in queue…"}</div>`;

  detail.innerHTML = `
    <h2 class="report-title">${esc(r.title)}</h2>
    <div class="report-sub">from <b>${esc(PLATFORM_LABEL[r.platform] || r.platform)}</b> · by <b>@${esc(r.reporter)}</b> · target <b>${esc(r.asset)}</b> · claimed <b>${esc(r.severity_claimed)}</b> · ${ago(r.received_at)}</div>
    <div class="field"><h4>Description</h4><pre>${esc(r.description)}</pre></div>
    <div class="field"><h4>Steps to reproduce</h4><pre>${esc(r.steps_to_reproduce)}</pre></div>
    <div class="field"><h4>Impact</h4><pre>${esc(r.impact)}</pre></div>
    <div class="sidecar">
      <div class="sidecar-head"><span class="ai">⬡ VibeBounty Sidecar</span>
        <span class="engine">${r.engine ? "engine: " + esc(r.engine) : "engine: —"}</span></div>
      <div class="sidecar-body">${sidecarBody}</div>
    </div>`;
}

function select(id) {
  selectedId = id;
  renderInbox();
  renderDetail();
  document.body.classList.add("show-detail");   // mobile: slide detail in
}
function upsert(r, fresh) {
  reports.set(r.id, r);
  if (r.engine) $("#engine-chip").textContent = "engine: " + r.engine;
  renderInbox();
  if (fresh && selectedId === null) select(r.id);
  if (r.id === selectedId) renderDetail();
}

function connect() {
  const es = new EventSource("/api/events");
  es.onopen = () => { $("#live-dot").className = "dot online"; $("#live-text").textContent = "live"; };
  es.onerror = () => { $("#live-dot").className = "dot offline"; $("#live-text").textContent = "reconnecting…"; };
  es.onmessage = (e) => {
    const msg = JSON.parse(e.data);
    if (msg.type === "snapshot") {
      msg.data.forEach((r) => reports.set(r.id, r));
      renderInbox();
      if (selectedId === null && msg.data.length) select(msg.data[0].id);
    } else if (msg.type === "new") {
      upsert(msg.data, true);
      const card = inboxList.querySelector(`[data-id="${msg.data.id}"]`);
      if (card) card.classList.add("fresh");
    } else if (msg.type === "update") {
      upsert(msg.data, false);
    }
  };
}

async function post(url, body) {
  try {
    await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
  } catch (e) { /* ignore */ }
}

// search filter
$("#search").addEventListener("input", (e) => { query = e.target.value.trim().toLowerCase(); renderInbox(); });

// mobile nav: sidebar drawer + list<->detail
const body = document.body;
$("#menu-toggle").addEventListener("click", () => body.classList.toggle("nav-open"));
$("#scrim").addEventListener("click", () => body.classList.remove("nav-open"));
$("#btn-back").addEventListener("click", () => body.classList.remove("show-detail"));
document.querySelectorAll(".rail-item").forEach((el) =>
  el.addEventListener("click", () => body.classList.remove("nav-open")));

// platform selector
$("#platform-select").addEventListener("change", (e) => {
  platform = e.target.value;
  $("#ctx-platform").textContent = PLATFORM_LABEL[platform] || platform;
});

// actions
$("#btn-random").addEventListener("click", () => post("/api/simulate/random"));
$("#btn-surge").addEventListener("click", () => post("/api/simulate/surge"));

// paste modal
const pasteModal = $("#paste-modal");
$("#btn-paste").addEventListener("click", () => pasteModal.classList.remove("hidden"));
$("#paste-submit").addEventListener("click", async () => {
  const text = $("#paste-text").value.trim();
  if (!text) return;
  await post("/api/triage_text", { text, platform });
  $("#paste-text").value = "";
  pasteModal.classList.add("hidden");
  toast("Report sent to the triage sidecar");
});

// connect modal
const connectModal = $("#connect-modal");
$("#btn-connect").addEventListener("click", async () => {
  connectModal.classList.remove("hidden");
  try {
    const c = await (await fetch("/api/connectors")).json();
    $("#conn-webhook").textContent = c.webhook_url;
    $("#conn-bookmarklet").textContent = c.bookmarklet;
    $("#conn-platforms").innerHTML = c.platforms.map((p) =>
      `<span class="conn-chip">${esc(p.name)} <b>· ${esc(p.mode)}</b></span>`).join("");
  } catch (e) { /* ignore */ }
});
document.querySelectorAll(".copyable").forEach((el) =>
  el.addEventListener("click", () => { navigator.clipboard.writeText(el.textContent); toast("Copied to clipboard"); }));
document.querySelectorAll("[data-close]").forEach((el) =>
  el.addEventListener("click", () => { pasteModal.classList.add("hidden"); connectModal.classList.add("hidden"); }));
document.querySelectorAll(".modal").forEach((m) =>
  m.addEventListener("click", (e) => { if (e.target === m) m.classList.add("hidden"); }));

setInterval(renderInbox, 15000);
connect();

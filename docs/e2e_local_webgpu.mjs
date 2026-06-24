#!/usr/bin/env node
/**
 * End-to-end local WebGPU demo test for docs/.
 *
 * Preconditions:
 *   1. Install Playwright in the runner context:
 *        npm exec --yes --package=playwright -- node docs/e2e_local_webgpu.mjs
 *   2. Point MLC_DIR at the converted WebLLM folder, or use the default:
 *        %USERPROFILE%\bbverifier\mlc\VibeThinker-3B-BugBounty-Triage-q4f16_1-MLC
 *
 * The MLC_DIR folder must contain mlc-chat-config.json and ndarray-cache.json.
 * This script starts both the Pages demo and a CORS static server for the local
 * model, launches Chrome Dev/Chrome Beta, loads WebGPU from localhost, pastes a
 * realistic IDOR submission, and verifies the sidecar returns a model verdict.
 */
import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.resolve(here, "..");
const docs = here;

const docsPort = Number(process.env.DOCS_PORT || 8767);
const mlcPort = Number(process.env.MLC_PORT || 8799);
const modelDir = path.resolve(process.env.MLC_DIR || path.join(
  os.homedir(),
  "bbverifier",
  "mlc",
  "VibeThinker-3B-BugBounty-Triage-q4f16_1-MLC",
));
const modelConfig = path.join(modelDir, "mlc-chat-config.json");
const modelCache = path.join(modelDir, "ndarray-cache.json");
const provenancePath = path.join(modelDir, "vibebounty-webgpu-provenance.json");

if (!fs.existsSync(modelConfig) || !fs.existsSync(modelCache)) {
  console.error("[e2e] Missing local MLC model files.");
  console.error(`[e2e] Expected: ${modelConfig}`);
  console.error(`[e2e] Expected: ${modelCache}`);
  console.error("[e2e] Set MLC_DIR to the converted WebLLM folder and rerun.");
  process.exit(2);
}
if (fs.existsSync(provenancePath)) {
  const provenance = JSON.parse(fs.readFileSync(provenancePath, "utf8"));
  console.log("[e2e] provenance", JSON.stringify(provenance, null, 2));
  if (provenance.base_model !== "WeiboAI/VibeThinker-3B" || provenance.quantization !== "q4f16_1") {
    console.error("[e2e] Local MLC provenance does not match the expected VibeThinker WebGPU tune.");
    process.exit(2);
  }
  if ((provenance.context_window_size || 0) < 8192) {
    console.error("[e2e] Local MLC context is too small for the VibeThinker reasoning demo.");
    process.exit(2);
  }
} else {
  console.warn(`[e2e] No provenance file found at ${provenancePath}`);
  console.warn("[e2e] The model can still be tested, but the Lambda->MLC source chain is not proven.");
}

const chromeCandidates = [
  process.env.CHROME_PATH,
  "C:\\Users\\mac\\AppData\\Local\\Google\\Chrome Dev\\Application\\chrome.exe",
  "C:\\Program Files\\Google\\Chrome Beta\\Application\\chrome.exe",
  "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
].filter(Boolean);
const chromePath = chromeCandidates.find(p => fs.existsSync(p));
if (!chromePath) {
  console.error("[e2e] Could not find Chrome Dev/Beta/Stable. Set CHROME_PATH.");
  process.exit(2);
}

function start(name, command, args, cwd = repo) {
  const child = spawn(command, args, { cwd, stdio: ["ignore", "pipe", "pipe"], shell: false });
  child.stdout.on("data", b => process.stdout.write(`[${name}] ${b}`));
  child.stderr.on("data", b => process.stderr.write(`[${name}] ${b}`));
  return child;
}

const children = [];
function cleanup() {
  for (const child of children.reverse()) {
    if (!child.killed) child.kill();
  }
}
process.on("exit", cleanup);
process.on("SIGINT", () => { cleanup(); process.exit(130); });
process.on("SIGTERM", () => { cleanup(); process.exit(143); });

children.push(start("docs", "python", ["-m", "http.server", String(docsPort), "--bind", "127.0.0.1", "--directory", docs]));
children.push(start("mlc", "python", [path.join(docs, "serve_mlc_local.py"), modelDir, "--port", String(mlcPort)]));

await new Promise(resolve => setTimeout(resolve, 1000));

const { chromium } = await import("playwright");
const browser = await chromium.launch({
  executablePath: chromePath,
  headless: false,
  args: ["--enable-unsafe-webgpu"],
});

try {
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  const errors = [];
  page.on("console", msg => {
    const text = msg.text();
    if (msg.type() === "error") errors.push(text);
    console.log(`[browser:${msg.type()}] ${text}`);
  });
  page.on("pageerror", err => errors.push(err.message));

  const appUrl = `http://127.0.0.1:${docsPort}/?mlc=http://127.0.0.1:${mlcPort}`;
  console.log(`[e2e] opening ${appUrl}`);
  await page.goto(appUrl, { waitUntil: "domcontentloaded" });

  await page.locator("#opt-webgpu").click();
  await page.waitForFunction(() => document.querySelector("#gate")?.classList.contains("gone"), null, {
    timeout: Number(process.env.MODEL_LOAD_TIMEOUT_MS || 10 * 60 * 1000),
  });

  await page.locator("#btn-paste").click();
  await page.locator("#paste-text").fill(`IDOR: invoice export exposes other tenants
Severity: High
Asset: api.acme.test

Description:
GET /api/v2/invoices/48152/export returns invoice PDFs for any sequential id. The server accepts my normal user cookie but does not check tenant ownership.

Steps to reproduce:
1. Log in as tenant A.
2. Open GET /api/v2/invoices/48152/export and confirm it is my invoice.
3. Change the id to 48151 and 48150.
4. Both responses return other tenants' invoice PDFs with names, billing addresses, and line items.

Impact:
Any authenticated user can enumerate invoices across tenants and download customer PII and purchase history.`);
  await page.locator("#paste-submit").click();

  const pastedCard = page.locator(".card", { hasText: "IDOR: invoice export exposes other tenants" }).first();
  await pastedCard.click({ timeout: 30_000 });
  await page.locator(".sidecar .engine", { hasText: "vibethinker-3b (webgpu)" }).waitFor({
    timeout: Number(process.env.TRIAGE_TIMEOUT_MS || 5 * 60 * 1000),
  });
  const verdict = await page.locator(".sidecar .verdict-row .pill").first().innerText();
  const reasoning = await page.locator(".sidecar .reasoning").innerText();
  const engine = await page.locator(".sidecar .engine").innerText();

  if (/heuristic|model error/i.test(`${engine}\n${reasoning}`)) {
    throw new Error(`model did not drive the verdict: ${engine} ${reasoning}`);
  }
  if (!/valid|impactful/i.test(verdict)) {
    throw new Error(`unexpected verdict for IDOR submission: ${verdict}`);
  }
  if (errors.length) {
    throw new Error(`browser errors encountered:\n${errors.join("\n")}`);
  }

  console.log(`[e2e] PASS verdict="${verdict}" engine="${engine}"`);
} finally {
  await browser.close();
}

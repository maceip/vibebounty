#!/usr/bin/env node
/**
 * End-to-end Emberglass (custom WebGPU harness) test for docs/.
 *
 * Starts:
 *   - qwen-webgpu-lora on :8013 (model + emberglass-bridge.js + optional LoRA)
 *   - VibeBounty docs on :8767
 *
 * Usage (from bb-triage repo root):
 *   node docs/e2e_local_emberglass.mjs
 *
 * Env:
 *   EMBERGLASS_REPO  path to qwen-webgpu-lora (default: ../../qwen-webgpu-lora)
 *   DOCS_PORT        default 8767
 *   EMBERGLASS_PORT  default 8013
 */
import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const docs = here;
const repo = path.resolve(here, "..");
const emberglassRepo = path.resolve(process.env.EMBERGLASS_REPO || path.join(repo, "..", "..", "qwen-webgpu-lora"));
const docsPort = Number(process.env.DOCS_PORT || 8767);
const emberglassPort = Number(process.env.EMBERGLASS_PORT || 8013);
const bridgeJs = path.join(emberglassRepo, "docs", "emberglass-bridge.js");
const modelIndex = path.join(emberglassRepo, "model", "model.safetensors.index.json");

if (!fs.existsSync(bridgeJs)) {
  console.error(`[e2e-emberglass] Missing bridge bundle: ${bridgeJs}`);
  console.error("[e2e-emberglass] Run npm run build in qwen-webgpu-lora first.");
  process.exit(2);
}
if (!fs.existsSync(modelIndex)) {
  console.error(`[e2e-emberglass] Missing model at ${path.join(emberglassRepo, "model")}`);
  console.error("[e2e-emberglass] Place VibeThinker-3B weights under qwen-webgpu-lora/model/");
  process.exit(2);
}

const chromeCandidates = [
  process.env.CHROME_PATH,
  "C:\\Users\\mac\\AppData\\Local\\Google\\Chrome Dev\\Application\\chrome.exe",
  "C:\\Program Files\\Google\\Chrome Beta\\Application\\chrome.exe",
  "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
].filter(Boolean);
const chromePath = chromeCandidates.find(p => fs.existsSync(p));
if (!chromePath) {
  console.error("[e2e-emberglass] Could not find Chrome. Set CHROME_PATH.");
  process.exit(2);
}

function start(name, command, args, cwd) {
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

children.push(start("emberglass", "npx", ["http-server", ".", "-p", String(emberglassPort), "-c-1", "--cors"], emberglassRepo));
children.push(start("docs", "python", ["-m", "http.server", String(docsPort), "--bind", "127.0.0.1", "--directory", docs]));

await new Promise(r => setTimeout(r, 1500));

const { chromium } = await import("playwright");
const browser = await chromium.launch({
  executablePath: chromePath,
  headless: false,
  args: ["--enable-unsafe-webgpu", "--enable-features=WebGPU"],
});

try {
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  const errors = [];
  page.on("console", msg => {
    if (msg.type() === "error") errors.push(msg.text());
    console.log(`[browser:${msg.type()}] ${msg.text()}`);
  });
  page.on("pageerror", err => errors.push(err.message));

  const bridge = `http://127.0.0.1:${emberglassPort}/docs/emberglass-bridge.js`;
  const model = `http://127.0.0.1:${emberglassPort}/model`;
  const lora = `http://127.0.0.1:${emberglassPort}/adapters/highconf-trace-20260623`;
  const appUrl = `http://127.0.0.1:${docsPort}/?emberglass.bridge=${encodeURIComponent(bridge)}&emberglass.model=${encodeURIComponent(model)}&emberglass.lora=${encodeURIComponent(lora)}`;
  console.log(`[e2e-emberglass] opening ${appUrl}`);
  await page.goto(appUrl, { waitUntil: "domcontentloaded" });

  await page.locator("#opt-emberglass").click();
  await page.waitForFunction(() => document.querySelector("#gate")?.classList.contains("gone"), null, {
    timeout: Number(process.env.MODEL_LOAD_TIMEOUT_MS || 15 * 60 * 1000),
  });

  await page.locator("#btn-paste").click();
  await page.locator("#paste-text").fill(`IDOR: invoice export exposes other tenants
Severity: High
Asset: api.acme.test

Description:
GET /api/v2/invoices/48152/export returns invoice PDFs for any sequential id.

Steps to reproduce:
1. Log in as tenant A.
2. Request GET /api/v2/invoices/48152/export for my invoice.
3. Decrement id to 48151; response contains another tenant's PDF with PII.

Impact:
Cross-tenant invoice disclosure.`);
  await page.locator("#paste-submit").click();

  const card = page.locator(".card", { hasText: "IDOR: invoice export exposes other tenants" }).first();
  await card.click({ timeout: 30_000 });
  await page.locator(".sidecar .engine", { hasText: /emberglass/i }).waitFor({
    timeout: Number(process.env.TRIAGE_TIMEOUT_MS || 10 * 60 * 1000),
  });
  const engine = await page.locator(".sidecar .engine").innerText();
  const reasoning = await page.locator(".sidecar .reasoning").innerText();
  if (/heuristic|model error/i.test(`${engine}\n${reasoning}`)) {
    throw new Error(`Emberglass did not drive the verdict: ${engine} ${reasoning.slice(0, 200)}`);
  }
  if (errors.length) throw new Error(`browser errors:\n${errors.join("\n")}`);
  console.log(`[e2e-emberglass] PASS engine="${engine}"`);
} finally {
  await browser.close();
  cleanup();
}

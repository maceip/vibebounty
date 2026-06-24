#!/usr/bin/env node
/** Quick smoke: Emberglass gate loads bridge module (no full model). */
import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const emberglassRepo = path.resolve(process.env.EMBERGLASS_REPO || path.join(here, "..", "..", "..", "qwen-webgpu-lora"));
const docsPort = 8767;
const emberglassPort = 8013;
const bridgeJs = path.join(emberglassRepo, "docs", "emberglass-bridge.js");
if (!fs.existsSync(bridgeJs)) {
  console.error("missing", bridgeJs);
  process.exit(2);
}
const chromePath = [
  process.env.CHROME_PATH,
  "C:\\Users\\mac\\AppData\\Local\\Google\\Chrome Dev\\Application\\chrome.exe",
  "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
].find(p => p && fs.existsSync(p));
if (!chromePath) process.exit(2);

function start(cwd, cmd, args) {
  const c = spawn(cmd, args, { cwd, stdio: ["ignore", "pipe", "pipe"] });
  return c;
}
const kids = [];
function cleanup() { for (const k of kids.reverse()) k.kill(); }
process.on("exit", cleanup);
process.on("SIGINT", () => { cleanup(); process.exit(130); });

kids.push(start(emberglassRepo, "npx", ["http-server", ".", "-p", String(emberglassPort), "-c-1", "--cors"]));
kids.push(start(here, "python", ["-m", "http.server", String(docsPort), "--bind", "127.0.0.1", "--directory", here]));
await new Promise(r => setTimeout(r, 1200));

const { chromium } = await import("playwright");
const browser = await chromium.launch({
  executablePath: chromePath,
  headless: true,
  args: ["--enable-unsafe-webgpu", "--enable-features=WebGPU"],
});
try {
  const page = await browser.newPage();
  const bridge = `http://127.0.0.1:${emberglassPort}/docs/emberglass-bridge.js`;
  const url = `http://127.0.0.1:${docsPort}/?emberglass.bridge=${encodeURIComponent(bridge)}&emberglass.repo=WeiboAI/VibeThinker-3B`;
  await page.goto(url, { waitUntil: "domcontentloaded" });
  await page.locator("#opt-emberglass").click();
  await page.waitForFunction(() => {
    const t = document.querySelector("#gp-text")?.textContent || "";
    return t.includes("streaming model") || t.includes("ready") || t.includes("failed") || document.querySelector("#gate")?.classList.contains("gone");
  }, null, { timeout: 120_000 });
  const text = await page.locator("#gp-text").innerText();
  const gateGone = await page.locator("#gate").evaluate(el => el.classList.contains("gone"));
  if (/failed/i.test(text) && !gateGone) throw new Error(`load failed early: ${text}`);
  console.log("[smoke-emberglass] bridge import OK:", text.slice(0, 120));
} finally {
  await browser.close();
  cleanup();
}

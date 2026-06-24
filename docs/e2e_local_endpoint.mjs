#!/usr/bin/env node
import fs from "node:fs";

const chromeCandidates = [
  process.env.CHROME_PATH,
  "C:\\Users\\mac\\AppData\\Local\\Google\\Chrome Dev\\Application\\chrome.exe",
  "C:\\Program Files\\Google\\Chrome Beta\\Application\\chrome.exe",
  "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
].filter(Boolean);
const chromePath = chromeCandidates.find((p) => fs.existsSync(p));
if (!chromePath) {
  console.error("[e2e] Chrome not found. Set CHROME_PATH.");
  process.exit(2);
}

const appUrl = process.env.APP_URL || "http://127.0.0.1:8767/";
const modelUrl = process.env.MODEL_URL || "http://127.0.0.1:8080/v1";
const modelName = process.env.MODEL_NAME || "VibeThinker-3B-BugBounty-Triage";

const { chromium } = await import("playwright");
const browser = await chromium.launch({
  executablePath: chromePath,
  headless: false,
});

try {
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  const errors = [];
  page.on("console", (msg) => {
    const text = msg.text();
    if (msg.type() === "error" && !/404 .*File not found|Failed to load resource/i.test(text)) {
      errors.push(text);
    }
  });
  page.on("pageerror", (err) => errors.push(err.message));

  await page.goto(appUrl, { waitUntil: "domcontentloaded" });
  await page.locator("#opt-local").click();
  await page.locator("#local-url").fill(modelUrl);
  await page.locator("#local-model").fill(modelName);
  await page.locator("#local-connect").click();
  await page.waitForFunction(
    () => document.querySelector("#gate")?.classList.contains("gone"),
    null,
    { timeout: 180_000 },
  );

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
  await page.locator(".sidecar .engine", { hasText: /BugBounty-Triage \(local\)/i }).waitFor({
    timeout: 240_000,
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

"""Live bug-bounty triage console (HackerOne/Bugcrowd-style PoC).

Reports stream into an inbox and are auto-triaged by the sidecar model the
moment they arrive - no manual per-report script run. The browser receives live
updates over SSE.

Run from the bb-triage/ directory:
  uvicorn app.server:app --reload --port 8000
then open http://localhost:8000
"""
import asyncio
import json
import pathlib
import random
import time

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, StreamingResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app import connectors, triage
from app.store import Report, Store, new_id

ROOT = pathlib.Path(__file__).resolve().parent.parent
STATIC = pathlib.Path(__file__).resolve().parent / "static"

app = FastAPI(title="BB Triage Console")
store = Store()
_triage_sem = asyncio.Semaphore(3)

REPORTERS = ["h4x0r_jane", "nullbyte", "recon_raj", "0xsam", "bountyhunterX",
             "ctrl_alt_pwn", "sleepless_soc", "anon_researcher"]


def _mk_report(sub: dict, reporter: str = None, platform: str = "generic") -> Report:
    return Report(
        id=new_id(),
        title=sub.get("title", "Untitled"),
        severity_claimed=sub.get("severity_claimed", "Unknown"),
        asset=sub.get("asset", ""),
        description=sub.get("description", ""),
        steps_to_reproduce=sub.get("steps_to_reproduce", ""),
        impact=sub.get("impact", ""),
        reporter=reporter or random.choice(REPORTERS),
        received_at=time.time(),
        platform=platform,
    )


async def triage_report(report: Report) -> None:
    async with _triage_sem:
        report.status = "triaging"
        await store.publish("update", report.to_dict())
        try:
            result = await asyncio.to_thread(triage.run, report.submission())
            report.engine = result["engine"]
            report.verdict = result["verdict"]
            report.corroboration = result["corroboration"]
            report.evidence = result.get("evidence")
            report.status = "done"
        except Exception as e:  # noqa: BLE001
            report.status = "error"
            report.error = str(e)
        await store.publish("update", report.to_dict())


async def ingest(sub: dict, reporter: str = None, platform: str = "generic") -> Report:
    report = _mk_report(sub, reporter, platform)
    store.add(report)
    await store.publish("new", report.to_dict())
    asyncio.create_task(triage_report(report))
    return report


# --- seed data ---------------------------------------------------------------
def _load_seed() -> list[dict]:
    p = ROOT / "data" / "seed_examples.jsonl"
    rows = []
    if p.exists():
        for line in p.read_text(encoding="utf-8").splitlines():
            if line.strip():
                rows.append(json.loads(line)["submission"])
    return rows


SURGE_LIB = {
    "title": "Prototype pollution in lodash@4.17.15 shipped in your web bundle",
    "severity_claimed": "High",
    "asset": "app.example.com",
    "description": "Your production bundle includes lodash@4.17.15, affected by a known "
                   "prototype pollution vulnerability. Attackers can inject properties via "
                   "crafted input processed by merge/set.",
    "steps_to_reproduce": "Inspect main.js in the bundle; lodash version is 4.17.15. "
                          "Payload {\"__proto__\":{\"polluted\":true}} pollutes Object.prototype.",
    "impact": "Prototype pollution -> potential XSS / logic bypass depending on sink.",
}


@app.on_event("startup")
async def _seed():
    async def run():
        seeds = _load_seed()[:6]
        for sub in seeds:
            await ingest(sub)
            await asyncio.sleep(1.1)  # stagger so the UI shows live triaging
    asyncio.create_task(run())


# --- API ---------------------------------------------------------------------
@app.get("/api/reports")
async def list_reports():
    return JSONResponse(store.snapshot())


@app.get("/api/reports/{rid}")
async def get_report(rid: str):
    r = store.get(rid)
    return JSONResponse(r.to_dict() if r else {}, status_code=200 if r else 404)


@app.post("/api/reports")
async def post_report(payload: dict):
    sub = payload.get("submission", payload)
    r = await ingest(sub, payload.get("reporter"))
    return JSONResponse(r.to_dict())


@app.post("/api/ingest")
async def ingest_any(payload: dict):
    """Platform-agnostic webhook: accept a report from ANY platform.

    Send the raw payload from HackerOne/Bugcrowd/Intigriti/YesWeHack/etc. (or a
    generic JSON body); we fingerprint the platform, normalize the fields, and
    triage it. Pass {"platform": "..."} to override detection.
    """
    norm = connectors.normalize(payload.get("submission", payload),
                                payload.get("platform"))
    r = await ingest(norm["submission"], norm["reporter"], norm["platform"])
    return JSONResponse({"id": r.id, "platform": norm["platform"],
                         "normalized": norm["submission"]})


@app.post("/api/triage_text")
async def triage_text(payload: dict):
    """Sidecar paste box: drop in a raw report copied from any portal/email."""
    parsed = connectors.parse_text(payload.get("text", ""))
    platform = payload.get("platform") or parsed["platform"]
    r = await ingest(parsed["submission"], parsed["reporter"], platform)
    return JSONResponse({"id": r.id, "parsed": parsed["submission"]})


@app.get("/api/connectors")
async def list_connectors(request: Request):
    """Integration metadata the UI shows so analysts can wire up their platform."""
    base = str(request.base_url).rstrip("/")
    return JSONResponse({
        "webhook_url": f"{base}/api/ingest",
        "paste_url": f"{base}/api/triage_text",
        "platforms": [
            {"id": "hackerone", "name": "HackerOne", "mode": "webhook"},
            {"id": "bugcrowd", "name": "Bugcrowd", "mode": "webhook"},
            {"id": "intigriti", "name": "Intigriti", "mode": "webhook"},
            {"id": "yeswehack", "name": "YesWeHack", "mode": "webhook"},
            {"id": "paste", "name": "Paste / Email / any portal", "mode": "paste"},
            {"id": "generic", "name": "Generic JSON / internal VDP", "mode": "webhook"},
        ],
        "bookmarklet": (
            "javascript:(async()=>{const t=document.body.innerText;"
            f"await fetch('{base}/api/triage_text',{{method:'POST',"
            "headers:{'Content-Type':'application/json'},"
            "body:JSON.stringify({text:t,platform:location.hostname})});"
            "alert('Sent to triage sidecar');})()"
        ),
    })


@app.post("/api/simulate/random")
async def simulate_random():
    seeds = _load_seed()
    if not seeds:
        return JSONResponse({"error": "no seed data"}, status_code=400)
    r = await ingest(random.choice(seeds))
    return JSONResponse(r.to_dict())


@app.post("/api/simulate/surge")
async def simulate_surge(count: int = 8):
    """Disclosure-surge scenario: one detailed report + a burst of near-dupes.

    Showcases that corroborated reports are NOT spam-binned.
    """
    first = await ingest(SURGE_LIB)
    variants = [
        "lodash 4.17.15 prototype pollution in your app",
        "CVE in lodash dependency (4.17.15) - prototype pollution",
        "Vulnerable lodash@4.17.15 bundled on app.example.com",
        "lodash prototype pollution - please patch 4.17.15",
        "Outdated lodash 4.17.15 = prototype pollution risk",
        "Security: lodash@4.17.15 known vuln in production bundle",
        "Prototype pollution via lodash 4.17.15",
        "Your site ships vulnerable lodash 4.17.15",
    ]
    for i in range(min(count, len(variants))):
        sub = dict(SURGE_LIB)
        sub["title"] = variants[i]
        sub["description"] = "Quick report: app.example.com bundles lodash@4.17.15 which has a known prototype pollution vulnerability. Please update."
        sub["steps_to_reproduce"] = "Check bundle; lodash 4.17.15 present."
        await ingest(sub)
        await asyncio.sleep(0.4)
    return JSONResponse({"ingested": min(count, len(variants)) + 1, "first": first.id})


@app.get("/api/events")
async def events(request: Request):
    q = store.subscribe()

    async def gen():
        try:
            snap = json.dumps({"type": "snapshot", "data": store.snapshot()})
            yield f"data: {snap}\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    ev = await asyncio.wait_for(q.get(), timeout=15)
                    yield f"data: {json.dumps(ev)}\n\n"
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        finally:
            store.unsubscribe(q)

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
    )


@app.get("/")
async def index():
    return FileResponse(STATIC / "index.html")


app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")

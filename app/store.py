"""In-memory report store with async pub/sub for live (SSE) updates.

All mutations happen on the event loop; blocking work (model/enrichment) is done
off-thread by the orchestrator and the results are written back here.
"""
import asyncio
import time
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Report:
    id: str
    title: str
    severity_claimed: str
    asset: str
    description: str
    steps_to_reproduce: str
    impact: str
    reporter: str
    received_at: float
    status: str = "queued"  # queued | triaging | done | error
    engine: Optional[str] = None  # vibethinker | heuristic-fallback
    verdict: Optional[dict] = None
    corroboration: Optional[dict] = None
    evidence: Optional[dict] = None
    platform: str = "generic"  # source platform: hackerone | bugcrowd | paste | ...
    error: Optional[str] = None

    def submission(self) -> dict:
        return {
            "title": self.title,
            "severity_claimed": self.severity_claimed,
            "asset": self.asset,
            "description": self.description,
            "steps_to_reproduce": self.steps_to_reproduce,
            "impact": self.impact,
        }

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "severity_claimed": self.severity_claimed,
            "asset": self.asset,
            "description": self.description,
            "steps_to_reproduce": self.steps_to_reproduce,
            "impact": self.impact,
            "reporter": self.reporter,
            "received_at": self.received_at,
            "status": self.status,
            "engine": self.engine,
            "verdict": self.verdict,
            "corroboration": self.corroboration,
            "evidence": self.evidence,
            "platform": self.platform,
            "error": self.error,
        }


class Store:
    def __init__(self) -> None:
        self._reports: dict[str, Report] = {}
        self._order: list[str] = []
        self._subscribers: set[asyncio.Queue] = set()

    # --- reports ---
    def add(self, report: Report) -> Report:
        self._reports[report.id] = report
        self._order.append(report.id)
        return report

    def get(self, rid: str) -> Optional[Report]:
        return self._reports.get(rid)

    def all_reports(self) -> "list[Report]":
        return [self._reports[i] for i in self._order]

    def snapshot(self) -> "list[dict]":
        # newest first for the inbox
        return [r.to_dict() for r in reversed(self.all_reports())]

    # --- pub/sub ---
    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue()
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subscribers.discard(q)

    async def publish(self, event_type: str, data: dict) -> None:
        for q in list(self._subscribers):
            await q.put({"type": event_type, "data": data})


def new_id(prefix: str = "rpt") -> str:
    return f"{prefix}-{int(time.time() * 1000)}-{int.from_bytes(__import__('os').urandom(2), 'big')}"

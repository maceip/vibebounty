#!/usr/bin/env python3
"""Rewrite text files to Unix LF. Run before deploy from Windows."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGETS = [
    ROOT / "remote",
]
GLOBS = ("*.sh", "constants.sh", "*.yaml")


def normalize_file(path: Path) -> bool:
    raw = path.read_bytes()
    if b"\r" not in raw:
        return False
    text = raw.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
    path.write_bytes(text.encode("utf-8"))
    return True


def main() -> int:
    changed = []
    for base in TARGETS:
        if not base.is_dir():
            continue
        seen: set[Path] = set()
        for pat in GLOBS:
            for p in base.glob(pat):
                if p in seen:
                    continue
                seen.add(p)
                if normalize_file(p):
                    changed.append(p.relative_to(ROOT))
    for rel in sorted(changed):
        print(f"lf  {rel}")
    print(f"normalize_lf: {len(changed)} file(s) fixed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Serve a local WebLLM/MLC model folder for the GitHub Pages demo.

Run this against the directory that contains mlc-chat-config.json and
ndarray-cache.json. The browser app expects this on http://127.0.0.1:8799 by
default when the page itself is running from localhost.
"""
from __future__ import annotations

import argparse
import functools
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


DEFAULT_DIR = Path.home() / "bbverifier" / "mlc" / "VibeThinker-3B-BugBounty-Triage-q4f16_1-MLC"


class CORSHandler(SimpleHTTPRequestHandler):
    def end_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Range, Content-Type")
        self.send_header("Cross-Origin-Resource-Policy", "cross-origin")
        super().end_headers()

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.end_headers()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("model_dir", nargs="?", default=str(DEFAULT_DIR))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8799)
    args = parser.parse_args()

    model_dir = Path(args.model_dir).expanduser().resolve()
    config = model_dir / "mlc-chat-config.json"
    if not config.exists():
        raise SystemExit(f"missing {config}")

    handler = functools.partial(CORSHandler, directory=str(model_dir))
    server = ThreadingHTTPServer((args.host, args.port), handler)
    print(f"serving {model_dir}")
    print(f"model URL: http://{args.host}:{args.port}/")
    server.serve_forever()


if __name__ == "__main__":
    main()

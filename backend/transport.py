# SPDX-License-Identifier: GPL-3.0-or-later
"""Decky's generic websocket logger prints RPC arguments and results.

Only the public local address is discovered via websocket. Sensitive arguments
and responses travel in HTTP bodies through Decky's authenticated fetch proxy.
"""

import hmac
import http.client
import json
import threading
import time
from http.server import BaseHTTPRequestHandler

from .phone import BoundedServer

MAX_BODY = 48 * 1024


def decky_auth_token():
    connection = http.client.HTTPConnection("127.0.0.1", 1337, timeout=3)
    try:
        connection.request("GET", "/auth/token")
        with connection.getresponse() as response:
            token = response.read(256).strip()
            if response.status != 200 or not 8 <= len(token) < 256:
                raise OSError("Decky auth unavailable")
            return token
    finally:
        connection.close()


class PanelHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def respond(self, status, body):
        content = json.dumps(body, ensure_ascii=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def do_POST(self):
        if (self.path != "/rpc"
                or self.headers.get("Host") != f"127.0.0.1:{self.server.server_port}"):
            return self.respond(404, {"error": "Unknown panel route."})
        try:
            size = int(self.headers.get("Content-Length", 0))
            if not 0 < size <= MAX_BODY or self.headers.get("Transfer-Encoding"):
                raise ValueError
            payload = json.loads(self.rfile.read(size))
            token = payload.get("auth", "").encode("ascii")
            if not hmac.compare_digest(token, self.server.token):
                return self.respond(403, {"error": "Decky authentication failed."})
            method = self.server.methods[payload["method"]]
            args = payload["args"]
            if not isinstance(args, list):
                raise ValueError
        except (ValueError, AttributeError, KeyError, TypeError, RecursionError):
            return self.respond(400, {"error": "Invalid panel request."})
        try:
            result = method(*args)
        except Exception:
            return self.respond(500, {"error": "The operation failed internally. Retry from the panel."})
        self.respond(200, result)


def open_panel(methods):
    server = BoundedServer(("127.0.0.1", 0), PanelHandler)
    try:
        deadline = time.monotonic() + 20
        while True:
            try:
                server.token = decky_auth_token()
                break
            except (OSError, http.client.HTTPException):
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.5)
        server.methods = methods
        threading.Thread(target=server.serve_forever, daemon=True).start()
    except Exception:
        server.server_close()
        raise
    return f"http://127.0.0.1:{server.server_port}/rpc"

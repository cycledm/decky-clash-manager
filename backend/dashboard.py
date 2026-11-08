# SPDX-License-Identifier: GPL-3.0-or-later
"""A local dashboard with a separate short-lived read-only capability."""

import hmac
import json
import secrets
import threading
import time
from html import escape
from http.server import BaseHTTPRequestHandler, HTTPServer

from .localization import browser_locale, translate


def dashboard_page(locale):
    def t(message):
        return escape(translate(message, locale))

    title = t("Clash Manager dashboard")
    return f"""<!doctype html>
<html lang="{locale}"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<style>body{{font:17px system-ui;color-scheme:light dark;max-width:48rem;margin:3rem auto;padding:0 1rem}}
pre{{white-space:pre-wrap;overflow-wrap:anywhere}}</style>
<h1>{title}</h1><pre role="status" id="status"
  data-expired="{t("Dashboard session ended. Open it again in Clash Manager.")}"
  data-unavailable="{t("The managed kernel is unavailable.")}">{t("Connecting…")}</pre>
<script src="/dashboard.js"></script></html>""".encode()


JS = b"""const key = location.hash.slice(1);
history.replaceState(null, '', '/');
const status = document.querySelector('#status');
async function refresh() {
  try {
    const response = await fetch('/status', {headers: {'X-Dashboard-Session': key}});
    if (!response.ok) {
      status.textContent = status.dataset.expired;
      return;
    }
    status.textContent = JSON.stringify(await response.json(), null, 2);
  } catch {
    status.textContent = status.dataset.unavailable;
  }
  setTimeout(refresh, 3000);
}
refresh();"""


class DashboardHandler(BaseHTTPRequestHandler):
    def setup(self):
        self.request.settimeout(3)
        super().setup()

    def log_message(self, *args):
        pass

    def do_GET(self):
        dashboard = self.server.dashboard
        host = f"127.0.0.1:{self.server.server_port}"
        active = dashboard.url and self.headers.get("Host") == host
        locale = browser_locale(self.headers.get("Accept-Language", ""))
        if active and self.path == "/":
            status, content, media = 200, dashboard_page(locale), "text/html"
        elif active and self.path == "/dashboard.js":
            status, content, media = 200, JS, "text/javascript"
        elif (active and self.path == "/status"
              and hmac.compare_digest(self.headers.get("X-Dashboard-Session", "").encode("latin-1"),
                                      dashboard.key.encode("ascii"))):
            try:
                status, content, media = 200, json.dumps(dashboard.read()).encode(), "application/json"
            except Exception:
                status, content, media = 503, translate("Kernel unavailable", locale).encode(), "text/plain"
        else:
            status, content, media = 403, translate("Dashboard unavailable", locale).encode(), "text/plain"
        self.send_response(status)
        self.send_header("Content-Type", media + "; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; "
                         "connect-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'")
        self.end_headers()
        self.wfile.write(content)


class LocalServer(HTTPServer):
    def handle_error(self, request, client_address):
        pass


class Dashboard:
    def __init__(self, read):
        self.read = read
        self.server = None
        self.key = ""
        self.deadline = 0

    @property
    def url(self):
        if self.server and time.monotonic() < self.deadline:
            return f"http://127.0.0.1:{self.server.server_port}/#{self.key}"
        return None

    def open(self):
        self.key = secrets.token_urlsafe(24)
        self.deadline = time.monotonic() + 900
        if self.server is None:
            self.server = LocalServer(("127.0.0.1", 0), DashboardHandler)
            self.server.dashboard = self
            threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tick(self):
        if self.server and not self.url:
            self.server.shutdown()
            self.server.server_close()
            self.server = None

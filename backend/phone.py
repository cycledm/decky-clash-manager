# SPDX-License-Identifier: GPL-3.0-or-later
"""Temporary, import-only HTTP service bound to physical LAN addresses."""

import hmac
import ipaddress
import json
import secrets
import socket
import subprocess
import threading
import time
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .downloads import MAX_PROFILE
from .ipc import OperationError
from .localization import browser_locale, translate

LIFETIME = 300
DEFAULT_FAKE_IP = ipaddress.ip_network("198.18.0.0/15")
MAX_BODY = MAX_PROFILE * 2


def lan_interfaces(excluded):
    networks = [DEFAULT_FAKE_IP]
    for value in excluded:
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
        except ValueError:
            continue
    try:
        result = subprocess.run(
            ["/usr/bin/ip", "-j", "-4", "addr", "show", "up", "scope", "global"],
            capture_output=True, check=True, timeout=3,
        )
        links = json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, ValueError):
        return []
    addresses = []
    for link in links:
        if not Path("/sys/class/net", link["ifname"], "device").exists():
            continue
        for item in link.get("addr_info", []):
            addr = ipaddress.IPv4Interface(f'{item["local"]}/{item["prefixlen"]}')
            if (not (addr.ip.is_loopback or addr.ip.is_link_local or addr.ip.is_unspecified
                     or addr.ip.is_multicast)
                    and not any(addr.ip in network for network in networks)):
                addresses.append(addr)
    return addresses


def mdns_host(address):
    name = socket.gethostname().split(".")[0].lower() + ".local"
    try:
        result = subprocess.run(
            ["/usr/bin/avahi-resolve-host-name", "-4", name],
            capture_output=True, text=True, check=True, timeout=2,
        )
        if result.stdout.split()[-1] == str(address):
            return name
    except (OSError, subprocess.SubprocessError, IndexError):
        pass
    return None


def import_page(locale):
    def t(message):
        return escape(translate(message, locale))

    title = t("Clash Manager remote import")
    return f"""<!doctype html>
<html lang="{locale}"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<style>body{{font:17px system-ui;color-scheme:light dark;max-width:34rem;margin:3rem auto;padding:0 1rem}}
input,button{{font:inherit;box-sizing:border-box;margin:.35rem 0;padding:.65rem;width:100%}}
p{{line-height:1.5}} small{{display:block;margin-bottom:1em}}</style>
<h1>{title}</h1><p>{t("Use this page on a trusted network. The pairing expires after five minutes.")}</p>
<form data-choice="{t("Enter one URL or choose one YAML file.")}" data-size="{t("The file exceeds 4 MiB.")}"
      data-loading="{t("Importing…")}" data-success="{t("Imported. Select the profile on your Steam Deck.")}"
      data-failed="{t("Could not reach your Deck. Check the pairing and try again.")}">
<label>{t("Profile name (optional)")}<input name="name" maxlength="80" aria-describedby="name-help"></label>
<small id="name-help">{t("Leave blank to use the name supplied by the subscription server.")}</small>
<label>{t("Subscription URL")}<input name="url" type="url" maxlength="4096" autocomplete="off"></label>
<label>{t("Or upload a YAML file")}<input name="file" type="file" accept=".yaml,.yml,text/yaml"></label>
<button>{t("Import")}</button></form><p role="status" id="result"></p><script src="/import.js"></script></html>""".encode()


JS = b"""const form = document.querySelector('form');
const result = document.querySelector('#result');
const token = location.hash.slice(1);
history.replaceState(null, '', location.pathname);
form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const file = form.elements.file.files[0];
  const url = form.elements.url.value.trim();
  if (Boolean(file) === Boolean(url)) {
    result.textContent = form.dataset.choice;
    return;
  }
  if (file && file.size > 4 * 1024 * 1024) {
    result.textContent = form.dataset.size;
    return;
  }
  const button = form.querySelector('button');
  button.disabled = true;
  result.textContent = form.dataset.loading;
  try {
    const response = await fetch('/import', {
      method: 'POST',
      headers: {'Content-Type': 'application/json', 'X-Clash-Pairing': token},
      body: JSON.stringify({name: form.elements.name.value.trim() || file?.name || '',
                            ...(file ? {yaml: await file.text()} : {url})})
    });
    const data = await response.json();
    result.textContent = data.ok ? form.dataset.success : data.error;
    if (data.ok) form.reset();
  } catch {
    result.textContent = form.dataset.failed;
  } finally {
    button.disabled = false;
  }
});"""


class BoundedServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, handler):
        self.slots = threading.BoundedSemaphore(6)
        super().__init__(address, handler)

    def get_request(self):
        connection, peer = super().get_request()
        connection.settimeout(8)
        return connection, peer

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        super().process_request(request, address)

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()

    def handle_error(self, request, client_address):
        pass


class ImportHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, status, body, media="application/json; charset=utf-8"):
        self.send_response(status)
        self.send_header("Content-Type", media)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; "
                         "connect-src 'self'; style-src 'unsafe-inline'; base-uri 'none'; "
                         "frame-ancestors 'none'; form-action 'none'")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def locale(self):
        return browser_locale(self.headers.get("Accept-Language", ""))

    def import_error(self, status, message):
        self.reply(status, json.dumps({"error": translate(message, self.locale())}).encode())

    def authorized_host(self):
        pair = self.server.pairing
        host = self.headers.get("Host")
        return (pair.active and host in pair.hosts
                and self.server is pair.server
                and ipaddress.ip_address(self.client_address[0]) in pair.network)

    def do_GET(self):
        if not self.authorized_host():
            return self.import_error(403, "Pairing is closed.")
        if self.path == "/":
            return self.reply(200, import_page(self.locale()), "text/html; charset=utf-8")
        if self.path == "/import.js":
            return self.reply(200, JS, "text/javascript; charset=utf-8")
        self.import_error(404, "Unknown page.")

    def do_POST(self):
        pair = self.server.pairing
        token = self.headers.get("X-Clash-Pairing", "").encode("latin-1")
        if (self.path != "/import" or not self.authorized_host()
                or self.headers.get("Origin") != "http://" + self.headers["Host"]
                or not hmac.compare_digest(token, pair.token.encode("ascii"))):
            return self.import_error(403, "Pairing is invalid or expired.")
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if self.headers.get_content_type() != "application/json" or not 0 < size <= MAX_BODY:
                raise ValueError
            payload = json.loads(self.rfile.read(size))
            if not isinstance(payload, dict) or not pair.active:
                raise ValueError
            pair.import_profile(payload)
            return self.reply(200, b'{"ok":true}')
        except OperationError as error:
            message = str(error)
        except (ValueError, OSError, RecursionError):
            message = "Invalid import request."
        except Exception:
            message = "Could not import the profile."
        self.import_error(400, message)


class Pairing:
    def __init__(self, import_profile):
        self.import_profile = import_profile
        self.server = None
        self.hosts = set()
        self.network = None
        self.deadline = 0
        self.expires_at = None
        self.token = ""
        self.name = None
        self.reason = "Remote import is closed."

    @property
    def active(self):
        return time.monotonic() < self.deadline

    def open(self, excluded):
        self.close()
        self.token = secrets.token_urlsafe(24)
        self.deadline = time.monotonic() + LIFETIME
        self.expires_at = int(time.time()) + LIFETIME
        self.update(excluded)

    def close(self):
        self.deadline = 0
        self.expires_at = None
        self.token = ""
        self.unbind()
        self.reason = "Remote import is closed."

    def unbind(self):
        if self.server:
            server, self.server = self.server, None
            server.shutdown()
            server.server_close()
        self.hosts = set()
        self.network = None
        self.name = None

    def update(self, excluded):
        if not self.active:
            self.close()
            return
        interfaces = lan_interfaces(excluded)
        if self.server and any(str(item.ip) == self.server.server_address[0]
                               and item.network == self.network for item in interfaces):
            if not self.name:
                name = mdns_host(self.server.server_address[0])
                if name:
                    self.name = f"{name}:{self.server.server_port}"
                    self.hosts.add(self.name)
            return
        self.unbind()
        for item in interfaces:
            try:
                server = BoundedServer((str(item.ip), 0), ImportHandler)
                server.pairing = self
            except OSError:
                continue
            _, port = server.server_address
            name = mdns_host(item.ip)
            self.hosts = {f"{item.ip}:{port}"}
            self.name = f"{name}:{port}" if name else None
            if self.name:
                self.hosts.add(self.name)
            self.network = item.network
            self.server = server
            threading.Thread(target=server.serve_forever, daemon=True).start()
            self.reason = None
            return
        self.reason = "No usable IPv4 address on an active Wi-Fi or Ethernet interface."

    def status(self):
        url = fallback = None
        if self.server and self.active:
            addr, port = self.server.server_address
            fallback = f"http://{addr}:{port}/#{self.token}"
            url = f"http://{self.name}/#{self.token}" if self.name else fallback
        return {"url": url, "fallback_url": fallback, "expires_at": self.expires_at, "reason": self.reason}

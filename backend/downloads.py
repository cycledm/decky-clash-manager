# SPDX-License-Identifier: GPL-3.0-or-later
"""Subscription downloads as the deck account, with optional public-only peers."""

import base64
import binascii
import http.client
import ipaddress
import socket
import time
import unicodedata
from email.errors import MessageError
from email.message import Message
from email.utils import collapse_rfc2231_value
from typing import NamedTuple, Optional
from urllib.parse import quote, urljoin, urlsplit

from .ipc import OperationError

MAX_PROFILE = 4 * 1024 * 1024
MAX_URL = 4096
REDIRECTS = {301, 302, 303, 307, 308}


class DownloadedProfile(NamedTuple):
    content: bytes
    name: Optional[str]


def clean_name(value):
    # HTTP headers arrive as Latin-1 even when the provider sent raw UTF-8.
    try:
        value = value.encode("latin-1").decode("utf-8")
    except UnicodeError:
        pass
    value = value.strip()
    if not value or any(unicodedata.category(char) in {"Cc", "Cf", "Cs"} for char in value):
        return None
    return value[:80].rstrip()


def subscription_name(headers):
    title = headers.get("Profile-Title", "").strip()
    if title.lower().startswith("base64:"):
        try:
            encoded = title[7:].strip()
            title = base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True).decode()
        except (binascii.Error, ValueError):
            title = ""
    if name := clean_name(title):
        return name

    disposition = Message()
    disposition["Content-Disposition"] = headers.get("Content-Disposition", "")
    try:
        filenames = [value for key, value in disposition.get_params(header="content-disposition", failobj=[])
                     if key == "filename"]
    except (MessageError, ValueError):
        return None
    # RFC 6266 gives the encoded filename precedence when both forms exist.
    for filename in sorted(filenames, key=lambda value: not isinstance(value, tuple)):
        try:
            if isinstance(filename, tuple):
                filename = collapse_rfc2231_value(filename, errors="strict")
        except (ValueError, LookupError):
            continue
        basename = filename.replace("\\", "/").rsplit("/", 1)[-1]
        if basename.lower().endswith((".yaml", ".yml")):
            basename = basename.rsplit(".", 1)[0]
        if name := clean_name(basename):
            return name
    return None


def subscription_url(value):
    try:
        if not isinstance(value, str) or len(value) > MAX_URL:
            raise ValueError
        value = value.strip()
        if any(ord(char) <= 32 or ord(char) == 127 or char == "\\" for char in value):
            raise ValueError
        url = urlsplit(value)
        if (url.scheme not in ("http", "https") or not url.hostname
                or url.username is not None or url.password is not None or url.port == 0):
            raise ValueError
        return url
    except (ValueError, UnicodeError):
        raise OperationError("Enter a valid HTTP or HTTPS subscription URL.") from None


def public_connect(address, timeout, source_address=None):
    # Resolve once and connect to the checked address to prevent DNS rebinding.
    infos = socket.getaddrinfo(*address, type=socket.SOCK_STREAM)
    for family, socktype, proto, _, peer in infos:
        ip = ipaddress.ip_address(peer[0])
        ip = getattr(ip, "ipv4_mapped", None) or ip
        if not ip.is_global or ip.is_multicast:
            continue
        connection = socket.socket(family, socktype, proto)
        try:
            connection.settimeout(timeout)
            if source_address is not None:
                connection.bind(source_address)
            connection.connect(peer)
            return connection
        except OSError:
            connection.close()
    raise OperationError("The paired import requires a reachable public subscription server.")


def fetch_profile(value, user_agent, *, public_only=False):
    started = time.monotonic()
    try:
        for _ in range(5):
            url = subscription_url(value)
            https = url.scheme == "https"
            cls = http.client.HTTPSConnection if https else http.client.HTTPConnection
            host = url.hostname.encode("idna").decode("ascii")
            connection = cls(host, url.port, timeout=8)
            if public_only:
                connection._create_connection = public_connect
            path = quote(url.path or "/", safe="/%:@!$&'()*+,;=-._~")
            if url.query:
                path += "?" + quote(url.query, safe="/%?:@!$&'()*+,;=-._~")
            try:
                connection.request("GET", path, headers={
                    "User-Agent": user_agent,
                    "Accept": "application/yaml, text/yaml, text/plain, */*",
                    "Accept-Encoding": "identity",
                })
                with connection.getresponse() as response:
                    if response.status in REDIRECTS:
                        target = response.getheader("Location")
                        if not target:
                            break
                        value = urljoin(value, target)
                        if https and subscription_url(value).scheme != "https":
                            raise OperationError("The subscription tried to redirect from HTTPS to HTTP.")
                        continue
                    if response.status != 200:
                        raise OperationError(f"The subscription server returned HTTP {response.status}.")
                    if response.getheader("Content-Encoding", "identity") != "identity":
                        raise OperationError("The subscription returned an unsupported content encoding.")
                    content = bytearray()
                    while len(content) <= MAX_PROFILE:
                        if time.monotonic() - started > 30:
                            raise OperationError("The subscription download timed out.")
                        chunk = response.read1(min(65536, MAX_PROFILE + 1 - len(content)))
                        if not chunk:
                            return DownloadedProfile(bytes(content), subscription_name(response.headers))
                        content.extend(chunk)
                    raise OperationError("The subscription exceeds the 4 MiB import limit.")
            finally:
                connection.close()
    except (OSError, UnicodeError, ValueError, http.client.HTTPException):
        raise OperationError("Could not download the subscription. Check the URL and network, then retry.") from None
    raise OperationError("The subscription redirected too many times.")

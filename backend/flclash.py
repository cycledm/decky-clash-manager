# SPDX-License-Identifier: GPL-3.0-or-later
"""FlClash v0.9.3's isolated Linux preferences, profile and controller adapter."""

import hashlib
import http.client
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import sqlite3
import struct
import subprocess
import tempfile
import time
from pathlib import Path

from .downloads import MAX_PROFILE
from .ipc import OperationError
from .vendor import yaml

CONTROLLER_HOST = "127.0.0.1"
CONTROLLER_PORT = 9090
TUN_DEVICE = "cm-tun"
TUN_TABLE = 20291
TUN_RULE = 30291
SCHEMA_VERSION = 23
PROFILE_ID = 7848212300773000
MAX_RESPONSE = 32 * 1024 * 1024
GEO_FILES = ("country.mmdb", "geoip.dat", "geosite.dat", "ASN.mmdb")
FAKE_DEFAULTS = ("198.18.0.0/15", "fc00::/18")

# Match YAML v3's scalar handling for strings such as on/off and preserve
# unquoted REALITY short-ids the way the released FlClash parser does.
class ProfileLoader(yaml.SafeLoader):
    yaml_implicit_resolvers = {
        key: [(tag, pattern) for tag, pattern in entries
              if tag not in ("tag:yaml.org,2002:bool", "tag:yaml.org,2002:timestamp")]
        for key, entries in yaml.SafeLoader.yaml_implicit_resolvers.items()
    }

    def construct_mapping(self, node, deep=False):
        keys = set()
        for key_node, value_node in node.value:
            if key_node.tag != "tag:yaml.org,2002:merge":
                key = self.construct_object(key_node, deep=deep)
                if key in keys:
                    raise ValueError
                keys.add(key)
                if key == "short-id":
                    preserve_short_id(value_node)
        return super().construct_mapping(node, deep)


def preserve_short_id(node):
    if isinstance(node, yaml.ScalarNode) and node.tag in (
        "tag:yaml.org,2002:int", "tag:yaml.org,2002:float"
    ):
        node.tag = "tag:yaml.org,2002:str"
    elif isinstance(node, yaml.SequenceNode):
        for entry in node.value:
            if isinstance(entry, yaml.ScalarNode):
                preserve_short_id(entry)


ProfileLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool", re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"),
    list("tTfF"),
)


def read_profile(path):
    try:
        with Path(path).open("rb") as file:
            raw = file.read(MAX_PROFILE + 1)
        if len(raw) > MAX_PROFILE:
            raise ValueError
        profile = yaml.load(raw.decode("utf-8-sig"), Loader=ProfileLoader)
        if not isinstance(profile, dict):
            raise ValueError
        pending = [(profile, 0)]
        visited = 0
        while pending:
            item, depth = pending.pop()
            visited += 1
            if visited > 300000 or depth > 64:
                raise ValueError
            if isinstance(item, dict):
                if any(not isinstance(key, str) for key in item):
                    raise ValueError
                pending.extend((value, depth + 1) for value in item.values())
            elif isinstance(item, list):
                pending.extend((value, depth + 1) for value in item)
            elif not isinstance(item, (str, int, float, bool, type(None))):
                raise ValueError
        sections = {"proxies": list, "proxy-groups": list, "proxy-providers": dict, "rules": list}
        if (any(key in profile and not isinstance(profile[key], kind) for key, kind in sections.items())
                or not any(profile.get(key) for key in sections)):
            raise ValueError
        if any(not isinstance(rule, str) for rule in profile.get("rules", ())):
            raise ValueError
        return profile
    except (OSError, UnicodeError, ValueError, TypeError, RecursionError, yaml.YAMLError):
        raise OperationError("Provide a valid Clash/Mihomo YAML with rules, proxies or proxy groups.") from None


def atomic(path, contents):
    fd, name = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(contents)
            output.flush()
            os.fsync(output.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(name).unlink(missing_ok=True)


def json_bytes(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False).encode()


def safe_config(raw, marker=None):
    # The Helper starts the official core with an elevated effective UID.
    # Take inbound services and system mutations out of user-supplied YAML.
    for key in ("listeners", "tunnels", "ss-config", "vmess-config", "tuic-server",
                "external-doh-server", "iptables", "ebpf", "external-controller",
                "external-controller-tls", "external-controller-unix",
                "external-controller-pipe", "external-ui", "external-ui-name",
                "external-ui-url", "authentication", "skip-auth-prefixes",
                "external-controller-routing-mark", "tls"):
        raw.pop(key, None)
    raw.update({"bind-address": CONTROLLER_HOST, "allow-lan": False,
                "port": 0, "socks-port": 0, "redir-port": 0, "tproxy-port": 0,
                "mixed-port": 0, "geo-auto-update": False, "routing-mark": 0,
                "external-controller-cors": {
                    "allow-origins": ["http://127.0.0.1:9090"], "allow-private-network": False,
                }})
    for section in ("dns", "ntp", "profile"):
        if section in raw and not isinstance(raw[section], dict):
            raise OperationError("A YAML settings section has an invalid structure.")
    raw.setdefault("dns", {})["listen"] = ""
    if "ntp" in raw:
        raw["ntp"]["write-to-system"] = False
    raw["tun"] = {
        "enable": False, "device": TUN_DEVICE, "auto-redirect": False,
        "iproute2-table-index": TUN_TABLE, "iproute2-rule-index": TUN_RULE,
    }
    if marker:
        raw["rules"] = [f"DOMAIN,{marker},DIRECT", *raw.get("rules", ())]
    return raw


def receive_exact(connection, size):
    result = bytearray()
    while len(result) < size:
        data = connection.recv(size - len(result))
        if not data:
            raise EOFError
        result.extend(data)
    return result


def core_method(connection, method, args):
    payload = json_bytes({"id": method, "method": method, "arguments": args})
    connection.sendall(struct.pack("<I", len(payload)) + payload)
    while True:
        size, = struct.unpack("<I", receive_exact(connection, 4))
        if size > MAX_RESPONSE:
            raise ValueError
        result = json.loads(receive_exact(connection, size))
        if result.get("id") == method:
            if result.get("error") or result.get("file"):
                raise OperationError("FlClash's bundled core rejected the YAML configuration.")
            return result.get("result")


def encode_profile(profile):
    try:
        return json_bytes(profile)
    except (UnicodeError, ValueError, TypeError, RecursionError):
        raise OperationError("The YAML contains an unsupported value.") from None


def read_link_data():
    try:
        result = subprocess.run(["/usr/bin/ip", "-j", "-d", "address", "show"],
                                capture_output=True, timeout=4, check=True)
        return json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, ValueError):
        return []


def lan_routes(links):
    # Also bypass the actual attached LAN when it does not use RFC 1918.
    networks = []
    for link in links:
        if ("UP" not in link.get("flags", []) or "LOOPBACK" in link.get("flags", [])
                or link.get("link_type") != "ether" or link.get("ifname") == TUN_DEVICE):
            continue
        for address in link.get("addr_info", []):
            try:
                interface = ipaddress.ip_interface(f"{address['local']}/{address['prefixlen']}")
                if interface.network.prefixlen and not interface.ip.is_loopback:
                    networks.append(str(interface.network))
            except (KeyError, ValueError):
                continue
    return list(dict.fromkeys(networks))


class FlClash:
    def __init__(self, data, controller_owned=None):
        self.data = Path(data)
        self.app = self.data / "share" / "com.follow.clash"
        self.preferences = self.app / "shared_preferences.json"
        self.database = self.app / "database.sqlite"
        self.profiles = self.app / "profiles"
        self.core = self.data.parent / "current" / "FlClashCore"
        self.assets = self.core.parent / "data" / "flutter_assets" / "assets" / "data"
        self.marker_file = self.data / "flclash-receipt.json"
        self.controller_owned = controller_owned

    def check_controller_available(self):
        try:
            with socket.socket() as listener:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind((CONTROLLER_HOST, CONTROLLER_PORT))
        except OSError:
            raise OperationError("FlClash requires local port 9090. Stop the other controller using it.") from None

    def _read_preferences(self):
        if not self.preferences.exists():
            return {}, {}
        preferences = json.loads(self.preferences.read_bytes())
        return preferences, json.loads(preferences.get("flutter.config", "{}"))

    def _schema(self):
        with sqlite3.connect(self.database.as_uri() + "?mode=ro", uri=True, timeout=2) as db:
            return db.execute("PRAGMA user_version").fetchone()[0]

    def initialized(self):
        try:
            _, config = self._read_preferences()
            return (config["appSettingProps"]["acceptedDisclaimerVersion"] >= 1
                    and self._schema() == SCHEMA_VERSION
                    and (self.app / "config.yaml").is_file())
        except (OSError, sqlite3.Error, KeyError, TypeError, ValueError):
            return False

    def wait_initialized(self, timeout=35):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.initialized():
                return
            time.sleep(0.25)
        raise OperationError("FlClash did not finish unattended initialization in the graphical session.")

    def validate(self, source):
        """Ask the official bundled core to parse and apply in a private scratch home."""
        profile = safe_config(read_profile(source))
        if os.geteuid() == 0:
            raise OperationError("The profile validator must run as the deck user.")
        if not self.core.is_file():
            raise OperationError("The installed FlClash core is unavailable for validation.")
        try:
            with tempfile.TemporaryDirectory(prefix="cm-check-", dir="/tmp") as tmp:
                home = Path(tmp)
                for name in GEO_FILES:
                    asset = self.assets / name
                    if asset.is_file():
                        shutil.copyfile(asset, home / name)
                for kind in ("proxy-providers", "rule-providers"):
                    for name, provider in (profile.get(kind) or {}).items():
                        if isinstance(provider, dict) and provider.get("type") != "inline":
                            digest = hashlib.sha256(f"{kind}/{name}".encode()).hexdigest()
                            provider["path"] = str(home / digest)
                config_path = home / "config.yaml"
                config_path.write_bytes(encode_profile(profile))
                address = str(home / "validate.sock")
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                    listener.bind(address)
                    listener.listen(1)
                    listener.settimeout(10)
                    with subprocess.Popen(
                        [str(self.core), address], cwd=tmp,
                        env={"HOME": tmp, "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
                        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    ) as process:
                        try:
                            connection, _ = listener.accept()
                            with connection:
                                connection.settimeout(20)
                                core_method(connection, "core.init", {"home-dir": tmp, "version": 0})
                                if core_method(connection, "config.validate", {"path": str(config_path)}):
                                    raise OperationError("FlClash's bundled core rejected the YAML configuration.")
                                core_method(connection, "config.setup", {"selected-map": {}, "options": {}})
                        finally:
                            process.terminate()
                            try:
                                process.wait(timeout=4)
                            except subprocess.TimeoutExpired:
                                process.kill()
        except (OSError, EOFError, ValueError, AttributeError):
            raise OperationError("FlClash's bundled core could not complete YAML validation.") from None

    def prepare(self, source, settings):
        """Write a managed file profile while the graphical client and its core are stopped."""
        try:
            return self._prepare(source, settings)
        except (OSError, sqlite3.Error, ValueError, TypeError, KeyError, AttributeError):
            raise OperationError("Could not write FlClash's isolated v0.9.3 profile data.") from None

    def _prepare(self, source, settings):
        marker = "cm-" + secrets.token_hex(12) + ".invalid" if source else None
        tun = bool(source and settings["tun"])
        raw = safe_config(read_profile(source), marker) if source else None
        if tun:
            links = read_link_data()
            if not links:
                raise OperationError("Could not inspect current network interfaces for safe TUN routing.")
            if any(link.get("ifname") != TUN_DEVICE
                   and link.get("linkinfo", {}).get("info_kind") in ("tun", "wireguard")
                   and "UP" in link.get("flags", []) for link in links):
                raise OperationError("Another VPN or TUN interface is active. Stop it before enabling TUN.")
            raw["tun"]["route-exclude-address"] = lan_routes(links)
        self.app.mkdir(parents=True, mode=0o700, exist_ok=True)
        preferences, config = self._read_preferences()
        patch = config.get("patchClashConfig", {})
        secret = patch.get("secret") or secrets.token_urlsafe(32)
        port = settings["mixed_port"] if source else 0
        patch.update({"mode": settings["mode"], "log-level": settings["log_level"],
                      "mixed-port": port, "port": 0, "socks-port": 0, "redir-port": 0,
                      "tproxy-port": 0, "allow-lan": False, "geo-auto-update": False,
                      "routing-mark": 0, "interface-name-mode": "clear",
                      "external-controller": f"{CONTROLLER_HOST}:{CONTROLLER_PORT}" if source else "",
                      "secret": secret, "tun": {"enable": tun, "device": TUN_DEVICE, "stack": "system"}})
        if settings.get("user_agent"):
            patch["global-ua"] = settings["user_agent"]
        config.update({"currentProfileId": PROFILE_ID if source else None, "patchClashConfig": patch,
                       "themeProps": config.get("themeProps", {})})
        config.setdefault("appSettingProps", {}).update({
            "autoLaunch": False, "silentLaunch": True, "autoRun": bool(source),
            "autoCheckUpdate": False, "openLogs": False,
        })
        config.setdefault("networkProps", {}).update({
            "systemProxy": False, "autoSetSystemDns": False, "appendSystemDns": False,
            "bypassPrivateRoute": settings["lan_bypass"],
        })
        if source:
            if self._schema() != SCHEMA_VERSION:
                raise OperationError("This FlClash database schema has not been validated by Clash Manager.")
            self.profiles.mkdir(mode=0o700, exist_ok=True)
            atomic(self.profiles / f"{PROFILE_ID}.yaml", encode_profile(raw))
        if self.database.exists():
            with sqlite3.connect(self.database, timeout=3) as db:
                if source:
                    db.execute(
                        """INSERT INTO profiles
                           (id, type, label, url, extend_type, auto_update_duration_millis,
                            auto_update, selected_map, unfold_set)
                           VALUES (?, 'file', 'Clash Manager', '', 'standard', 0, 0, '{}', '[]')
                           ON CONFLICT(id) DO UPDATE SET
                           type='file', label='Clash Manager', url='', auto_update=0""",
                        (PROFILE_ID,),
                    )
                else:
                    db.execute("DELETE FROM profiles WHERE id = ?", (PROFILE_ID,))
        preferences.update({"flutter.version": 1, "flutter.config": json_bytes(config).decode()})
        atomic(self.preferences, json_bytes(preferences))
        if not source:
            self.marker_file.unlink(missing_ok=True)
            return None
        receipt = {"marker": marker, "mode": settings["mode"], "tun": tun,
                   "mixed_port": port, "log_level": settings["log_level"]}
        atomic(self.marker_file, json_bytes(receipt))
        return receipt

    def receipt(self):
        try:
            return json.loads(self.marker_file.read_bytes())
        except (OSError, ValueError):
            return None

    def _get(self, path, secret):
        connection = http.client.HTTPConnection(CONTROLLER_HOST, CONTROLLER_PORT, timeout=1.5)
        try:
            connection.request("GET", path, headers={"Authorization": f"Bearer {secret}"})
            response = connection.getresponse()
            if response.status != 200:
                return {}
            content = response.read(MAX_RESPONSE + 1)
            if len(content) > MAX_RESPONSE:
                return {}
            result = json.loads(content)
            return result if isinstance(result, dict) else {}
        finally:
            connection.close()

    def _probe(self, receipt, groups=False):
        if not receipt or (self.controller_owned and not self.controller_owned()):
            return {"effective": False}
        _, stored = self._read_preferences()
        secret = stored["patchClashConfig"]["secret"]
        version = self._get("/version", secret).get("version")
        if not version:
            return {"effective": False}
        configs = self._get("/configs", secret)
        first_rule = next(iter(self._get("/rules", secret).get("rules") or []), {})
        active_tun = configs.get("tun") or {}
        try:
            device = bool(socket.if_nametoindex(TUN_DEVICE))
        except OSError:
            device = False
        tun = active_tun.get("enable") is True and device
        port = configs.get("mixed-port")
        try:
            with socket.create_connection((CONTROLLER_HOST, port), timeout=1):
                listener = True
        except (OSError, TypeError):
            listener = False
        effective = (
            first_rule.get("payload") == receipt["marker"]
            and first_rule.get("proxy") == "DIRECT"
            and configs.get("mode") == receipt["mode"]
            and configs.get("log-level") == receipt["log_level"]
            and port == receipt["mixed_port"] and listener
            and (active_tun.get("enable") is True) == receipt["tun"]
            and device == receipt["tun"]
            and (not receipt["tun"] or (
                active_tun.get("device") == TUN_DEVICE
                and active_tun.get("iproute2-table-index") == TUN_TABLE
                and active_tun.get("iproute2-rule-index") == TUN_RULE
            ))
        )
        status = {"effective": effective, "core_version": version, "mode": configs.get("mode"),
                  "mixed_port": port, "tun": tun, "log_level": configs.get("log-level")}
        if groups and effective:
            proxies = self._get("/proxies", secret).get("proxies") or {}
            status["groups"] = [
                {"name": name[:120], "current": entry["now"][:120]}
                for name, entry in proxies.items()
                if isinstance(entry, dict) and isinstance(entry.get("now"), str)
            ][:100]
        return status

    def status(self, receipt=None):
        try:
            return self._probe(receipt or self.receipt())
        except (OSError, http.client.HTTPException, ValueError, TypeError, KeyError, AttributeError):
            return {"effective": False}

    def verify(self, receipt, timeout=35):
        if not receipt:
            raise OperationError("Import and select a valid configuration before starting.")
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.status(receipt).get("effective"):
                return
            time.sleep(0.4)
        if receipt.get("tun"):
            raise OperationError("FlClash did not confirm the managed TUN interface and selected configuration.")
        raise OperationError("FlClash did not confirm the selected configuration and mixed port.")

    def dashboard_info(self):
        try:
            return self._probe(self.receipt(), groups=True)
        except (OSError, http.client.HTTPException, ValueError, TypeError, KeyError, AttributeError):
            return {"effective": False}

    def fake_ip_networks(self, source):
        networks = list(FAKE_DEFAULTS)
        if source:
            try:
                dns = read_profile(source).get("dns") or {}
                for key in ("fake-ip-range", "fake-ip-range6"):
                    if dns.get(key):
                        networks.append(str(ipaddress.ip_network(dns[key], strict=False)))
            except (OperationError, TypeError, ValueError, AttributeError):
                pass
        return list(dict.fromkeys(networks))

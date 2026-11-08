# SPDX-License-Identifier: GPL-3.0-or-later
import json
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from backend.downloads import DownloadedProfile, fetch_profile, subscription_name
from backend.ipc import OperationError
from backend.manager import Manager
from backend.phone import BoundedServer, Pairing, lan_interfaces
from backend.transport import PanelHandler


class Core:
    def __init__(self, events):
        self.events = events
        self.prepared = None
        self.reject = None

    def validate(self, source):
        if source.read_bytes() == b"bad":
            raise OperationError("Bad YAML.")

    def prepare(self, source, settings):
        self.events.append("prepare")
        self.prepared = (source.read_bytes(), settings.copy()) if source else None
        return self.prepared

    def verify(self, receipt):
        self.events.append("verify")
        if not receipt or receipt[0] == self.reject:
            raise OperationError("The core rejected the profile.")

    def receipt(self):
        return self.prepared

    def check_controller_available(self):
        pass

    def status(self):
        return {"effective": bool(self.prepared)}

    def fake_ip_networks(self, path):
        return []


class Lifecycle:
    def __init__(self):
        self.active = False
        self.ready = False
        self.auto = False
        self.events = []
        self.deadline = None
        self.recovery = False
        self.pending = False
        self.version = "v0.9.3"

    def __call__(self, operation, *args):
        self.events.append(operation)
        if operation in ("start", "bootstrap"):
            self.active = True
        if operation in ("stop", "halt"):
            self.active = False
        if operation == "set_config_ready":
            self.ready = args[0]
        if operation == "arm_tun_rollback":
            self.deadline = int(time.time()) + 60
        if operation == "confirm_tun":
            self.deadline = None
        if operation == "clear_recovery":
            self.recovery = False
        if operation == "begin_upgrade":
            self.pending = True
            self.version = "v0.9.4"
            return {"was_running": self.active}
        if operation == "rollback_upgrade":
            self.pending = False
            self.version = "v0.9.3"
        return {
            "installed_version": self.version, "running": self.active,
            "autostart_enabled": self.auto, "tun_deadline": self.deadline,
            "recovery_pending": self.recovery, "upgrade_pending": self.pending,
        }.get(operation)


class ManagerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.lifecycle = Lifecycle()
        self.core = Core(self.lifecycle.events)
        self.manager = Manager(Path(self.tmp.name), self.core, self.lifecycle)

    def test_start_requires_profile_and_reports_actual_effective(self):
        with self.assertRaisesRegex(OperationError, "valid configuration"):
            self.manager.start()
        self.manager.save_profile("A", b"rules: [MATCH,DIRECT]")
        self.assertTrue(self.lifecycle.ready)
        self.assertFalse(self.lifecycle.active)
        self.assertIsNone(self.manager.get_status()["effective"])
        self.manager.start()
        self.assertEqual(self.manager.get_status()["effective"], self.manager.state["selected"])
        self.manager.stop()
        self.assertIsNone(self.manager.get_status()["effective"])

    def test_switch_failure_restores_selected_and_running(self):
        self.manager.save_profile("A", b"first")
        self.manager.save_profile("B", b"second")
        first, second = self.manager.state["profiles"]
        self.manager.start()
        self.core.reject = b"second"
        with self.assertRaisesRegex(OperationError, "core rejected"):
            self.manager.select_profile(second)
        self.assertEqual(self.manager.get_status()["effective"], first)
        self.assertEqual(self.core.prepared[0], b"first")
        self.assertTrue(self.lifecycle.active)

    def test_first_enable_requires_trial_and_recovery_leaves_service_stopped(self):
        self.manager.save_profile("A", b"first")
        self.manager.start()
        self.manager.set_settings({"tun": True})
        self.assertLess(self.lifecycle.events.index("arm_tun_rollback"),
                        self.lifecycle.events.index("prepare", self.lifecycle.events.index("arm_tun_rollback")))
        self.assertIsNotNone(self.lifecycle.deadline)
        self.lifecycle.active = False
        self.lifecycle.deadline = None
        self.lifecycle.recovery = True
        self.manager.tick()
        self.assertFalse(self.core.prepared[1]["tun"])
        self.assertFalse(self.lifecycle.active)
        self.assertFalse(self.lifecycle.recovery)

    def test_download_manual_scheduled_ua_and_failed_refresh_retains_data(self):
        seen = []
        content = [b"first", b"second", b"third", b"bad"]

        class Server(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                seen.append(self.headers["User-Agent"])
                data = content.pop(0)
                self.send_response(200)
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Content-Disposition", "attachment; filename*=UTF-8''%E6%B5%8B%E8%AF%95.yaml")
                self.end_headers()
                self.wfile.write(data)

        with ThreadingHTTPServer(("127.0.0.1", 0), Server) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.addCleanup(server.shutdown)
            url = f"http://127.0.0.1:{server.server_port}/subscription"
            self.manager.save_user_agent("", "Custom", "ClashManager-Observer/1")
            self.manager.select_user_agent(next(iter(self.manager.state["agents"])))
            self.manager.import_subscription(url)
            profile = self.manager.state["selected"]
            self.assertEqual(self.manager.state["profiles"][profile]["name"], "测试")
            self.manager.refresh_profile(profile)
            self.manager.edit_subscription(profile, "", "Feed", 1)
            state = self.manager.state
            state["profiles"][profile]["attempted_at"] = time.time() - 3601
            self.manager.tick()
            good_blob = self.manager.blob()
            self.assertEqual(good_blob.read_bytes(), b"third")
            self.assertEqual(self.manager.state["profiles"][profile]["name"], "Feed")
            self.assertEqual(seen, ["ClashManager-Observer/1"] * 3)
            with self.assertRaisesRegex(OperationError, "Bad YAML"):
                self.manager.refresh_profile(profile)
            self.assertEqual(self.manager.blob(), good_blob)
            self.assertTrue(self.manager.state["profiles"][profile]["update_error"])
            with self.assertRaisesRegex(OperationError, "public subscription"):
                fetch_profile(url, "Test", public_only=True)
            server.shutdown()

    def test_remote_import_uses_provider_name_unless_custom_name_is_present(self):
        self.manager.pairing.deadline = time.monotonic() + 30
        url = "https://example.com/subscription"
        with patch("backend.manager.fetch_profile", return_value=DownloadedProfile(b"first", "服务端名称")) as fetch:
            self.manager.phone_import({"url": url})
            self.manager.phone_import({"url": url, "name": "自定义名称"})
        with patch("backend.manager.fetch_profile", return_value=DownloadedProfile(b"first", None)):
            self.manager.phone_import({"url": url, "name": ""})
        self.assertEqual([profile["name"] for profile in self.manager.state["profiles"].values()],
                         ["服务端名称", "自定义名称", "Subscription"])
        fetch.assert_called_with(url, self.manager.selected_ua(), public_only=True)

    def test_subscription_name_accepts_encoded_metadata_and_falls_back_on_errors(self):
        self.assertEqual(subscription_name({"Profile-Title": "base64:5rWL6K+V"}), "测试")
        self.assertEqual(subscription_name({
            "Profile-Title": "base64:!!!",
            "Content-Disposition": "attachment; filename=backup.yaml; filename*=UTF-8''%E6%B5%8B%E8%AF%95.yml",
        }), "测试")
        self.assertEqual(subscription_name({
            "Content-Disposition": "attachment; filename=backup.yaml; filename*=UTF-8''%FF.yaml",
        }), "backup")
        self.assertIsNone(subscription_name({"Profile-Title": "\x00bad"}))

    def test_phone_route_rejects_unauthenticated_and_rebind_hosts(self):
        import ipaddress
        saved = []
        pair = Pairing(saved.append)
        with patch("backend.phone.lan_interfaces", return_value=[ipaddress.ip_interface("127.0.0.1/8")]), \
                patch("backend.phone.mdns_host", return_value=None):
            pair.open([])
            self.addCleanup(pair.close)
            url = pair.status()["url"].split("#")[0]
            with urllib.request.urlopen(urllib.request.Request(url, headers={"Accept-Language": "zh-CN,en;q=0.9"})) as response:
                page = response.read().decode()
                self.assertIn('lang="zh-CN"', page)
                self.assertIn("配置名称（可选）", page)
            with urllib.request.urlopen(urllib.request.Request(url, headers={"Accept-Language": "en-US,zh;q=0.9"})) as response:
                self.assertIn("Profile name (optional)", response.read().decode())
            body = json.dumps({"name": "Test", "yaml": "rules: [MATCH,DIRECT]"}).encode()
            headers = {"Content-Type": "application/json", "Origin": url.rstrip("/"), "Accept-Language": "zh-CN"}
            with self.assertRaises(urllib.error.HTTPError) as failed:
                urllib.request.urlopen(urllib.request.Request(url + "import", body, headers))
            self.assertEqual(failed.exception.code, 403)
            self.assertEqual(json.load(failed.exception)["error"], "配对无效或已到期。")
            headers["X-Clash-Pairing"] = pair.token
            with urllib.request.urlopen(urllib.request.Request(url + "import", body, headers)) as response:
                self.assertEqual(response.status, 200)
            with self.assertRaises(urllib.error.HTTPError):
                urllib.request.urlopen(urllib.request.Request(url, headers={"Host": "other.invalid"}))
            pair.deadline = time.monotonic() - 1
            with self.assertRaises(urllib.error.HTTPError):
                urllib.request.urlopen(urllib.request.Request(url + "import", body, headers))
            self.assertEqual(len(saved), 1)

    def test_lan_addresses_exclude_virtual_and_profile_fake_ip_ranges(self):
        def link(name, *addresses):
            return {"ifname": name, "addr_info": [{"local": addr, "prefixlen": 24} for addr in addresses]}

        output = json.dumps([
            link("lo", "127.0.0.1"), link("cm-tun", "10.20.0.1"),
            link("wlan0", "192.168.1.10", "198.18.0.1", "10.90.1.1"),
        ])
        with patch("backend.phone.subprocess.run") as ip, \
                patch("backend.phone.Path.exists", autospec=True, side_effect=lambda path: path.parent.name == "wlan0"):
            ip.return_value.stdout = output
            self.assertEqual([str(item.ip) for item in lan_interfaces(["10.90.0.0/16"])], ["192.168.1.10"])

    def test_panel_transport_requires_decky_token_and_fixed_methods(self):
        with BoundedServer(("127.0.0.1", 0), PanelHandler) as server:
            server.token = b"test-token"
            server.methods = {"status": lambda: {"running": False}}
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.addCleanup(server.shutdown)
            url = f"http://127.0.0.1:{server.server_port}/rpc"

            def request(token, method):
                body = json.dumps({"auth": token, "method": method, "args": []}).encode()
                return urllib.request.urlopen(urllib.request.Request(url, body))

            with self.assertRaises(urllib.error.HTTPError) as failed:
                request("wrong", "status")
            self.assertEqual(failed.exception.code, 403)
            with self.assertRaises(urllib.error.HTTPError) as failed:
                request("test-token", "__dict__")
            self.assertEqual(failed.exception.code, 400)
            with request("test-token", "status") as response:
                self.assertEqual(json.load(response), {"running": False})
            server.shutdown()

    def test_upgrade_verification_failure_rolls_back(self):
        self.manager.save_profile("A", b"first")
        self.manager.start()
        with patch.object(self.manager, "bootstrap"), \
                patch.object(self.core, "verify", side_effect=[OperationError("Candidate failed."), None]):
            with self.assertRaisesRegex(OperationError, "Candidate failed"):
                self.manager.upgrade()
        status = self.manager.get_status()
        self.assertEqual(status["state"], "upgrade_rolled_back")
        self.assertEqual(status["version"], "v0.9.3")
        self.assertEqual(status["effective"], status["selected"])
        self.assertEqual(self.manager.blob().read_bytes(), b"first")


if __name__ == "__main__":
    unittest.main()

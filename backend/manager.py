# SPDX-License-Identifier: GPL-3.0-or-later
"""Profile and preference state. Runs exclusively as the deck account."""

import copy
import json
import os
import re
import shutil
import stat
import tempfile
import threading
import time
import uuid
from pathlib import Path

from .downloads import MAX_PROFILE, fetch_profile, subscription_url
from .ipc import OperationError
from .phone import Pairing

DEFAULT_SETTINGS = {"mode": "rule", "tun": False, "mixed_port": 17890,
                    "log_level": "warning", "lan_bypass": True}
PRESETS = [
    {"id": "flclash", "name": "FlClash", "value": "FlClash/0.9.3", "preset": True},
    {"id": "mihomo", "name": "Mihomo", "value": "mihomo", "preset": True},
    {"id": "clash", "name": "Clash", "value": "Clash", "preset": True},
]


def atomic_write(path, content):
    fd, temporary = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as file:
            file.write(content)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, path)
        fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        Path(temporary).unlink(missing_ok=True)


def write_json(path, value):
    atomic_write(path, json.dumps(value, ensure_ascii=True, allow_nan=False).encode())


def label(value, fallback):
    if not isinstance(value, str) or len(value) > 80 or any(ord(c) < 32 for c in value):
        raise OperationError("Use a name of up to 80 characters.")
    return value.strip() or fallback


def boot_id():
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    except OSError:
        return None


class Manager:
    def __init__(self, data, client, root, dashboard=None, deployment=None):
        self.data = data
        self.client = client
        self.root = root
        self.directory = data / "manager"
        self.directory.mkdir(mode=0o700, exist_ok=True)
        self.blobs = self.directory / "profiles"
        self.blobs.mkdir(mode=0o700, exist_ok=True)
        self.store = self.directory / "state.json"
        self.journal = self.directory / "applying.json"
        self.lock = threading.RLock()
        self.ending = threading.Event()
        self.pairing = Pairing(self.phone_import)
        self.dashboard = dashboard
        self.deployment = deployment
        self.state = self.load()
        self.transition = None
        self.last_status = self.status_base()

    def load(self):
        if self.store.exists():
            return json.loads(self.store.read_bytes())
        return {"profiles": {}, "selected": None, "agents": {}, "selected_ua": "flclash",
                "settings": DEFAULT_SETTINGS.copy(), "available_version": None,
                "problem": None, "failure_state": None, "auto_install": True}

    def save(self, state):
        write_json(self.store, state)
        self.state = state

    def change(self, **fields):
        self.save({**self.state, **fields})

    def blob(self, state=None):
        state = state if state is not None else self.state
        profile = state["profiles"].get(state["selected"])
        return self.blobs / profile["blob"] if profile else None

    def collect_blobs(self):
        keep = {profile["blob"] for profile in self.state["profiles"].values()}
        for path in self.blobs.iterdir():
            if path.name not in keep and path.is_file():
                path.unlink(missing_ok=True)

    def require_client(self):
        if not self.root("installed_version"):
            raise OperationError("Install FlClash first.")

    def selected_ua(self, state=None):
        state = state if state is not None else self.state
        agents = {entry["id"]: entry for entry in PRESETS} | state["agents"]
        return agents[state["selected_ua"]]["value"]

    def prepare(self, state, with_profile=True):
        settings = {**state["settings"], "user_agent": self.selected_ua(state)}
        return self.client.prepare(self.blob(state) if with_profile else None, settings)

    def tun_guard(self):
        if self.root("tun_deadline") or self.root("recovery_pending"):
            raise OperationError("Finish or cancel the current TUN trial first.")

    def bootstrap(self):
        if not self.client.initialized():
            self.root("set_config_ready", False)
            self.root("halt")
            self.prepare(self.state, with_profile=False)
            try:
                self.root("bootstrap")
                self.client.wait_initialized()
            finally:
                self.root("halt")

    def install(self):
        self.transition = "installing"
        try:
            self.root("wait_for_cleanup")
            self.root("install")
            self.bootstrap()
            if self.blob() and not self.root("running"):
                self.apply(self.state, run=False)
            self.change(problem=None, failure_state=None, auto_install=True)
        except Exception as error:
            problem = str(error) if isinstance(error, OperationError) else "FlClash could not finish setup."
            self.change(problem=problem, failure_state="install_failed")
            raise OperationError(problem) from None
        finally:
            self.transition = None

    def apply(self, next_state, *, run=None, allow_recovery=False):
        """Stage only while stopped. Keep the old state authoritative until verified."""
        previous = self.state
        was_running = self.root("running")
        run = was_running if run is None else run
        if run and not self.blob(next_state):
            raise OperationError("Import and select a valid configuration first.")
        write_json(self.journal, {"was_running": was_running, "boot": boot_id()})
        try:
            self.root("set_config_ready", False)
            self.root("halt")
            receipt = self.prepare(next_state)
            if run:
                self.client.check_controller_available()
                self.root("bootstrap")
                self.client.verify(receipt)
            self.save(next_state)
            if allow_recovery:
                self.root("clear_recovery")
            self.root("set_config_ready", bool(self.blob(next_state)))
            self.journal.unlink()
        except Exception:
            try:
                self.restore(previous, was_running and not allow_recovery)
                if self.state is not previous:
                    self.save(previous)
                self.journal.unlink()
            except Exception:
                self.root("set_config_ready", False)
                self.root("halt")
                raise OperationError("The change failed and the previous configuration could not be restarted. "
                                     "The managed service is stopped.") from None
            raise

    def restore(self, state, run):
        self.root("set_config_ready", False)
        self.root("halt")
        receipt = self.prepare(state)
        if run and receipt:
            self.client.check_controller_available()
            self.root("bootstrap")
            self.client.verify(receipt)
        self.root("set_config_ready", bool(self.blob(state)))

    def restore_interrupted(self):
        if self.root("upgrade_pending"):
            self.root("rollback_upgrade")
            self.state = self.load()
            self.change(problem="An interrupted upgrade was rolled back.", failure_state="upgrade_rolled_back")
        if self.root("recovery_pending"):
            self.recover_tun()
        if self.journal.exists():
            transaction = json.loads(self.journal.read_bytes())
            current_boot = boot_id()
            resume = bool(current_boot and transaction.get("boot") == current_boot
                          and transaction.get("was_running") and self.blob())
            self.restore(self.state, resume)
            self.journal.unlink()

    def start(self):
        self.require_client()
        if not self.blob():
            raise OperationError("Import and select a valid configuration before starting.")
        self.tun_guard()
        try:
            if not self.root("running"):
                self.client.check_controller_available()
                self.root("start")
            self.client.verify(self.client.receipt())
        except OperationError as error:
            self.root("stop")
            self.change(problem=str(error), failure_state="tun_failed" if self.state["settings"]["tun"] else "error")
            raise
        self.change(problem=None, failure_state=None)

    def stop(self):
        if self.root("recovery_pending") or self.root("tun_deadline"):
            self.cancel_tun()
        else:
            self.root("stop")

    def set_autostart(self, enabled):
        if type(enabled) is not bool:
            raise OperationError("Invalid autostart setting.")
        self.root("set_autostart", enabled)

    def check_update(self):
        update = self.root("check_update")
        self.change(available_version=update["available"], published_version=update["latest"],
                    problem=None)

    def upgrade(self):
        self.require_client()
        self.tun_guard()
        previous = self.state
        context = {}
        try:
            context = self.root("begin_upgrade")
            self.bootstrap()
            receipt = self.prepare(self.state)
            if receipt:
                self.client.check_controller_available()
            self.root("verify_upgrade_start", bool(receipt))
            if receipt:
                self.client.verify(receipt)
            else:
                self.client.wait_initialized()
            self.root("commit_upgrade")
            self.change(available_version=None, problem=None, failure_state=None)
        except Exception as error:
            pending = self.root("upgrade_pending")
            rolled_back = pending
            if pending:
                self.root("rollback_upgrade")
                self.state = self.load()
            problem = str(error) if isinstance(error, OperationError) else "The upgrade failed during verification."
            rolled_back |= "prior FlClash release and data were restored" in problem
            if rolled_back and context.get("was_running") and self.blob(previous):
                try:
                    self.client.verify(self.client.receipt())
                except OperationError:
                    self.root("stop")
                    problem += " The previous service did not pass runtime verification and was stopped."
            self.change(problem=problem, failure_state="upgrade_rolled_back" if rolled_back else None)
            raise OperationError(problem) from None

    def save_blob(self, content):
        if not isinstance(content, bytes) or not 0 < len(content) <= MAX_PROFILE:
            raise OperationError("Provide a non-empty YAML file of up to 4 MiB.")
        path = self.blobs / (uuid.uuid4().hex + ".yaml")
        atomic_write(path, content)
        try:
            self.client.validate(path)
        except Exception:
            path.unlink()
            raise
        return path.name

    def save_profile(self, name, content, url=None, public_only=False):
        self.require_client()
        if len(self.state["profiles"]) >= 100:
            raise OperationError("Delete a saved profile before importing another.")
        profile_id = uuid.uuid4().hex
        blob = self.save_blob(content)
        state = copy.deepcopy(self.state)
        state["profiles"][profile_id] = {
            "id": profile_id, "name": name, "kind": "subscription" if url else "file",
            "blob": blob, "url": url, "public_only": public_only,
            "updated_at": int(time.time()), "attempted_at": int(time.time()),
            "update_error": None, "refresh_hours": 0,
        }
        try:
            if not state["selected"]:
                self.tun_guard()
                state["selected"] = profile_id
                self.apply(state, run=False)
            else:
                self.save(state)
        finally:
            self.collect_blobs()

    def import_subscription(self, url, name="", public_only=False):
        self.require_client()
        url = subscription_url(url).geturl()
        custom_name = label(name, "")
        download = fetch_profile(url, self.selected_ua(), public_only=public_only)
        self.save_profile(custom_name or download.name or "Subscription", download.content, url, public_only)

    def import_file(self, path, name):
        self.require_client()
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as file:
                if not stat.S_ISREG(os.fstat(file.fileno()).st_mode):
                    raise OSError
                content = file.read(MAX_PROFILE + 1)
        except (OSError, TypeError, ValueError):
            raise OperationError("Could not read the selected YAML file as deck.") from None
        self.save_profile(label(name, "Local YAML"), content)

    def phone_import(self, payload):
        with self.lock:
            if not self.pairing.active:
                raise OperationError("Pairing expired. Open a new pairing on the Deck.")
            fields = set(payload) - {"name"}
            name = payload.get("name", "")
            if fields == {"url"}:
                self.import_subscription(payload["url"], name, True)
            elif fields == {"yaml"} and isinstance(payload["yaml"], str):
                self.save_profile(label(name, "Remote YAML"), payload["yaml"].encode())
            else:
                raise OperationError("Choose one subscription URL or YAML file.")

    def profile(self, profile_id, subscription=False):
        profile = self.state["profiles"].get(profile_id)
        if not profile or (subscription and profile["kind"] != "subscription"):
            raise OperationError("Profile not found.")
        return profile

    def select_profile(self, profile_id):
        self.require_client()
        self.profile(profile_id)
        self.tun_guard()
        if self.state["selected"] != profile_id:
            self.apply({**self.state, "selected": profile_id, "problem": None, "failure_state": None})

    def edit_subscription(self, profile_id, url, name, refresh_hours):
        self.profile(profile_id, True)
        if type(refresh_hours) not in (int, float) or refresh_hours not in (0, 1, 6, 12, 24, 48, 168):
            raise OperationError("Choose one of the supported refresh intervals.")
        state = copy.deepcopy(self.state)
        profile = state["profiles"][profile_id]
        profile["name"] = label(name, profile["name"])
        profile["refresh_hours"] = refresh_hours
        if url and subscription_url(url).geturl() != profile["url"]:
            profile["url"] = subscription_url(url).geturl()
            profile["public_only"] = False
            self.refresh_profile(profile_id, state)
        else:
            self.save(state)

    def refresh_profile(self, profile_id, state=None):
        self.require_client()
        self.profile(profile_id, True)
        state = copy.deepcopy(self.state) if state is None else state
        profile = state["profiles"][profile_id]
        try:
            if state["selected"] == profile_id:
                self.tun_guard()
            download = fetch_profile(profile["url"], self.selected_ua(), public_only=profile["public_only"])
            profile.update(blob=self.save_blob(download.content), updated_at=int(time.time()),
                           attempted_at=int(time.time()), update_error=None)
            if state["selected"] == profile_id:
                self.apply(state)
            else:
                self.save(state)
        except OperationError as error:
            failed = copy.deepcopy(self.state)
            failed["profiles"][profile_id].update(attempted_at=int(time.time()), update_error=str(error))
            self.save(failed)
            raise
        finally:
            self.collect_blobs()

    def delete_profile(self, profile_id):
        self.profile(profile_id)
        state = copy.deepcopy(self.state)
        del state["profiles"][profile_id]
        if self.state["selected"] == profile_id:
            self.tun_guard()
            state["selected"] = None
            if self.root("installed_version"):
                self.apply(state, run=False)
            else:
                self.save(state)
        else:
            self.save(state)
        self.collect_blobs()

    def save_user_agent(self, agent_id, name, value):
        if not isinstance(value, str) or not re.fullmatch(r"[ -~]{1,256}", value) or not value.strip():
            raise OperationError("Use a printable HTTP User-Agent of up to 256 characters.")
        agents = self.state["agents"].copy()
        if agent_id and agent_id not in agents:
            raise OperationError("Only custom User-Agents can be edited.")
        if len(agents) >= 24 and not agent_id:
            raise OperationError("Delete a custom User-Agent before adding another.")
        agent_id = agent_id or uuid.uuid4().hex
        agents[agent_id] = {"id": agent_id, "name": label(name, "Custom"), "value": value}
        self.update_agents(agents, self.state["selected_ua"])

    def select_user_agent(self, agent_id):
        if agent_id not in self.state["agents"] and agent_id not in {preset["id"] for preset in PRESETS}:
            raise OperationError("User-Agent not found.")
        self.update_agents(self.state["agents"], agent_id)

    def delete_user_agent(self, agent_id):
        agents = self.state["agents"].copy()
        if agent_id not in agents:
            raise OperationError("Only custom User-Agents can be deleted.")
        del agents[agent_id]
        selected = "flclash" if self.state["selected_ua"] == agent_id else self.state["selected_ua"]
        self.update_agents(agents, selected)

    def update_agents(self, agents, selected):
        state = {**self.state, "agents": agents, "selected_ua": selected}
        if self.selected_ua(state) != self.selected_ua() and self.blob() and self.root("installed_version"):
            self.tun_guard()
            self.apply(state)
        else:
            self.save(state)

    def set_settings(self, patch):
        self.require_client()
        self.tun_guard()
        if not isinstance(patch, dict) or set(patch) - set(DEFAULT_SETTINGS):
            raise OperationError("Unsupported setting.")
        settings = {**self.state["settings"], **patch}
        if (settings["mode"] not in ("rule", "global", "direct")
                or settings["log_level"] not in ("silent", "error", "warning", "info", "debug")
                or type(settings["mixed_port"]) is not int or not 1024 <= settings["mixed_port"] <= 65535
                or settings["mixed_port"] == 9090 or type(settings["tun"]) is not bool
                or type(settings["lan_bypass"]) is not bool):
            raise OperationError("Invalid proxy setting.")
        if not settings["lan_bypass"] and settings["tun"]:
            raise OperationError("TUN requires LAN bypass to preserve local access.")
        trial = settings["tun"] and settings != self.state["settings"]
        if trial and (not self.blob() or not self.root("running")):
            raise OperationError("Start a valid profile before enabling or changing TUN.")
        if trial:
            self.root("arm_tun_rollback")
        try:
            self.apply({**self.state, "settings": settings, "problem": None, "failure_state": None})
        except OperationError as error:
            if trial:
                self.root("confirm_tun")
                self.change(problem=str(error), failure_state="tun_failed")
            raise

    def confirm_tun(self):
        if self.root("recovery_pending") or not self.root("tun_deadline"):
            raise OperationError("There is no active TUN trial to confirm.")
        self.client.verify(self.client.receipt())
        self.root("confirm_tun")

    def cancel_tun(self):
        self.root("cancel_tun")
        self.recover_tun()

    def recover_tun(self):
        state = {**self.state, "settings": {**self.state["settings"], "tun": False},
                 "problem": "Network recovery stopped FlClash and disabled TUN. Start it when ready.",
                 "failure_state": "tun_failed"}
        self.apply(state, run=False, allow_recovery=True)

    def open_phone(self):
        self.require_client()
        self.pairing.open(self.client.fake_ip_networks(self.blob()))

    def close_phone(self):
        self.pairing.close()

    def open_dashboard(self):
        if not self.dashboard or not self.root("running"):
            raise OperationError("Start a valid configuration before opening the dashboard.")
        self.dashboard.open()

    def uninstall(self):
        self.pairing.close()
        self.root("uninstall")
        self.change(auto_install=False, deployment=self.deployment, problem=None, failure_state=None,
                    settings={**self.state["settings"], "tun": False})

    def purge_data(self):
        if self.root("installed_version"):
            raise OperationError("Uninstall the managed client before deleting its saved data.")
        self.pairing.close()
        self.root("purge_snapshot")
        for child in self.data.iterdir():
            if child == self.directory:
                continue
            if child.is_dir() and not child.is_symlink():
                shutil.rmtree(child)
            else:
                child.unlink()
        self.store.unlink(missing_ok=True)
        self.journal.unlink(missing_ok=True)
        self.change(**{**self.load(), "auto_install": False, "deployment": self.deployment})
        self.collect_blobs()

    def status_base(self):
        profiles = [{key: profile[key] for key in ("id", "name", "kind", "updated_at",
                                                    "update_error", "refresh_hours")}
                    for profile in self.state["profiles"].values()]
        return {"profiles": profiles, "selected": self.state["selected"], "effective": None,
                "user_agents": PRESETS + list(self.state["agents"].values()),
                "selected_ua": self.state["selected_ua"], "settings": self.state["settings"],
                "available_version": self.state["available_version"], "problem": self.state["problem"],
                "published_version": self.state.get("published_version"),
                "version": None, "installed": False, "running": False, "autostart": False,
                "state": "not_installed", "tun_pending_until": None,
                "phone": self.pairing.status(), "dashboard_url": None}

    def get_status(self):
        if not self.lock.acquire(blocking=False):
            return {**self.last_status, "state": self.transition or self.last_status["state"]}
        try:
            status = self.status_base()
            version = self.root("installed_version")
            running = bool(version and self.root("running"))
            effective = bool(running and self.blob() and self.client.status().get("effective"))
            state = self.transition or self.state["failure_state"]
            problem = status["problem"]
            if not state:
                if not version:
                    state = "not_installed"
                elif not self.blob():
                    state = "waiting_config"
                    problem = "Import a valid configuration before starting FlClash."
                elif effective:
                    state = "running"
                elif running:
                    state = "error"
                    problem = "FlClash is running, but the kernel did not confirm the selected configuration."
                else:
                    state = "stopped"
            status.update(version=version, installed=bool(version), running=running, state=state,
                          problem=problem, autostart=self.root("autostart_enabled"),
                          effective=self.state["selected"] if effective else None,
                          tun_pending_until=self.root("tun_deadline"),
                          dashboard_url=self.dashboard.url if self.dashboard and effective else None)
            self.last_status = status
            return status
        finally:
            self.lock.release()

    def tick(self):
        with self.lock:
            if self.pairing.active or self.pairing.server:
                self.pairing.update(self.client.fake_ip_networks(self.blob()))
            if self.dashboard:
                self.dashboard.tick()
            if self.root("recovery_pending"):
                self.recover_tun()
            if not self.root("installed_version") or self.root("tun_deadline"):
                return
            now = time.time()
            for profile in list(self.state["profiles"].values()):
                interval = profile["refresh_hours"] * 3600
                if interval and now - profile["attempted_at"] >= interval:
                    try:
                        self.refresh_profile(profile["id"])
                    except OperationError:
                        pass
                    break

    def background(self):
        with self.lock:
            try:
                self.root("wait_for_cleanup")
                self.restore_interrupted()
                if not self.state["auto_install"] and self.state.get("deployment") != self.deployment:
                    self.change(auto_install=True)
                if self.state["auto_install"] and not self.root("installed_version"):
                    self.install()
                elif self.state["auto_install"] and not self.client.initialized():
                    self.install()
            except OperationError as error:
                if not self.state["failure_state"]:
                    self.change(problem=str(error), failure_state="error")
        while not self.ending.wait(5):
            try:
                self.tick()
            except (EOFError, BrokenPipeError):
                return
            except Exception as error:
                problem = str(error) if isinstance(error, OperationError) else "A background task could not finish."
                with self.lock:
                    if self.state["problem"] != problem:
                        self.change(problem=problem)

    def invoke(self, method, *args):
        with self.lock:
            try:
                if self.journal.exists() and method not in {"stop", "cancel_tun", "uninstall", "purge_data"}:
                    self.restore_interrupted()
                method_fn = getattr(self, method)
                method_fn(*args)
                return {"ok": True}
            except OperationError as error:
                if str(error) != self.state["problem"]:
                    self.change(problem=str(error))
                return {"ok": False, "error": str(error)}
            except Exception:
                return {"ok": False, "error": "The operation failed internally. Retry from the panel."}

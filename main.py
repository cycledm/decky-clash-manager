# SPDX-License-Identifier: GPL-3.0-or-later
"""Decky entry point. Only the lifecycle broker retains root."""

import asyncio
import os
import socket
import subprocess
import sys
import threading
from pathlib import Path

PLUGIN_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(PLUGIN_DIR))

from backend.ipc import Channel, OperationError, serve
from backend.lifecycle import Lifecycle, LifecycleError

ROOT = Path("/home/clash-manager")
DATA = ROOT / "data"

READ_METHODS = ("installed_version", "running", "autostart_enabled", "upgrade_pending",
                "recovery_pending", "tun_deadline", "wait_for_cleanup", "controller_owned")
ROOT_ACTIONS = ("install", "bootstrap", "halt", "start", "stop", "check_update",
                "begin_upgrade", "commit_upgrade", "rollback_upgrade", "arm_tun_rollback",
                "confirm_tun", "cancel_tun", "clear_recovery", "uninstall", "purge_snapshot")
ROOT_BOOL_ACTIONS = ("set_autostart", "set_config_ready", "verify_upgrade_start")

def strict_bool(operation):
    def call(enabled):
        if type(enabled) is not bool:
            raise OperationError("Invalid service setting.")
        return operation(enabled)
    return call


class Plugin:
    def __init__(self):
        self.channel = None
        self.process = None
        self.lifecycle = None
        self.broker = None
        self.initialization_error = None

    def _launch_worker(self):
        if os.geteuid() != 0:
            raise OperationError("Clash Manager needs Decky's root plugin permission.")
        self.lifecycle = Lifecycle(root=ROOT, data=DATA, manifest=PLUGIN_DIR / "releases.json")
        self.lifecycle.initialize()
        methods = {name: getattr(self.lifecycle, name) for name in (*READ_METHODS, *ROOT_ACTIONS)}
        methods.update({name: strict_bool(getattr(self.lifecycle, name)) for name in ROOT_BOOL_ACTIONS})
        root_side, worker_root = socket.socketpair()
        panel_side, worker_panel = socket.socketpair()
        try:
            self.process = subprocess.Popen(
                ["/usr/bin/python3", "-I", "-B", str(PLUGIN_DIR / "backend" / "worker.py"),
                 str(worker_root.fileno()), str(worker_panel.fileno()), str(DATA)],
                user="deck", group="deck", extra_groups=[], cwd="/",
                env={"PATH": "/usr/bin:/bin", "HOME": "/home/deck", "USER": "deck", "LANG": "C.UTF-8"},
                pass_fds=(worker_root.fileno(), worker_panel.fileno()),
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        except OSError:
            root_side.close()
            panel_side.close()
            raise OperationError("Could not start the unprivileged Deck worker.") from None
        finally:
            worker_root.close()
            worker_panel.close()
        self.broker = threading.Thread(
            target=serve, args=(Channel(root_side), methods, (OperationError, LifecycleError)), daemon=True,
        )
        self.broker.start()
        self.channel = Channel(panel_side)

    async def _main(self):
        try:
            await asyncio.to_thread(self._launch_worker)
        except (OperationError, LifecycleError) as error:
            self.initialization_error = str(error)
        except Exception:
            self.initialization_error = "Could not initialize the managed service."

    async def get_transport(self):
        if self.channel:
            try:
                return await asyncio.to_thread(self.channel.request, "get_transport")
            except (OperationError, OSError, EOFError, ValueError):
                pass
        error = self.initialization_error or "The Clash Manager worker is unavailable. Reload the plugin."
        return {"error": error}

    async def _uninstall(self):
        # The Loader can remove the plugin independently of the panel.
        if self.lifecycle:
            await asyncio.to_thread(self.lifecycle.queue_cleanup)

    async def _unload(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                await asyncio.to_thread(self.process.wait, 1)
            except subprocess.TimeoutExpired:
                self.process.kill()
                await asyncio.to_thread(self.process.wait)
        if self.channel:
            self.channel.close()
            self.channel = None

#!/usr/bin/python3 -I
# SPDX-License-Identifier: GPL-3.0-or-later
"""Systemd-owned boot and emergency recovery entrypoint."""

import contextlib
import fcntl
import json
import os
import stat
import subprocess
import sys
import time
from pathlib import Path

APP = "clash-manager-flclash.service"
HELPER = "clash-manager-flclash-helper.service"
AUTOSTART = "clash-manager-session.timer"
TRIAL = "clash-manager-tun-rollback"
RUNTIME = Path("/run/clash-manager-flclash")
ROOT = Path(__file__).resolve().parent
FLAGS = ROOT / "flags"
TUN_DEVICE = "cm-tun"
TUN_TABLE = 20291
TUN_RULES = range(30291, 30302)
SAFE_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C"}


def command(*args):
    return subprocess.run(
        args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env=SAFE_ENV,
        timeout=30, check=False,
    ).returncode


@contextlib.contextmanager
def trial_lock(root):
    with (root / "private" / "trial.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def network_objects(*args):
    result = subprocess.run(
        ["/usr/bin/ip", "-json", *args], capture_output=True,
        env=SAFE_ENV, timeout=10, check=True,
    )
    return json.loads(result.stdout)


def tun_slot_available():
    if any(link["ifname"] == TUN_DEVICE for link in network_objects("link", "show")):
        return False
    for family in ("-4", "-6"):
        if any(rule["priority"] in TUN_RULES for rule in network_objects(family, "rule", "show")):
            return False
        routes = network_objects(family, "route", "show", "table", "all")
        if any(str(route.get("table")) == str(TUN_TABLE) for route in routes):
            return False
    return True


def clean_tun(root):
    if not (root / "flags" / "tun-owned").is_file():
        return
    # The first trial reserves these indexes only when unused. Upstream
    # sing-tun normally clears them during SIGTERM. This also handles a
    # forced stop after the Core was unable to finish its own cleanup.
    for family in ("-4", "-6"):
        for rule in network_objects(family, "rule", "show"):
            if rule["priority"] in TUN_RULES:
                command("/usr/bin/ip", family, "rule", "del", "pref", str(rule["priority"]))
        command("/usr/bin/ip", family, "route", "flush", "table", str(TUN_TABLE))
    if any(link["ifname"] == TUN_DEVICE for link in network_objects("link", "show")):
        command("/usr/bin/resolvectl", "revert", TUN_DEVICE)
        command("/usr/bin/ip", "link", "del", TUN_DEVICE)


def recover(timed=False, root=ROOT):
    flags = root / "flags"
    with trial_lock(root):
        deadline = flags / "tun-deadline"
        if timed and not deadline.exists():
            return 0
        RUNTIME.mkdir(mode=0o755, exist_ok=True)
        metadata = RUNTIME.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
            return 1
        (flags / "recovery").touch()
        (RUNTIME / "manual-stop").touch()
        (RUNTIME / "bootstrap").unlink(missing_ok=True)
        deadline.unlink(missing_ok=True)
        (RUNTIME / "tun-trial").unlink(missing_ok=True)
        # Stopping the official Helper lets it send SIGTERM to its Core so
        # sing-tun removes the policy routes and DNS hijack it created.
        result = command("/usr/bin/systemctl", "stop", APP, HELPER)
        if result != 0:
            return result
        try:
            clean_tun(root)
        except (OSError, subprocess.SubprocessError, ValueError, KeyError):
            return 1
        command("/usr/bin/systemctl", "start", HELPER)
    return 0


def autostart():
    deadline = FLAGS / "tun-deadline"
    if deadline.exists():
        try:
            expired = not (RUNTIME / "tun-trial").exists() or time.time() >= float(deadline.read_text())
        except (OSError, ValueError):
            expired = deadline.exists()
        if expired:
            return recover(timed=True)
    if (
        (FLAGS / "autostart").exists()
        and (FLAGS / "ready").exists()
        and not (FLAGS / "upgrade").exists()
        and not (FLAGS / "recovery").exists()
        and not (RUNTIME / "manual-stop").exists()
        and not (RUNTIME / "bootstrap").exists()
        and not deadline.exists()
    ):
        return command("/usr/bin/systemctl", "start", "--no-block", APP)
    return 0


if __name__ == "__main__":
    if os.geteuid() != 0:
        sys.exit("Run this command with sudo.")
    action = sys.argv[1:]
    if action == ["--autostart"]:
        sys.exit(autostart())
    if action not in ([], ["--trial"]):
        sys.exit("Unknown recovery action.")
    result = recover(timed=bool(action))
    if result:
        print("Clash Manager could not complete network recovery.", file=sys.stderr)
    elif not action:
        print("Clash Manager stopped. Open the plugin to restore a TUN-off configuration.")
    sys.exit(result)

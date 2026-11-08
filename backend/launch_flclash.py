# SPDX-License-Identifier: GPL-3.0-or-later
"""Select the live SteamOS display and start the official AppRun as deck."""

import os
import re
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
FLAGS = ROOT / "flags"
RUNTIME = Path("/run/clash-manager-flclash")
SESSION_KEYS = (
    "DISPLAY", "XAUTHORITY", "WAYLAND_DISPLAY", "XDG_CURRENT_DESKTOP",
    "XDG_SESSION_DESKTOP", "XDG_SESSION_TYPE", "XDG_DESKTOP_PORTAL_DIR",
)
SESSION_PROCESSES = {
    "kwin_wayland", "kwin_x11", "plasmashell", "startplasma-way",
    "gamescope", "gamescope-wl", "gamescope-sessi", "start-gamescope", "steam", "steamwebhelper",
}


def graphical_environments(runtime):
    """Prefer the actual desktop compositor/Steam over a stale user manager."""
    for proc in Path("/proc").iterdir():
        if not proc.name.isdecimal():
            continue
        try:
            if proc.stat().st_uid != os.getuid():
                continue
            if (proc / "comm").read_text().strip() not in SESSION_PROCESSES:
                continue
            raw = (proc / "environ").read_bytes().decode(errors="replace")
            yield dict(item.split("=", 1) for item in raw.split("\0") if "=" in item)
        except OSError:
            continue
    try:
        result = subprocess.run(
            ["/usr/bin/systemctl", "--user", "show-environment"],
            env={
                "PATH": "/usr/bin:/bin",
                "XDG_RUNTIME_DIR": str(runtime),
                "DBUS_SESSION_BUS_ADDRESS": f"unix:path={runtime}/bus",
            },
            capture_output=True, text=True, timeout=3, check=False,
        )
        yield dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    except (OSError, subprocess.TimeoutExpired):
        pass
    try:
        # SteamOS publishes the Xwayland display here even before Steam
        # starts and when its compositor's /proc/environ is unreadable.
        session = runtime / "gamescope-environment"
        with session.open() as source:
            metadata = os.fstat(source.fileno())
            if metadata.st_uid == os.getuid() and metadata.st_size < 65536:
                yield dict(line.split("=", 1) for line in source.read().splitlines() if "=" in line)
    except OSError:
        pass


def is_socket(path):
    try:
        return stat.S_ISSOCK(path.stat().st_mode)
    except OSError:
        return False


def find_display(runtime):
    try:
        if runtime.stat().st_uid != os.getuid():
            return None
    except OSError:
        return None

    wayland = None
    for candidate in graphical_environments(runtime):
        env = {key: candidate[key] for key in SESSION_KEYS if key in candidate}
        display = re.fullmatch(r":(\d{1,4})(?:\.\d+)?", env.get("DISPLAY", ""))
        if display and is_socket(Path("/tmp/.X11-unix") / ("X" + display[1])):
            env["GDK_BACKEND"] = "x11"
            return env
        socket = env.get("WAYLAND_DISPLAY", "")
        if re.fullmatch(r"wayland-\d+", socket) and is_socket(runtime / socket):
            env["GDK_BACKEND"] = "wayland"
            wayland = env
    return wayland


def permitted():
    if (FLAGS / "recovery").exists():
        return False
    try:
        deadline = float((FLAGS / "tun-deadline").read_text())
    except FileNotFoundError:
        deadline = None
    except (OSError, ValueError):
        return False
    if deadline is not None and (not (RUNTIME / "tun-trial").exists() or time.time() >= deadline):
        return False
    if (RUNTIME / "bootstrap").is_file():
        return True
    return (FLAGS / "ready").is_file() and not (RUNTIME / "manual-stop").exists()


def controller_available():
    if not (ROOT / "data" / "flclash-receipt.json").is_file():
        return True
    try:
        with socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 9090))
        return True
    except OSError:
        return False


def main():
    if os.geteuid() == 0 or not permitted():
        return 1
    runtime = Path("/run/user") / str(os.getuid())
    display = find_display(runtime)
    if not display:
        return 1
    if sys.argv[1:] == ["--check"]:
        return 0 if controller_available() else 1
    data = ROOT / "data"
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": os.environ["HOME"],
        "USER": "deck",
        "LOGNAME": "deck",
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "XDG_RUNTIME_DIR": str(runtime),
        "XDG_DATA_HOME": str(data / "share"),
        "XDG_CONFIG_HOME": str(data / "config"),
        "XDG_CACHE_HOME": str(data / "cache"),
        "FLCLASH_ACCEPT_DISCLAIMER": "1",
        **display,
    }
    # AppRun's bundled C++ runtime can be older than SteamOS's graphics
    # drivers. Use the host runtime with the unchanged upstream bundle.
    runtime_libraries = ("/usr/lib/libstdc++.so.6", "/usr/lib/libgcc_s.so.1")
    if all(Path(library).is_file() for library in runtime_libraries):
        env["LD_PRELOAD"] = ":".join(runtime_libraries)
    # The clean environment also leaves APPIMAGE unset for Helper support.
    # The private bus also keeps GtkApplication's fixed app ID instance-local.
    command = ["/usr/bin/dbus-run-session", "--", str(ROOT / "current" / "AppRun")]
    os.execve(command[0], command, env)


if __name__ == "__main__":
    sys.exit(main())

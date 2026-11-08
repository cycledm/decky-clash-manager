# SPDX-License-Identifier: GPL-3.0-or-later
"""Run the private worker on inherited sockets, as the deck account."""

import os
import socket
import sys
import threading
from functools import partial
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.dashboard import Dashboard
from backend.flclash import FlClash
from backend.ipc import Channel, serve
from backend.manager import Manager
from backend.transport import open_panel

ACTIONS = ("install", "start", "stop", "set_autostart", "check_update", "upgrade",
           "import_file", "import_subscription", "select_profile", "edit_subscription",
           "refresh_profile", "delete_profile", "save_user_agent", "select_user_agent",
           "delete_user_agent", "set_settings", "confirm_tun", "cancel_tun", "open_phone",
           "close_phone", "open_dashboard", "uninstall", "purge_data")


def channel(fd):
    fd = int(fd)
    os.set_inheritable(fd, False)
    return Channel(socket.socket(fileno=fd))


def main():
    if os.geteuid() == 0:
        return
    root = channel(sys.argv[1])
    panel = channel(sys.argv[2])
    data = Path(sys.argv[3])
    os.umask(0o077)
    client = FlClash(data, controller_owned=partial(root.request, "controller_owned"))
    metadata = (Path(__file__).resolve().parents[1] / "plugin.json").stat()
    deployment = f"{metadata.st_ino}:{metadata.st_ctime_ns}"
    manager = Manager(data, client, root.request, Dashboard(client.dashboard_info), deployment)
    methods = {name: partial(manager.invoke, name) for name in ACTIONS}
    url = open_panel({**methods, "get_status": manager.get_status})
    threading.Thread(target=manager.background, daemon=True).start()
    serve(panel, {"get_transport": lambda: {"url": url}})


if __name__ == "__main__":
    main()

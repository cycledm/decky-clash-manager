# SPDX-License-Identifier: GPL-3.0-or-later
"""Complete Decky removal from an immutable systemd task."""

import sys
from pathlib import Path

# This script is copied into /home/clash-manager/private/cleanup by root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from cleanup.lifecycle import Lifecycle


def main():
    lifecycle = Lifecycle()
    lifecycle.uninstall()
    (lifecycle.flags / "uninstall-pending").unlink(missing_ok=True)


if __name__ == "__main__":
    main()

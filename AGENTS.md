# Clash Manager

- Build a Decky Loader plugin for Steam Deck that installs and manages an isolated, original FlClash release. Keep the display name Clash Manager. Original code is GPL-3.0-or-later. Preserve third-party notices.
- Use `npm ci`, `npm run typecheck`, `npm run build`, `python3 -m unittest discover -s tests`, and `python3 scripts/package.py`. Test the ZIP through Decky Developer Mode. See INSTALL.md for device procedures.
- The plugin owns subscription fetching, User-Agent selection, scheduling, profile selection, and recovery. FlClash owns the running proxy and its bundled core. Keep client-specific persistence and lifecycle separate from generic profile management. Do not patch or substitute official binaries.
- Root handles fixed install and systemd operations. Run FlClash, subscription handling, YAML processing, and local web servers as deck. Keep managed data separate from other clients. Expose only scoped capabilities over pairing and authenticated local control. Keep URLs, profile content, tokens, and secrets out of logs and fixtures.
- Pin approved release assets and digests. Stage and verify releases before switching. Snapshot matching client data while stopped, verify loaded configuration against the live core, and restore the old version, data, and run intent on failure.
- Preserve independent recovery and a systemd TUN trial deadline. On hardware, verify both session types, boot and manual stop, TUN and remote import reachability, suspend/resume, Wi-Fi changes, and Decky reload. Distinguish simulated tests from observed device behavior.

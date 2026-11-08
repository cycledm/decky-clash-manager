# Install Clash Manager

Enable Developer Mode in Decky Loader, then use its install-from-ZIP option with the Clash Manager release archive. Use a current Decky Loader on SteamOS. Clash Manager needs the Decky root plugin permission to install its own systemd services.

The plugin downloads the official Linux x86-64 FlClash v0.9.3 AppImage, checks its pinned SHA-256, and extracts it under `/home/clash-manager`. The Helper runs as a system service. The client and its private data use the deck account. On first launch the plugin accepts the FlClash v0.9.3 disclaimer on your behalf via the upstream unattended-start option. Review the upstream notice before installing. [FlClash unattended desktop startup](https://github.com/chen08209/FlClash/blob/v0.9.3/README.md#unattended-desktop)

Import a Clash/Mihomo YAML or an HTTP(S) subscription, select it, and choose Start. Autostart is opt-in. The panel distinguishes the selected profile from the profile confirmed by the running core. The original client has a fixed authenticated controller on loopback port 9090. If another client already uses that port or controls host-wide routing, resolve the conflict before starting FlClash or enabling TUN.

Choose a subscription User-Agent in the panel. The plugin sends it on initial download and on manual and scheduled refreshes. The managed client also receives it as FlClash's global User-Agent for core downloads. Providers inside a YAML retain their own update mechanism and any explicit headers. A failed subscription refresh keeps the previous copy. When importing, you can leave the profile name blank to use the title or filename sent by the subscription server.

Remote import opens a five-minute LAN session. From any device on the same network, scan the QR code or copy the displayed link. Use it on a trusted network because the import page uses local HTTP. The page can submit YAML and public subscription links. The Decky panel can also import private subscription URLs. The built-in dashboard opens a separate loopback-only session and reads the authenticated running core.

## Recovery

Before enabling TUN, verify that you can run `sudo /home/clash-manager/recover` from the Deck's desktop terminal or a working SSH session. The initial TUN trial starts a systemd timer independent of Decky. If you cannot confirm the trial from the panel, the timer stops the managed proxy. The same command stops it immediately. Open the panel afterwards to see the recovery state and start again with TUN disabled.

Use Remove managed client to remove its services and client while retaining profiles. Delete stored profiles and settings is a separate panel action. Removing Clash Manager from Decky also queues removal of the managed client and services. A Decky reload preserves the client's current run intent.

Client updates are offered only for versions with a pinned asset and supported local data format. The plugin disables FlClash's own update checks. Subscription refresh intervals are independent.

// SPDX-License-Identifier: GPL-3.0-or-later
import { definePlugin, openFilePicker, type FileSelectionType } from "@decky/api";
import {
  ButtonItem, DropdownItem, Field, Navigation, PanelSection, PanelSectionRow, ToggleField, staticClasses,
} from "@decky/ui";
import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { ConfirmAction, PortDialog, SubscriptionDialog, UserAgentDialog, showDialog, type Run } from "./dialogs.tsx";
import { RemoteImport } from "./remote-import.tsx";
import { useLocalization } from "./localization.ts";
import { rpc, type Result, type Settings, type Status } from "./rpc.ts";

const stateLabels: Record<string, string> = {
  not_installed: "FlClash is not installed",
  installing: "Installing FlClash",
  install_failed: "FlClash installation failed",
  waiting_config: "Waiting for a valid profile",
  stopped: "Stopped",
  running: "Running",
  tun_failed: "TUN could not be enabled",
  upgrade_rolled_back: "Client upgrade rolled back",
  error: "Needs attention",
};
const modeOptions = [
  { data: "rule", label: "Rule" },
  { data: "global", label: "Global" },
  { data: "direct", label: "Direct" },
];
const logOptions = ["silent", "error", "warning", "info", "debug"].map((level) => ({
  data: level,
  label: level[0].toUpperCase() + level.slice(1),
}));

function Action({ label, description, disabled, onClick }: {
  label: string;
  description?: string;
  disabled?: boolean;
  onClick: () => void;
}) {
  return (
    <PanelSectionRow>
      <ButtonItem layout="below" description={description} disabled={disabled} onClick={onClick}>
        {label}
      </ButtonItem>
    </PanelSectionRow>
  );
}

function Info({ label, value }: { label: string; value: ReactNode }) {
  return <PanelSectionRow><Field label={label} description={value} /></PanelSectionRow>;
}

function Panel() {
  const { t, locale } = useLocalization();
  const [status, setStatus] = useState<Status>();
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<string>();
  const [advanced, setAdvanced] = useState(false);
  const active = useRef(false);
  const mutating = useRef(false);
  const polling = useRef(false);
  const statusRevision = useRef(0);

  const reload = useCallback(async () => {
    const revision = ++statusRevision.current;
    try {
      const next = await rpc.status();
      if (active.current && statusRevision.current === revision) setStatus(next);
    } catch (error) {
      if (active.current && statusRevision.current === revision) {
        setProblem(error instanceof Error ? error.message : "Clash Manager backend is unavailable.");
      }
    }
  }, []);

  useEffect(() => {
    active.current = true;
    async function poll() {
      if (polling.current || mutating.current) return;
      polling.current = true;
      try {
        await reload();
      } finally {
        polling.current = false;
      }
    }
    void poll();
    const interval = window.setInterval(poll, 3000);
    return () => {
      active.current = false;
      statusRevision.current += 1;
      window.clearInterval(interval);
    };
  }, [reload]);

  const run: Run = async (action) => {
    if (mutating.current) return { ok: false, error: "Wait for the current operation to finish." };
    mutating.current = true;
    setBusy(true);
    setProblem(undefined);
    let result: Result;
    try {
      result = await action();
    } catch {
      result = { ok: false, error: "Could not complete the operation. Check the backend and try again." };
    }
    if (active.current && !result.ok) setProblem(result.error ?? "The operation failed.");
    await reload();
    mutating.current = false;
    if (active.current) setBusy(false);
    return result;
  };

  function confirm(title: string, description: string, label: string, action: () => Promise<Result>, destructive = false) {
    showDialog((close) => (
      <ConfirmAction close={close} run={run} title={title} description={description}
        actionLabel={label} action={action} destructive={destructive} />
    ));
  }

  async function importYaml() {
    try {
      // Decky declares this as a compile-time enum only.
      const selection: FileSelectionType.FILE = 0;
      const file = await openFilePicker(selection, "/home/deck", true, true, /\.ya?ml$/i);
      const name = file.path.split("/").pop()?.replace(/\.ya?ml$/i, "") ?? "";
      await run(() => rpc.importFile(file.realpath || file.path, name));
    } catch (error) {
      if (!String(error).toLowerCase().includes("cancel")) setProblem("The file picker could not open the YAML file.");
    }
  }

  function launchDashboard(url: string) {
    try {
      const target = new URL(url);
      if (target.protocol !== "http:" || target.hostname !== "127.0.0.1" || target.username || target.password) {
        throw new Error("Unexpected dashboard address");
      }
      Navigation.NavigateToExternalWeb(target.href);
      Navigation.CloseSideMenus();
    } catch {
      setProblem("Could not open the local dashboard.");
    }
  }

  if (!status) {
    return (
      <PanelSection title="Clash Manager">
        <Info label={t(problem ?? "Loading status…")} value="" />
        {problem && <Action label={t("Retry")} onClick={() => void reload()} />}
      </PanelSection>
    );
  }

  const selected = status.profiles.find((profile) => profile.id === status.selected);
  const effective = status.profiles.find((profile) => profile.id === status.effective);
  const disabled = busy || status.state === "installing";
  const now = Date.now() / 1000;
  const pendingTun = status.tun_pending_until && status.tun_pending_until > now;
  const settings = status.settings;
  const setting = (changes: Partial<Settings>) => void run(() => rpc.setSettings(changes));
  const upgradeReady = status.available_version !== status.version ? status.available_version : null;

  return (
    <>
      <PanelSection title="FlClash">
        <Info label={t(stateLabels[status.state] ?? "Checking client")} value={
          status.version ? t("Client {version} · {status}", { version: status.version,
            status: t(status.effective ? "Core verified" : status.running ? "Client running" : "Stopped") }) : ""
        } />
        {(problem || status.problem) && (
          <Info label={t("Last operation")} value={<span role="alert">{t(problem || status.problem || "")}</span>} />
        )}
        {busy && <Info label={t("Working…")} value="" />}
        <Info label={t("Selected profile")} value={selected?.name ?? t("None")} />
        <Info label={t("Active in the core")} value={effective?.name ?? t("None")} />
        {(!status.installed || status.state === "install_failed") && (
          <Action
            label={t(status.state === "install_failed" ? "Retry client installation" : "Install FlClash")}
            description={t("Downloads the official AppImage and sets up its Helper.")}
            disabled={disabled}
            onClick={() => void run(rpc.install)}
          />
        )}
        {status.installed && (
          <>
            <Action label={t(status.running ? "Stop proxy" : "Start proxy")}
              description={!status.running && !selected ? t("Import and select a valid profile first.") : undefined}
              disabled={disabled || (!status.running && !selected)}
              onClick={() => void run(status.running ? rpc.stop : rpc.start)} />
            <PanelSectionRow>
              <ToggleField label={t("Start with Steam or Desktop")}
                description={t("Starts at graphical login when a valid profile is selected.")}
                checked={status.autostart} disabled={disabled}
                onChange={(enabled) => void run(() => rpc.setAutostart(enabled))} />
            </PanelSectionRow>
          </>
        )}
      </PanelSection>

      <Profiles status={status} disabled={disabled} run={run} importYaml={importYaml} />
      <RemoteImport pairing={status.phone} busy={disabled}
        open={() => void run(rpc.openRemoteImport)} close={() => void run(rpc.closeRemoteImport)} />

      {status.installed && (
        <PanelSection title={t("Common settings")}>
          <PanelSectionRow>
            <DropdownItem label={t("Proxy mode")} selectedOption={settings.mode} rgOptions={modeOptions.map((option) => ({ ...option, label: t(option.label) }))}
              disabled={disabled} onChange={(option) => setting({ mode: option.data })} />
          </PanelSectionRow>
          <PanelSectionRow>
            <ToggleField label="TUN"
              description={t("Test your network and confirm the change to keep TUN enabled.")}
              checked={settings.tun} disabled={disabled || (!status.running && !settings.tun)}
              onChange={(tun) => setting({ tun })} />
          </PanelSectionRow>
          {pendingTun && (
            <>
              <Info label={t("TUN test in progress")}
                value={t("Reverts automatically at {time}.", { time: new Date(status.tun_pending_until! * 1000).toLocaleTimeString(locale) })} />
              <Action label={t("Keep TUN enabled")} disabled={disabled} onClick={() => void run(rpc.confirmTun)} />
              <Action label={t("Revert TUN now")} disabled={disabled} onClick={() => void run(rpc.cancelTun)} />
            </>
          )}
          <Action
            label={t(status.dashboard_url ? "Open local dashboard" : "Prepare local dashboard")}
            description={t("A separate dashboard connected to the local Mihomo controller.")}
            disabled={disabled || !status.running}
            onClick={() => {
              if (status.dashboard_url) launchDashboard(status.dashboard_url);
              else void run(rpc.openDashboard);
            }}
          />
        </PanelSection>
      )}

      <PanelSection title={t("Advanced")}>
        <Action label={t(advanced ? "Hide advanced settings" : "Show advanced settings")} onClick={() => setAdvanced(!advanced)} />
        {advanced && (
          <>
            {status.installed && (
              <>
                <PanelSectionRow>
                  <ToggleField label={t("Bypass the LAN")}
                    description={t("Keeps local destinations outside TUN.")}
                    checked={settings.lan_bypass}
                    disabled={disabled || Boolean(pendingTun)}
                    onChange={(lan_bypass) => setting({ lan_bypass })} />
                </PanelSectionRow>
                <Action label={t("Mixed port · {port}", { port: settings.mixed_port })}
                  disabled={disabled}
                  onClick={() => showDialog((close) => <PortDialog close={close} run={run} port={settings.mixed_port} />)} />
                <PanelSectionRow>
                  <DropdownItem label={t("Core log level")} selectedOption={settings.log_level} rgOptions={logOptions.map((option) => ({ ...option, label: t(option.label) }))}
                    disabled={disabled} onChange={(option) => setting({ log_level: option.data })} />
                </PanelSectionRow>
                <Action label={t("Check client version")} description={t("Only releases verified for this plugin can be installed.")}
                  disabled={disabled} onClick={() => void run(rpc.checkUpdate)} />
                {status.published_version && (
                  <Info label={t("Latest official release")} value={status.published_version} />
                )}
                {status.available_version && (
                  <Info label={t("Supported release")} value={status.available_version} />
                )}
                {upgradeReady && (
                  <Action label={t("Upgrade to {version}", { version: upgradeReady })} disabled={disabled}
                    onClick={() => confirm(t("Upgrade FlClash?"), t("The old client and its data are saved before switching."), t("Upgrade"), rpc.upgrade)} />
                )}
                <Action label={t("Remove managed client")} disabled={disabled}
                  onClick={() => confirm(t("Remove FlClash?"), t("This stops the managed instance and keeps your profiles."), t("Remove"), rpc.uninstall)} />
              </>
            )}
            <Action label={t("Delete stored profiles and settings")} disabled={disabled || status.installed}
              description={status.installed ? t("Remove the managed client first.") : undefined}
              onClick={() => confirm(t("Delete Clash Manager data?"),
                t("This erases your stored profiles, subscription links, User-Agents and settings."),
                t("Delete data"), rpc.purgeData, true)} />
            <Info label={t("Local network recovery")} value={<code>sudo /home/clash-manager/recover</code>} />
          </>
        )}
      </PanelSection>
      {advanced && <UserAgents status={status} disabled={disabled} run={run} />}
    </>
  );
}

function Profiles({ status, disabled, run, importYaml }: {
  status: Status;
  disabled: boolean;
  run: Run;
  importYaml: () => void;
}) {
  const { t, locale } = useLocalization();
  const [managedId, setManagedId] = useState<string>();
  const profile = status.profiles.find(({ id }) => id === managedId) ??
    status.profiles.find(({ id }) => id === status.selected) ?? status.profiles[0];
  return (
    <PanelSection title={t("Profiles")}>
      <Action label={t("Import YAML file")} disabled={disabled} onClick={importYaml} />
      <Action label={t("Import subscription")} disabled={disabled}
        onClick={() => showDialog((close) => <SubscriptionDialog close={close} run={run} />)} />
      {profile && (
        <>
          <PanelSectionRow>
            <DropdownItem label={t("Manage profile")} selectedOption={profile.id}
              rgOptions={status.profiles.map(({ id, name }) => ({ data: id, label: name }))}
              disabled={disabled} onChange={(option) => setManagedId(option.data)} />
          </PanelSectionRow>
          <Action label={t(profile.id === status.selected ? "Current selection" : "Select this profile")}
            disabled={disabled || profile.id === status.selected}
            onClick={() => void run(() => rpc.selectProfile(profile.id))} />
          {profile.kind === "subscription" && (
            <>
              <Info label={t("Subscription refresh")} value={profile.update_error ? t(profile.update_error) :
                (profile.updated_at ? new Date(profile.updated_at * 1000).toLocaleString(locale) : t("No successful refresh yet"))} />
              <Action label={t("Refresh now")} disabled={disabled} onClick={() => void run(() => rpc.refreshProfile(profile.id))} />
              <Action label={t("Edit subscription")} disabled={disabled}
                description={profile.refresh_hours ? t("Refreshes every {hours} hours", { hours: profile.refresh_hours }) : t("Automatic refresh is off")}
                onClick={() => showDialog((close) => <SubscriptionDialog close={close} run={run} profile={profile} />)} />
            </>
          )}
          <Action label={t("Delete profile")} disabled={disabled}
            onClick={() => showDialog((close) => (
              <ConfirmAction close={close} run={run} title={t("Delete profile?")}
                description={t("Remove {name} from Clash Manager.", { name: profile.name })}
                actionLabel={t("Delete")} action={() => rpc.deleteProfile(profile.id)} />
            ))} />
        </>
      )}
    </PanelSection>
  );
}

function UserAgents({ status, disabled, run }: { status: Status; disabled: boolean; run: Run }) {
  const { t } = useLocalization();
  const [managedId, setManagedId] = useState<string>();
  const selected = status.user_agents.find(({ id }) => id === status.selected_ua);
  const agent = status.user_agents.find(({ id }) => id === managedId) ?? selected ?? status.user_agents[0];
  return (
    <PanelSection title={t("Subscription User-Agent")}>
      <Info label={t("Active User-Agent")} value={selected?.name ?? t("Default")} />
      <Action label={t("Add custom User-Agent")} disabled={disabled}
        onClick={() => showDialog((close) => <UserAgentDialog close={close} run={run} />)} />
      {agent && (
        <>
          <PanelSectionRow>
            <DropdownItem label={t("Manage User-Agent")} selectedOption={agent.id}
              rgOptions={status.user_agents.map(({ id, name }) => ({ data: id, label: name }))}
              disabled={disabled} onChange={(option) => setManagedId(option.data)} />
          </PanelSectionRow>
          <Info label={t(agent.preset ? "Preset" : "User-Agent")} value={agent.value} />
          <Action label={t("Use for subscriptions")} disabled={disabled || agent.id === status.selected_ua}
            onClick={() => void run(() => rpc.selectUserAgent(agent.id))} />
          {!agent.preset && (
            <>
              <Action label={t("Edit User-Agent")} disabled={disabled}
                onClick={() => showDialog((close) => <UserAgentDialog close={close} run={run} agent={agent} />)} />
              <Action label={t("Delete User-Agent")} disabled={disabled} onClick={() => showDialog((close) => (
                <ConfirmAction close={close} run={run} title={t("Delete User-Agent?")}
                  description={t("Remove {name} from Clash Manager.", { name: agent.name })} actionLabel={t("Delete")}
                  action={() => rpc.deleteUserAgent(agent.id)} />
              ))} />
            </>
          )}
        </>
      )}
    </PanelSection>
  );
}

function GlobeIcon() {
  return (
    <svg aria-hidden="true" width="18" height="18" viewBox="0 0 24 24" fill="none"
      stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="9" />
      <ellipse cx="12" cy="12" rx="4" ry="9" />
      <path d="M3 12h18" />
    </svg>
  );
}

export default definePlugin(() => ({
  name: "Clash Manager",
  titleView: <div className={staticClasses.Title}>Clash Manager</div>,
  content: <Panel />,
  icon: <GlobeIcon />,
  onDismount() {},
}));

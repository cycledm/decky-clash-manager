// SPDX-License-Identifier: GPL-3.0-or-later
import { ButtonItem, DropdownItem, ModalRoot, TextField, ToggleField, showModal } from "@decky/ui";
import { useState, type ReactNode } from "react";
import { useLocalization } from "./localization.ts";
import { rpc, type Profile, type Result, type UserAgent } from "./rpc.ts";

export type Run = (action: () => Promise<Result>) => Promise<Result>;

interface DialogProps {
  close: () => void;
  run: Run;
}

export function showDialog(render: (close: () => void) => ReactNode) {
  const handle = showModal(render(() => handle.Close()));
}

function ActionDialog({
  title, actionLabel, close, run, action, disabled, children,
}: DialogProps & {
  title: string;
  actionLabel: string;
  action: () => Promise<Result>;
  disabled?: boolean;
  children: ReactNode;
}) {
  const { t } = useLocalization();
  const [working, setWorking] = useState(false);
  const [error, setError] = useState<string>();

  async function submit() {
    setWorking(true);
    const result = await run(action);
    setWorking(false);
    if (result.ok) close();
    else setError(result.error ?? "The operation failed.");
  }

  return (
    <ModalRoot onCancel={close} bDisableBackgroundDismiss={working}>
      <div style={{ minWidth: 300, maxWidth: 500 }}>
        <h2>{title}</h2>
        <fieldset disabled={working} style={{ border: 0, margin: 0, padding: 0 }}>
          {children}
        </fieldset>
        {error && <p role="alert">{t(error)}</p>}
        <ButtonItem layout="below" disabled={working || disabled} onClick={submit}>
          {working ? t("Working…") : actionLabel}
        </ButtonItem>
        <ButtonItem layout="below" disabled={working} onClick={close}>{t("Cancel")}</ButtonItem>
      </div>
    </ModalRoot>
  );
}

export function ConfirmAction(props: DialogProps & {
  title: string;
  description: string;
  actionLabel: string;
  action: () => Promise<Result>;
  destructive?: boolean;
}) {
  const { t } = useLocalization();
  const [confirmed, setConfirmed] = useState(false);
  return (
    <ActionDialog {...props} disabled={props.destructive && !confirmed}>
      <p>{props.description}</p>
      {props.destructive && (
        <ToggleField label={t("I understand this cannot be undone")} checked={confirmed} onChange={setConfirmed} />
      )}
    </ActionDialog>
  );
}

export function SubscriptionDialog({ profile, ...props }: DialogProps & { profile?: Profile }) {
  const { t } = useLocalization();
  const [name, setName] = useState(profile?.name ?? "");
  const [url, setUrl] = useState("");
  const [autoRefresh, setAutoRefresh] = useState(Boolean(profile?.refresh_hours));
  const [hours, setHours] = useState(profile?.refresh_hours || 24);
  const intervals = [1, 6, 12, 24, 48, 168].map((hours) => ({
    data: hours,
    label: hours === 1 ? t("Every hour") : t("Every {hours} hours", { hours }),
  }));

  return (
    <ActionDialog
      {...props}
      title={t(profile ? "Edit subscription" : "Import subscription")}
      actionLabel={t(profile ? "Save" : "Download and import")}
      disabled={profile ? !name.trim() : !url.trim()}
      action={() => profile
        ? rpc.editSubscription(profile.id, url.trim(), name.trim(), autoRefresh ? hours : 0)
        : rpc.importSubscription(url.trim(), name.trim())}
    >
      <TextField label={t(profile ? "Profile name" : "Profile name (optional)")}
        description={profile ? undefined : t("Leave blank to use the name supplied by the subscription server.")}
        value={name} onChange={(event) => setName(event.target.value)} />
      <TextField
        label={t(profile ? "Replacement URL (optional)" : "Subscription URL")}
        description={t(profile ? "Leave blank to keep the current URL." : "Paste the HTTP or HTTPS subscription link.")}
        bIsPassword
        value={url}
        onChange={(event) => setUrl(event.target.value)}
      />
      {profile && (
        <>
          <ToggleField label={t("Refresh automatically")} checked={autoRefresh} onChange={setAutoRefresh} />
          {autoRefresh && (
            <DropdownItem
              label={t("Refresh interval")}
              selectedOption={hours}
              rgOptions={intervals}
              onChange={(option) => setHours(option.data)}
            />
          )}
        </>
      )}
    </ActionDialog>
  );
}

export function UserAgentDialog({ agent, ...props }: DialogProps & { agent?: UserAgent }) {
  const { t } = useLocalization();
  const [name, setName] = useState(agent?.name ?? "");
  const [value, setValue] = useState(agent?.value ?? "");

  return (
    <ActionDialog
      {...props}
      title={t(agent ? "Edit User-Agent" : "Add User-Agent")}
      actionLabel={t("Save")}
      disabled={!name.trim() || !value.trim()}
      action={() => rpc.saveUserAgent(agent?.id ?? "", name.trim(), value.trim())}
    >
      <TextField label={t("Name")} value={name} onChange={(event) => setName(event.target.value)} />
      <TextField label="User-Agent" value={value} onChange={(event) => setValue(event.target.value)} />
    </ActionDialog>
  );
}

export function PortDialog({ port, ...props }: DialogProps & { port: number }) {
  const { t } = useLocalization();
  const [value, setValue] = useState(String(port));
  const parsed = Number(value);
  return (
    <ActionDialog
      {...props}
      title={t("Mixed port")}
      actionLabel={t("Apply")}
      disabled={!Number.isInteger(parsed) || parsed < 1024 || parsed > 65535 || parsed === 9090}
      action={() => rpc.setSettings({ mixed_port: parsed })}
    >
      <TextField
        label={t("Loopback proxy port")}
        description={t("Enter a port from 1024 to 65535. Port 9090 is used by the controller.")}
        mustBeNumeric
        value={value}
        onChange={(event) => setValue(event.target.value)}
      />
    </ActionDialog>
  );
}

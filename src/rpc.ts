// SPDX-License-Identifier: GPL-3.0-or-later
import { callable, fetchNoCors } from "@decky/api";

export interface Result {
  ok: boolean;
  error?: string;
}

export interface Profile {
  id: string;
  name: string;
  kind: "subscription" | "file";
  updated_at: number | null;
  update_error: string | null;
  refresh_hours: number;
}

export interface UserAgent {
  id: string;
  name: string;
  value: string;
  preset?: boolean;
}

export interface Settings {
  mode: "rule" | "global" | "direct";
  tun: boolean;
  mixed_port: number;
  log_level: "silent" | "error" | "warning" | "info" | "debug";
  lan_bypass: boolean;
}

export interface RemoteImportStatus {
  url: string | null;
  fallback_url: string | null;
  expires_at: number | null;
  reason: string | null;
}

export interface Status {
  state: string;
  version: string | null;
  available_version: string | null;
  published_version?: string | null;
  problem: string | null;
  installed: boolean;
  running: boolean;
  autostart: boolean;
  selected: string | null;
  effective: string | null;
  profiles: Profile[];
  user_agents: UserAgent[];
  selected_ua: string | null;
  settings: Settings;
  tun_pending_until: number | null;
  phone: RemoteImportStatus;
  dashboard_url: string | null;
}

const getTransport = callable<[], { url?: string; error?: string }>("get_transport");
let connection: Promise<{ url: string; auth: string }> | undefined;

async function connect() {
  const [endpoint, token] = await Promise.all([
    getTransport(),
    fetch("http://127.0.0.1:1337/auth/token", { credentials: "include", cache: "no-store" }),
  ]);
  if (!endpoint.url || !token.ok) throw new Error(endpoint.error ?? "Clash Manager transport is unavailable");
  const url = new URL(endpoint.url);
  if (url.protocol !== "http:" || url.hostname !== "127.0.0.1" || url.username || url.password) {
    throw new Error("Clash Manager transport is not local");
  }
  return { url: url.href, auth: (await token.text()).trim() };
}

function method<Args extends unknown[], Return>(name: string) {
  return async (...args: Args): Promise<Return> => {
    // Decky's WebSocket debug trace includes RPC arguments and results.
    // Keep private payloads in the body sent to the local worker.
    const current = connection ?? (connection = connect());
    try {
      const { url, auth } = await current;
      const response = await fetchNoCors(url, {
        method: "POST",
        body: JSON.stringify({ auth, method: name, args }),
      });
      if (!response.ok) throw new Error("Clash Manager transport request failed");
      return await response.json() as Return;
    } catch (error) {
      if (connection === current) connection = undefined;
      throw error;
    }
  };
}

export const rpc = {
  status: method<[], Status>("get_status"),
  install: method<[], Result>("install"),
  checkUpdate: method<[], Result>("check_update"),
  upgrade: method<[], Result>("upgrade"),
  start: method<[], Result>("start"),
  stop: method<[], Result>("stop"),
  setAutostart: method<[boolean], Result>("set_autostart"),
  importSubscription: method<[string, string], Result>("import_subscription"),
  importFile: method<[string, string], Result>("import_file"),
  selectProfile: method<[string], Result>("select_profile"),
  editSubscription: method<[string, string, string, number], Result>("edit_subscription"),
  refreshProfile: method<[string], Result>("refresh_profile"),
  deleteProfile: method<[string], Result>("delete_profile"),
  saveUserAgent: method<[string, string, string], Result>("save_user_agent"),
  selectUserAgent: method<[string], Result>("select_user_agent"),
  deleteUserAgent: method<[string], Result>("delete_user_agent"),
  setSettings: method<[Partial<Settings>], Result>("set_settings"),
  confirmTun: method<[], Result>("confirm_tun"),
  cancelTun: method<[], Result>("cancel_tun"),
  openRemoteImport: method<[], Result>("open_phone"),
  closeRemoteImport: method<[], Result>("close_phone"),
  openDashboard: method<[], Result>("open_dashboard"),
  uninstall: method<[], Result>("uninstall"),
  purgeData: method<[], Result>("purge_data"),
};

// SPDX-License-Identifier: GPL-3.0-or-later
import { ButtonItem, Field, PanelSection, PanelSectionRow } from "@decky/ui";
import qrcode from "qrcode-generator";
import { useMemo, useState } from "react";
import { useLocalization } from "./localization.ts";
import type { RemoteImportStatus } from "./rpc.ts";

function CopyAddress({ address }: { address: string }) {
  const { t } = useLocalization();
  const [result, setResult] = useState("");
  async function copy() {
    try {
      await navigator.clipboard.writeText(address);
      setResult("Copied");
      return;
    } catch {
      const field = document.createElement("textarea");
      field.value = address;
      field.style.position = "fixed";
      field.style.opacity = "0";
      document.body.appendChild(field);
      field.select();
      try {
        setResult(document.execCommand("copy") ? "Copied" : "Select the address above to copy it.");
      } catch {
        setResult("Select the address above to copy it.");
      } finally {
        field.remove();
      }
    }
  }

  return (
    <>
      <div style={{ userSelect: "text", overflowWrap: "anywhere", fontSize: 12 }}>{address}</div>
      <ButtonItem layout="below" onClick={copy}>{t(result || "Copy link")}</ButtonItem>
    </>
  );
}

export function RemoteImport({
  pairing, busy, open, close,
}: {
  pairing: RemoteImportStatus;
  busy: boolean;
  open: () => void;
  close: () => void;
}) {
  const { t, locale } = useLocalization();
  const [useFallback, setUseFallback] = useState(false);
  const active = Boolean(pairing.expires_at && pairing.expires_at * 1000 > Date.now());
  const fallback = pairing.fallback_url !== pairing.url ? pairing.fallback_url : null;
  const address = active ? (useFallback && fallback ? fallback : pairing.url ?? fallback) : null;
  const qr = useMemo(() => {
    if (!address) return null;
    try {
      const code = qrcode(0, "M");
      code.addData(address);
      code.make();
      return code.createDataURL(5);
    } catch {
      return null;
    }
  }, [address]);

  return (
    <PanelSection title={t("Remote import")}>
      <PanelSectionRow>
        <ButtonItem
          layout="below"
          description={t("Open a temporary page for devices on the same local network.")}
          onClick={active ? close : open}
          disabled={busy}
        >
          {t(active ? "Close remote import" : "Open remote import")}
        </ButtonItem>
      </PanelSectionRow>
      {pairing.reason && <PanelSectionRow><Field label={t("Network")} description={t(pairing.reason)} /></PanelSectionRow>}
      {address && (
        <>
          <PanelSectionRow>
            {qr && (
              <img
                src={qr}
                alt={t("Scan the code to open the remote import page")}
                style={{ display: "block", width: 180, maxWidth: "100%", margin: "10px auto", imageRendering: "pixelated" }}
              />
            )}
            <CopyAddress key={address} address={address} />
          </PanelSectionRow>
          {fallback && (
            <PanelSectionRow>
              <ButtonItem layout="below" onClick={() => setUseFallback(!useFallback)}>
                {t(useFallback ? "Use .local address" : "Use local IP address")}
              </ButtonItem>
            </PanelSectionRow>
          )}
          <PanelSectionRow>
            <Field
              label={t("Pairing expires")}
              description={pairing.expires_at ? new Date(pairing.expires_at * 1000).toLocaleTimeString(locale) : ""}
            />
          </PanelSectionRow>
        </>
      )}
    </PanelSection>
  );
}


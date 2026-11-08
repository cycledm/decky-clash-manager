// SPDX-License-Identifier: GPL-3.0-or-later
import { useEffect, useState } from "react";
import zhCN from "../backend/locales/zh-CN.json";

const chinese = zhCN as Record<string, string>;
type Locale = "en" | "zh-CN";
type Values = Record<string, string | number>;

function localeFor(language: string): Locale {
  return /^(?:zh(?:[-_]|$)|schinese$|tchinese$)/i.test(language) ? "zh-CN" : "en";
}

const browserLocale = localeFor(navigator.language);
let currentLocale = browserLocale;
let steamLocale: Promise<Locale> | undefined;

function translator(locale: Locale) {
  return (message: string, values: Values = {}) => {
    if (locale === "zh-CN") {
      const httpStatus = /^The subscription server returned HTTP (\d{3})\.$/.exec(message);
      if (httpStatus) {
        message = "The subscription server returned HTTP {status}.";
        values = { status: httpStatus[1] };
      }
    }
    const template = locale === "zh-CN" ? (chinese[message] ?? message) : message;
    return template.replace(/\{(\w+)\}/g, (placeholder, key: string) =>
      key in values ? String(values[key]) : placeholder);
  };
}

const translators = { en: translator("en"), "zh-CN": translator("zh-CN") };

export function useLocalization() {
  const [locale, setLocale] = useState(currentLocale);
  useEffect(() => {
    let mounted = true;
    steamLocale ??= Promise.resolve()
      .then(() => window.SteamClient?.Settings?.GetCurrentLanguage?.())
      .then((language) => language ? localeFor(language) : browserLocale)
      .catch(() => browserLocale);
    void steamLocale.then((language) => {
      currentLocale = language;
      if (mounted) setLocale(language);
    });
    return () => { mounted = false; };
  }, []);
  return { locale, t: translators[locale] };
}

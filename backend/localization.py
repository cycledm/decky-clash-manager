# SPDX-License-Identifier: GPL-3.0-or-later
"""Shared translations for the web pages and Decky panel."""

import json
import re
from pathlib import Path

CHINESE = json.loads(Path(__file__).with_name("locales").joinpath("zh-CN.json").read_text(encoding="utf-8"))


def browser_locale(accept_language):
    choices = []
    for item in accept_language[:512].split(","):
        language, _, parameter = item.strip().lower().partition(";")
        try:
            quality = float(parameter.strip().removeprefix("q=")) if parameter else 1
        except ValueError:
            continue
        if 0 < quality <= 1:
            choices.append((quality, language.split("-", 1)[0]))
    for _, language in sorted(choices, key=lambda choice: choice[0], reverse=True):
        if language == "zh":
            return "zh-CN"
        if language in {"en", "*"}:
            break
    return "en"


def translate(message, locale):
    if locale != "zh-CN":
        return message
    if status := re.fullmatch(r"The subscription server returned HTTP (\d{3})\.", message):
        return CHINESE["The subscription server returned HTTP {status}."].format(status=status[1])
    return CHINESE.get(message, message)

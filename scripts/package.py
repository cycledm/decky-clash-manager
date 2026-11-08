#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Create the ZIP layout expected by Decky Loader's developer installer."""
import json
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

ROOT = Path(__file__).resolve().parent.parent
REQUIRED = (
    "LICENSE", "INSTALL.md", "main.py", "package.json", "plugin.json", "releases.json",
    "backend/flclash.py", "backend/lifecycle.py", "backend/worker.py", "dist/index.js",
    "third-party/decky-plugin-template.txt", "third-party/qrcode-generator.txt",
)
SOURCE = ("package-lock.json", "rollup.config.js", "tsconfig.json", "scripts/package.py")
TREES = ("backend", "dist", "src", "third-party")
DECKY_API_SOURCE = Path("node_modules/@decky/api/src")


def main():
    manifest = json.loads((ROOT / "plugin.json").read_text())
    version = json.loads((ROOT / "package.json").read_text())["version"]
    missing = [name for name in REQUIRED if not (ROOT / name).is_file()]
    if missing:
        raise SystemExit(f"Missing package inputs: {', '.join(missing)}. Run npm ci and npm run build first.")
    files = {Path(name) for name in (*REQUIRED, *SOURCE)}
    for tree in TREES:
        files.update(file.relative_to(ROOT) for file in (ROOT / tree).rglob("*")
                     if file.is_file() and "__pycache__" not in file.parts
                     and file.suffix != ".pyc" and not file.name.startswith("."))
    api_source = [file for file in (ROOT / DECKY_API_SOURCE).glob("*.ts") if file.is_file()]
    if not api_source:
        raise SystemExit("Missing Decky API source. Run npm ci first.")
    name = manifest["name"]
    release = ROOT / "release"
    release.mkdir(exist_ok=True)
    output = release / f"Clash-Manager-{version}.zip"
    temporary = output.with_suffix(".tmp")
    try:
        with ZipFile(temporary, "w", ZIP_DEFLATED) as archive:
            for file in sorted(files):
                if (ROOT / file).is_symlink():
                    raise SystemExit(f"Unexpected symlink: {file}")
                archive.write(ROOT / file, f"{name}/{file.as_posix()}")
            for file in sorted(api_source):
                archive.write(file, f"{name}/third-party/decky-api-src/{file.name}")
        temporary.replace(output)
    finally:
        temporary.unlink(missing_ok=True)
    print(output)


if __name__ == "__main__":
    main()

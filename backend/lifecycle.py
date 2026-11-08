# SPDX-License-Identifier: GPL-3.0-or-later
"""Privileged operations on the immutable, plugin-managed FlClash installation."""

import contextlib
import fcntl
import functools
import hashlib
import http.client
import json
import os
import platform
import pwd
import queue
import re
import shutil
import ssl
import stat
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

from .recover_flclash import (APP, AUTOSTART, HELPER, RUNTIME, TRIAL, clean_tun,
                              recover, trial_lock, tun_slot_available)

DEFAULT_ROOT = Path("/home/clash-manager")
MANIFEST = Path(__file__).resolve().parents[1] / "releases.json"
UNITS = Path("/etc/systemd/system")
HELPER_RUNTIME = Path("/run/clash-manager-flclash-helper")
AUTO_SERVICE = "clash-manager-session.service"
CLEANUP_SERVICE = "clash-manager-uninstall"
REPOSITORY = "https://github.com/chen08209/FlClash"
RELEASE_API = "https://api.github.com/repos/chen08209/FlClash/releases/latest"
STEAMOS_CA_BUNDLE = Path("/etc/ssl/certs/ca-certificates.crt")
TAG = re.compile(r"v\d+\.\d+\.\d+")
SAFE_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C", "HOME": "/root"}
TUN_TRIAL_SECONDS = 90
ASSET_DOWNLOAD_SECONDS = 60 * 60


class LifecycleError(RuntimeError):
    """An operation failed. The message is safe for the plugin panel."""


class DownloadInterrupted(LifecycleError):
    """The download can retry from the bytes already written."""


def mutation(method):
    @functools.wraps(method)
    def locked(self, *args, **kwargs):
        self.initialize()
        with (self.private / "lifecycle.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                return method(self, *args, **kwargs)
            except OSError:
                raise LifecycleError("Managed storage is unavailable. Check free space and permissions, then retry.") from None

    return locked


class OfficialRedirects(urllib.request.HTTPRedirectHandler):
    hosts = {"github.com", "api.github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"}

    def redirect_request(self, request, fp, code, msg, headers, newurl):
        target = urlsplit(newurl)
        if target.scheme != "https" or target.hostname not in self.hosts:
            raise urllib.error.URLError("Unexpected release redirect")
        return super().redirect_request(request, fp, code, msg, headers, newurl)


class AssetRedirects(OfficialRedirects):
    hosts = OfficialRedirects.hosts | {"gh-proxy.com", "dl.clashwall.com"}


def open_release(url, offset, redirects, timeout):
    target = urlsplit(url)
    if target.scheme != "https" or target.hostname not in redirects.hosts:
        raise urllib.error.URLError("Unexpected release host")
    headers = {"User-Agent": "Clash-Manager", "Accept-Encoding": "identity"}
    if offset:
        headers["Range"] = f"bytes={offset}-"
    # Decky's bundled OpenSSL can look under /usr/lib/ssl, which SteamOS
    # does not populate. Keep normal certificate and hostname verification.
    context = ssl.create_default_context(
        cafile=str(STEAMOS_CA_BUNDLE) if STEAMOS_CA_BUNDLE.is_file() else None,
    )
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}), redirects, urllib.request.HTTPSHandler(context=context),
    ).open(urllib.request.Request(url, headers=headers), timeout=timeout)


def open_official(url):
    return open_release(url, 0, OfficialRedirects(), 20)


def open_asset(url, offset):
    return open_release(url, offset, AssetRedirects(), 20)


def safe_directory(path, mode, uid=0, gid=0):
    try:
        path.mkdir(mode=mode)
    except FileExistsError:
        metadata = path.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != uid or metadata.st_mode & 0o022:
            raise LifecycleError("Managed directory has unsafe ownership or permissions.")
    else:
        os.chown(path, uid, gid)
        path.chmod(mode)


def write_atomic(path, content, mode=0o644):
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as tmp:
        temporary = Path(tmp.name)
        try:
            os.fchmod(tmp.fileno(), mode)
            tmp.write(content)
            tmp.flush()
            os.fsync(tmp.fileno())
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)
    with directory_fd(path.parent) as fd:
        os.fsync(fd)


@contextlib.contextmanager
def directory_fd(path):
    fd = os.open(path, os.O_DIRECTORY | os.O_RDONLY | os.O_NOFOLLOW)
    try:
        yield fd
    finally:
        os.close(fd)


def unit_argument(value):
    escaped = str(value).replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%").replace("$", "$$")
    return f'"{escaped}"'


class Lifecycle:
    def __init__(self, root=DEFAULT_ROOT, data=None, manifest=MANIFEST):
        self.root = Path(root)
        self.data = Path(data) if data is not None else self.root / "data"
        self.flags = self.root / "flags"
        self.private = self.root / "private"
        self.releases = self.root / "releases"
        self.current = self.root / "current"
        self.journal = self.private / "upgrade.json"
        self.snapshot = self.private / "upgrade-data"
        self.manifest = Path(manifest)

    @property
    def deck(self):
        try:
            account = pwd.getpwnam("deck")
        except KeyError:
            raise LifecycleError("The SteamOS deck account is unavailable.") from None
        if account.pw_uid == 0 or account.pw_gid == 0:
            raise LifecycleError("The SteamOS deck account must be unprivileged.")
        return account

    def initialize(self):
        if os.geteuid() != 0 or platform.system() != "Linux" or platform.machine() != "x86_64":
            raise LifecycleError("Installation needs the root Decky backend on x86-64 Linux.")
        parent = self.root.parent.lstat()
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_mode & 0o022:
            raise LifecycleError("The installation parent directory must be protected by root.")
        safe_directory(self.root, 0o755)
        safe_directory(self.flags, 0o755)
        safe_directory(self.private, 0o700)
        safe_directory(self.releases, 0o755)
        safe_directory(RUNTIME, 0o755)
        # Recovery after an interrupted rename must see the old data in its
        # snapshot. The new worker still needs a directory to initialize.
        safe_directory(self.data, 0o700, self.deck.pw_uid, self.deck.pw_gid)

    def _manifest(self):
        try:
            return json.loads(self.manifest.read_text())["flclash"]
        except (OSError, ValueError, KeyError):
            raise LifecycleError("The plugin's pinned release manifest is unreadable.") from None

    def installed_version(self):
        try:
            target = Path(os.readlink(self.current))
        except FileNotFoundError:
            return None
        if target.parent != Path("releases") or not TAG.fullmatch(target.name):
            raise LifecycleError("The managed release link is invalid.")
        if not (self.current / "AppRun").is_file():
            raise LifecycleError("The managed release is incomplete. Reinstall it.")
        return target.name

    def check_update(self):
        manifest = self._manifest()
        current = self.installed_version()
        latest_pinned = manifest["default"]
        candidate = latest_pinned if current and self._version(latest_pinned) > self._version(current) else None
        try:
            with open_official(RELEASE_API) as response:
                published = json.loads(response.read(256 * 1024))
            latest = published["tag_name"]
            if published.get("prerelease") or published.get("draft") or not TAG.fullmatch(latest):
                raise ValueError
        except (OSError, ValueError, KeyError, TypeError):
            raise LifecycleError("Could not check the official FlClash releases. Retry when GitHub is reachable.") from None
        return {"current": current, "latest": latest, "available": candidate}

    @staticmethod
    def _version(tag):
        return tuple(int(part) for part in tag[1:].split("."))

    def _command(self, arguments, error, *, allow_failure=False, timeout=40, **kwargs):
        try:
            result = subprocess.run(
                arguments, env=SAFE_ENV, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=timeout, check=False, **kwargs,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise LifecycleError(error) from None
        if result.returncode and not allow_failure:
            raise LifecycleError(error)
        return result.returncode

    def _ctl(self, *arguments, allow_failure=False):
        return self._command(
            ["/usr/bin/systemctl", *arguments], "Systemd could not complete the managed service operation.",
            allow_failure=allow_failure,
        )

    def running(self):
        return self._ctl("is-active", "--quiet", APP, allow_failure=True) == 0

    def controller_owned(self):
        try:
            result = subprocess.run(
                ["/usr/bin/ss", "-H", "-lntp", "( sport = :9090 )"], env=SAFE_ENV,
                capture_output=True, text=True, check=True, timeout=3,
            )
            processes = set(re.findall(r"\bpid=(\d+),", result.stdout))
            return bool(processes) and all(
                any(line.rsplit("/", 1)[-1] in {APP, HELPER}
                    for line in Path(f"/proc/{pid}/cgroup").read_text().splitlines())
                for pid in processes
            )
        except (OSError, subprocess.SubprocessError):
            return False

    def helper_ready(self):
        try:
            metadata = (HELPER_RUNTIME / "helper.sock").lstat()
        except FileNotFoundError:
            return False
        return (
            stat.S_ISSOCK(metadata.st_mode)
            and metadata.st_uid == 0
            and metadata.st_gid == self.deck.pw_gid
            and stat.S_IMODE(metadata.st_mode) == 0o660
            and self._ctl("is-active", "--quiet", HELPER, allow_failure=True) == 0
        )

    def _wait_helper(self):
        for _ in range(40):
            if self.helper_ready():
                return
            time.sleep(0.15)
        raise LifecycleError("The managed FlClash Helper did not create its socket.")

    def _get_release(self, tag):
        manifest = self._manifest()
        if not TAG.fullmatch(tag) or tag not in manifest["releases"]:
            raise LifecycleError("This FlClash version has no validated adapter in the plugin release manifest.")
        record = manifest["releases"][tag]
        asset = f"FlClash-{tag[1:]}-linux-amd64.AppImage"
        digest = record["sha256"]
        size = record["size"]
        if record["asset"] != asset or not re.fullmatch(r"[0-9a-f]{64}", digest) or type(size) is not int or size < 1:
            raise LifecycleError("The pinned FlClash artifact metadata is invalid.")
        destination = self.releases / tag
        if destination.is_dir():
            self._validate_bundle(destination)
            return
        partial = self.private / f"{tag}-{digest}.partial"
        urls = [f"{REPOSITORY}/releases/download/{tag}/{asset}", *record.get("mirrors", [])]
        self._download_first(partial, urls, digest, size)
        with tempfile.TemporaryDirectory(dir=self.private) as working:
            directory = Path(working)
            image = directory / asset
            partial.rename(image)
            image.chmod(0o700)
            self._command(
                [str(image), "--appimage-extract"], "The official AppImage failed to unpack.",
                cwd=directory, timeout=90,
            )
            extracted = directory / "squashfs-root"
            self._protect_bundle(extracted)
            self._validate_bundle(extracted)
            extracted.rename(destination)

    def _download_first(self, partial, urls, digest, size):
        if len(urls) == 1:
            self._download(partial, urls[0], digest, size)
            return

        # Each source writes independently. All candidates represent the same
        # pinned asset, so a retry can seed them from the longest partial.
        directory = partial.parent / "asset-race"
        if directory.exists():
            self._discard(directory)
        directory.mkdir(mode=0o700)
        results = queue.Queue()
        cancelled = threading.Event()
        paths = [partial, *(directory / str(index) for index in range(1, len(urls)))]
        workers = []
        winner = None

        def attempt(index, path, url):
            verified = None
            reason = None
            try:
                self._download(path, url, digest, size, cancelled)
                verified = path
            except LifecycleError as error:
                reason = str(error)
            except Exception:
                reason = "The download source failed unexpectedly."
            finally:
                results.put((index, verified, reason))

        failures = [None] * len(urls)
        try:
            if partial.is_file() and partial.stat().st_size < size:
                for path in paths[1:]:
                    shutil.copyfile(partial, path)
            for index, (path, url) in enumerate(zip(paths, urls)):
                worker = threading.Thread(target=attempt, args=(index, path, url), daemon=True)
                worker.start()
                workers.append(worker)
            for _ in workers:
                index, winner, failures[index] = results.get()
                if winner is not None:
                    break
        finally:
            cancelled.set()
            for worker in workers:
                worker.join()
            try:
                retained = winner or max((path for path in paths if path.is_file()),
                                         key=lambda path: path.stat().st_size, default=None)
                if retained is not None and retained != partial:
                    retained.replace(partial)
            finally:
                self._discard(directory)
        if winner is None:
            summary = "Could not download and verify FlClash from any source. Check connectivity and retry."
            details = [f"{urlsplit(url).hostname}: {reason}" for url, reason in zip(urls, failures) if reason]
            raise LifecycleError("\n".join([summary, *details]))

    @staticmethod
    def _download(path, url, digest, size, cancelled=None):
        deadline = time.monotonic() + ASSET_DOWNLOAD_SECONDS
        for attempt in range(3):
            try:
                Lifecycle._download_once(path, url, digest, size, cancelled, deadline)
                return
            except DownloadInterrupted:
                if attempt == 2 or time.monotonic() >= deadline:
                    raise
                if cancelled is not None and cancelled.wait(1):
                    raise LifecycleError("Download cancelled.") from None
                if cancelled is None:
                    time.sleep(1)

    @staticmethod
    def _download_once(path, url, digest, size, cancelled, deadline):
        checksum = hashlib.sha256()
        timed_out = "The FlClash download timed out. Retry to resume."
        interrupted = "The FlClash download was interrupted. Retry to resume."
        try:
            count = path.stat().st_size if path.exists() else 0
            if count > size:
                path.unlink()
                count = 0
            if count:
                with path.open("rb") as previous:
                    while chunk := previous.read(1024 * 1024):
                        checksum.update(chunk)
            if cancelled is not None and cancelled.is_set():
                raise LifecycleError("Download cancelled.")
            if time.monotonic() >= deadline:
                raise LifecycleError(timed_out)
            if count < size:
                with open_asset(url, count) as response:
                    if response.status == 200:
                        checksum, count = hashlib.sha256(), 0
                    elif (response.status != 206 or not count
                          or response.headers.get("Content-Range") != f"bytes {count}-{size - 1}/{size}"):
                        raise LifecycleError("The download source returned an invalid AppImage byte range.")
                    with path.open("ab" if count else "wb") as output:
                        while chunk := response.read1(128 * 1024):
                            if cancelled is not None and cancelled.is_set():
                                raise LifecycleError("Download cancelled.")
                            count += len(chunk)
                            if count > size:
                                path.unlink()
                                raise LifecycleError("FlClash AppImage size verification failed. Retry the download.")
                            checksum.update(chunk)
                            output.write(chunk)
                            if time.monotonic() >= deadline:
                                raise LifecycleError(timed_out)
        except urllib.error.HTTPError as error:
            error.close()
            message = f"The download source returned HTTP {error.code}."
            if error.code in {408, 500, 502, 503, 504}:
                raise DownloadInterrupted(message) from None
            raise LifecycleError(message) from None
        except urllib.error.URLError as error:
            if isinstance(error.reason, TimeoutError):
                raise DownloadInterrupted(timed_out) from None
            if isinstance(error.reason, ssl.SSLCertVerificationError):
                raise LifecycleError("The download source's TLS certificate could not be verified.") from None
            if isinstance(error.reason, ssl.SSLError):
                raise LifecycleError("The download source failed the TLS handshake.") from None
            if error.reason == "Unexpected release redirect":
                raise LifecycleError("The download source redirected to an unapproved host.") from None
            raise DownloadInterrupted("Could not connect to the download source.") from None
        except TimeoutError:
            raise DownloadInterrupted(timed_out) from None
        except ssl.SSLCertVerificationError:
            raise LifecycleError("The download source's TLS certificate could not be verified.") from None
        except ssl.SSLError:
            raise LifecycleError("The download source failed the TLS handshake.") from None
        except (ConnectionError, http.client.IncompleteRead):
            raise DownloadInterrupted(interrupted) from None
        except (OSError, http.client.HTTPException):
            raise LifecycleError("Could not download the official FlClash AppImage. Check GitHub connectivity and disk space, then retry.") from None
        if count != size:
            raise DownloadInterrupted(interrupted)
        if checksum.hexdigest() != digest:
            path.unlink(missing_ok=True)
            raise LifecycleError("FlClash AppImage SHA-256 verification failed. Retry the download.")

    @staticmethod
    def _protect_bundle(root):
        if not root.is_dir() or root.is_symlink():
            raise LifecycleError("The official AppImage did not contain the expected bundle.")
        for directory, directories, files in os.walk(root, followlinks=False):
            for path in [Path(directory), *(Path(directory) / name for name in directories + files)]:
                metadata = path.lstat()
                if stat.S_ISLNK(metadata.st_mode):
                    if os.path.isabs(os.readlink(path)) or not path.resolve().is_relative_to(root):
                        raise LifecycleError("The official bundle contains an external symlink.")
                    os.chown(path, 0, 0, follow_symlinks=False)
                elif stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode):
                    os.chown(path, 0, 0)
                    path.chmod(0o755 if metadata.st_mode & 0o111 or path.is_dir() else 0o644)
                else:
                    raise LifecycleError("The official bundle contains an unsupported file type.")

    @staticmethod
    def _validate_bundle(root):
        for name in ("AppRun", "FlClash", "FlClashCore", "FlClashHelperService"):
            path = root / name
            if not path.is_file() or not path.resolve().is_relative_to(root.resolve()):
                raise LifecycleError("The official AppImage layout does not match the validated adapter.")
            metadata = path.stat()
            if metadata.st_uid != 0 or metadata.st_mode & 0o022 or not metadata.st_mode & 0o111:
                raise LifecycleError("The FlClash executable has unsafe ownership or permissions.")
        try:
            expected = json.loads((root / "manifest.json").read_text())["coreSha256"]
        except (OSError, ValueError, KeyError):
            raise LifecycleError("The official FlClash Core manifest is unreadable.") from None
        with (root / "FlClashCore").open("rb") as file:
            actual = hashlib.file_digest(file, "sha256").hexdigest()
        if actual != expected:
            raise LifecycleError("The bundled FlClash Core failed its manifest check.")

    def _point(self, tag):
        staged = self.private / "current.link"
        staged.unlink(missing_ok=True)
        staged.symlink_to(Path("releases") / tag)
        staged.replace(self.current)
        with directory_fd(self.root) as fd:
            os.fsync(fd)

    def _unit(self, name, text):
        path = UNITS / name
        marker = "# Owned by Clash Manager\n"
        if path.is_symlink() or path.exists() and not path.read_text().startswith(marker):
            raise LifecycleError("An existing service uses a Clash Manager service name.")
        write_atomic(path, (marker + text).encode())

    def _setup_services(self):
        uid, gid = self.deck.pw_uid, self.deck.pw_gid
        source = Path(__file__).resolve().parent
        write_atomic(self.root / "launch.py", (source / "launch_flclash.py").read_bytes(), 0o755)
        write_atomic(self.root / "recover", (source / "recover_flclash.py").read_bytes(), 0o755)
        launch = unit_argument(self.root / "launch.py")
        recover = unit_argument(self.root / "recover")
        helper = unit_argument(self.current / "FlClashHelperService")
        binding = f"{HELPER_RUNTIME}:/run/flclash"
        self._unit(HELPER, f"""[Unit]
Description=Clash Manager FlClash Helper
After=nftables.service iptables.service

[Service]
Type=simple
ExecStart={helper}
Group={gid}
Environment=FLCLASH_HELPER_OWNER_UID={uid}
Environment=FLCLASH_HELPER_OWNER_GID={gid}
RuntimeDirectory={HELPER_RUNTIME.name}
RuntimeDirectoryMode=0755
BindPaths={binding}
Restart=on-failure
RestartSec=5
KillMode=mixed
TimeoutStopSec=15
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
""")
        self._unit(APP, f"""[Unit]
Description=Clash Manager FlClash graphical client
After={HELPER}
Requires={HELPER}

[Service]
Type=exec
User=deck
BindPaths={binding}
ExecCondition=/usr/bin/python3 -I {launch} --check
ExecStart=/usr/bin/python3 -I {launch}
TimeoutStartSec=15
TimeoutStopSec=12
StandardOutput=null
StandardError=null
""")
        self._unit(AUTO_SERVICE, f"""[Unit]
Description=Clash Manager graphical session check

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 -I {recover} --autostart
""")
        self._unit(AUTOSTART, f"""[Unit]
Description=Clash Manager graphical session watcher

[Timer]
OnBootSec=10s
OnUnitInactiveSec=15s
Unit={AUTO_SERVICE}

[Install]
WantedBy=timers.target
""")
        self._ctl("daemon-reload")
        self._ctl("enable", "--now", HELPER, AUTOSTART)
        self._wait_helper()

    @mutation
    def install(self):
        if self.upgrade_pending():
            raise LifecycleError("An interrupted upgrade must be rolled back before installing.")
        version = self.installed_version()
        if version:
            self._setup_services()
            return version
        version = self._manifest()["default"]
        self._get_release(version)
        self._point(version)
        try:
            self._setup_services()
        except LifecycleError:
            self._remove_services()
            self.current.unlink(missing_ok=True)
            raise
        return version

    def _launch(self, temporary=False, upgrade=False):
        if not self.installed_version():
            raise LifecycleError("FlClash is not installed.")
        if self.upgrade_pending() and not upgrade:
            raise LifecycleError("Roll back the interrupted upgrade before starting FlClash.")
        if self.recovery_pending():
            raise LifecycleError("Restore safe networking in Clash Manager before starting FlClash.")
        if not temporary and not self.config_ready():
            raise LifecycleError("Import and verify a valid configuration before starting FlClash.")
        if temporary:
            (RUNTIME / "bootstrap").touch()
        try:
            self._ctl("start", HELPER)
            self._wait_helper()
            self._ctl("start", APP)
            if not self.running():
                raise LifecycleError("FlClash could not start. A usable deck graphical session is required.")
        except LifecycleError:
            (RUNTIME / "bootstrap").unlink(missing_ok=True)
            raise

    @mutation
    def bootstrap(self):
        self._launch(temporary=True, upgrade=self.upgrade_pending())

    @mutation
    def start(self):
        marker = RUNTIME / "manual-stop"
        was_stopped = marker.exists()
        marker.unlink(missing_ok=True)
        try:
            self._launch()
        except LifecycleError:
            if was_stopped:
                marker.touch()
            raise

    def _halt(self, restart_helper=True):
        (RUNTIME / "bootstrap").unlink(missing_ok=True)
        if self._owns_unit(APP):
            self._ctl("stop", APP)
        if self._owns_unit(HELPER):
            self._ctl("restart" if restart_helper else "stop", HELPER)
            if restart_helper:
                self._wait_helper()
        try:
            clean_tun(self.root)
        except (OSError, subprocess.SubprocessError, ValueError, KeyError):
            raise LifecycleError("Could not clean the managed TUN routes. Run the local recovery command.") from None

    @mutation
    def halt(self):
        self._halt()

    @mutation
    def stop(self):
        (RUNTIME / "manual-stop").touch()
        self._halt()

    def config_ready(self):
        return (self.flags / "ready").is_file()

    @mutation
    def set_config_ready(self, enabled):
        self._flag("ready", enabled)
        if enabled:
            (RUNTIME / "bootstrap").unlink(missing_ok=True)

    def autostart_enabled(self):
        return (self.flags / "autostart").is_file()

    @mutation
    def set_autostart(self, enabled):
        self._flag("autostart", enabled)

    def _flag(self, name, enabled):
        if enabled:
            write_atomic(self.flags / name, b"")
        else:
            (self.flags / name).unlink(missing_ok=True)

    def recovery_pending(self):
        deadline = self.tun_deadline()
        return (self.flags / "recovery").exists() or (
            deadline is not None and (not (RUNTIME / "tun-trial").exists() or time.time() >= deadline)
        )

    @mutation
    def clear_recovery(self):
        with trial_lock(self.root):
            if self.tun_deadline() is not None:
                raise LifecycleError("Wait for the scheduled TUN rollback to finish first.")
            if (self.flags / "tun-owned").is_file():
                try:
                    if not tun_slot_available():
                        raise LifecycleError("Managed TUN routes remain. Run the local recovery command again.")
                except (OSError, subprocess.SubprocessError, ValueError, KeyError):
                    raise LifecycleError("Could not confirm TUN route cleanup.") from None
                self._flag("tun-owned", False)
            self._flag("recovery", False)

    def tun_deadline(self):
        try:
            return float((self.flags / "tun-deadline").read_text())
        except FileNotFoundError:
            return None
        except ValueError:
            return 0.0

    @mutation
    def arm_tun_rollback(self):
        if not self.installed_version() or self.upgrade_pending():
            raise LifecycleError("Complete FlClash installation before testing TUN.")
        with trial_lock(self.root):
            if self.recovery_pending() or self.tun_deadline() is not None:
                raise LifecycleError("A TUN test or recovery is already in progress.")
            if not (self.flags / "tun-owned").is_file():
                try:
                    if not tun_slot_available():
                        raise LifecycleError("The managed TUN interface or route indexes are already in use.")
                except (OSError, subprocess.SubprocessError, ValueError, KeyError):
                    raise LifecycleError("Could not inspect the managed TUN route indexes.") from None
                self._flag("tun-owned", True)
            deadline = time.time() + TUN_TRIAL_SECONDS
            (RUNTIME / "tun-trial").touch()
            write_atomic(self.flags / "tun-deadline", str(deadline).encode())
            try:
                self._command([
                    "/usr/bin/systemd-run", "--quiet", f"--unit={TRIAL}",
                    f"--on-active={TUN_TRIAL_SECONDS}s", "--timer-property=AccuracySec=1s",
                    "/usr/bin/python3", "-I", str(self.root / "recover"), "--trial",
                ], "Systemd could not arm the independent TUN rollback.")
            except LifecycleError:
                (self.flags / "tun-deadline").unlink(missing_ok=True)
                (RUNTIME / "tun-trial").unlink(missing_ok=True)
                raise
            return deadline

    @mutation
    def confirm_tun(self):
        with trial_lock(self.root):
            if self.tun_deadline() is None or self.recovery_pending():
                raise LifecycleError("The TUN test expired. Restore safe networking and retry.")
            (self.flags / "tun-deadline").unlink()
            (RUNTIME / "tun-trial").unlink(missing_ok=True)
        self._ctl("stop", f"{TRIAL}.timer", allow_failure=True)

    @mutation
    def cancel_tun(self):
        if recover(root=self.root):
            raise LifecycleError("Could not complete network recovery. Retry the local recovery command.")
        self._ctl("stop", f"{TRIAL}.timer", allow_failure=True)

    def upgrade_pending(self):
        return (self.flags / "upgrade").exists() or self.journal.exists()

    @mutation
    def begin_upgrade(self):
        previous = self.installed_version()
        target = self._manifest()["default"]
        if not previous or self._version(target) <= self._version(previous):
            raise LifecycleError("No newer FlClash version is approved by this plugin release.")
        if self.upgrade_pending() or self.tun_deadline() is not None or self.recovery_pending():
            raise LifecycleError("Complete the pending upgrade or TUN recovery before upgrading.")
        # Downloads and verification precede any change to the running instance.
        self._get_release(target)
        if self.snapshot.exists():
            self._discard(self.snapshot)
        transaction = {
            "old": previous, "version": target, "was_running": self.running(),
            "was_ready": self.config_ready(),
        }
        self._flag("upgrade", True)
        write_atomic(self.journal, json.dumps(transaction).encode(), 0o600)
        try:
            self._halt(restart_helper=False)
            self._flag("ready", False)
            self.data.rename(self.snapshot)
            safe_directory(self.data, 0o700, self.deck.pw_uid, self.deck.pw_gid)
            self._copy_snapshot()
            self._point(target)
            self._ctl("start", HELPER)
            self._wait_helper()
        except (LifecycleError, OSError):
            self._rollback()
            raise LifecycleError("Upgrade preparation failed. The prior FlClash release and data were restored.") from None
        return transaction

    def _copy_snapshot(self):
        # Open the root-private snapshot directory, then perform all copying
        # as deck. Neither symlinks nor files inside it are read as root.
        with directory_fd(self.snapshot) as fd:
            self._command(
                ["/usr/bin/cp", "-a", "--reflink=auto", "--", f"/proc/self/fd/{fd}/.", str(self.data)],
                "The FlClash data snapshot could not be copied.",
                user=self.deck.pw_uid, group=self.deck.pw_gid, extra_groups=[],
                pass_fds=(fd,), timeout=90,
            )

    @staticmethod
    def _discard(path):
        if not shutil.rmtree.avoids_symlink_attacks:
            raise LifecycleError("This system cannot safely remove a FlClash data snapshot.")
        shutil.rmtree(path)

    @mutation
    def verify_upgrade_start(self, has_config):
        if not self.journal.is_file():
            raise LifecycleError("There is no pending FlClash upgrade.")
        self._launch(temporary=True, upgrade=True)

    @mutation
    def commit_upgrade(self):
        if not self.journal.is_file():
            raise LifecycleError("There is no pending FlClash upgrade.")
        transaction = json.loads(self.journal.read_text())
        if not transaction["was_running"]:
            (RUNTIME / "manual-stop").touch()
            self._halt()
        self._flag("ready", transaction["was_ready"])
        (RUNTIME / "bootstrap").unlink(missing_ok=True)
        self.journal.replace(self.private / "last-upgrade.json")
        self._flag("upgrade", False)

    def _rollback(self):
        if not self.journal.is_file():
            self._flag("upgrade", False)
            return None
        transaction = json.loads(self.journal.read_text())
        self._halt(restart_helper=False)
        if self.snapshot.exists():
            if self.data.exists():
                self._discard(self.data)
            self.snapshot.rename(self.data)
        self._point(transaction["old"])
        self._ctl("start", HELPER)
        self._wait_helper()
        self._flag("ready", transaction["was_ready"])
        if transaction["was_running"]:
            self._launch(upgrade=True)
        self.journal.unlink()
        self._flag("upgrade", False)
        return transaction["old"]

    @mutation
    def rollback_upgrade(self):
        return self._rollback()

    @staticmethod
    def _owns_unit(name):
        path = UNITS / name
        return not path.is_symlink() and path.is_file() and path.read_text().startswith("# Owned by Clash Manager\n")

    def _remove_services(self):
        if self._owns_unit(AUTOSTART):
            self._ctl("disable", "--now", AUTOSTART)
            self._ctl("stop", AUTO_SERVICE)
        self._ctl("stop", f"{TRIAL}.timer", f"{TRIAL}.service", allow_failure=True)
        if self._owns_unit(APP):
            self._ctl("stop", APP)
        if self._owns_unit(HELPER):
            self._ctl("disable", "--now", HELPER)
        for name in (APP, HELPER, AUTO_SERVICE, AUTOSTART):
            if self._owns_unit(name):
                (UNITS / name).unlink()
        self._ctl("daemon-reload")

    def queue_cleanup(self):
        # Decky gives uninstall hooks five seconds. The system manager keeps
        # cleanup alive after Decky removes the plugin files or reloads.
        self.initialize()
        cleanup = self.private / "cleanup"
        safe_directory(cleanup, 0o700)
        write_atomic(cleanup / "__init__.py", b"", 0o600)
        source = Path(__file__).resolve().parent
        for name in ("lifecycle.py", "recover_flclash.py", "cleanup.py"):
            write_atomic(cleanup / name, (source / name).read_bytes(), 0o600)
        self._flag("uninstall-pending", True)
        self._command([
            "/usr/bin/systemd-run", "--quiet", "--no-block", f"--unit={CLEANUP_SERVICE}",
            "/usr/bin/python3", "-I", str(cleanup / "cleanup.py"),
        ], "Could not queue managed FlClash removal.", timeout=2)

    def wait_for_cleanup(self):
        deadline = time.monotonic() + 60
        while (self.flags / "uninstall-pending").exists():
            if time.monotonic() >= deadline:
                raise LifecycleError("The previous removal did not finish. Inspect the Clash Manager uninstall service.")
            time.sleep(0.25)

    @mutation
    def purge_snapshot(self):
        if self.installed_version() or self.upgrade_pending():
            raise LifecycleError("Remove the managed client before deleting its snapshots.")
        if self.snapshot.exists():
            self._discard(self.snapshot)
        (self.private / "last-upgrade.json").unlink(missing_ok=True)
        self._flag("autostart", False)

    @mutation
    def uninstall(self):
        if self.upgrade_pending():
            self._rollback()
        self._remove_services()
        clean_tun(self.root)
        self.current.unlink(missing_ok=True)
        for name in ("recover", "launch.py"):
            (self.root / name).unlink(missing_ok=True)
        for flag in ("upgrade", "ready", "tun-deadline", "recovery", "tun-owned"):
            self._flag(flag, False)
        for marker in ("manual-stop", "bootstrap", "tun-trial"):
            (RUNTIME / marker).unlink(missing_ok=True)
        for release in self.releases.iterdir():
            self._discard(release)
        for partial in self.private.glob("*.partial"):
            partial.unlink()
        race = self.private / "asset-race"
        if race.exists():
            self._discard(race)

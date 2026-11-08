# SPDX-License-Identifier: GPL-3.0-or-later
import hashlib
import io
import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import call, patch

from backend.lifecycle import Lifecycle, LifecycleError


class LifecycleTests(unittest.TestCase):
    def test_download_reconnects_after_a_short_response(self):
        asset = b"official AppImage"
        offset = 8
        initial = io.BytesIO(asset[:offset])
        initial.status = 200
        remaining = io.BytesIO(asset[offset:])
        remaining.status = 206
        remaining.headers = {"Content-Range": f"bytes {offset}-{len(asset) - 1}/{len(asset)}"}
        url = "https://github.com/example/release/AppImage"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "asset.partial"
            with patch("backend.lifecycle.open_asset", side_effect=[initial, remaining]) as request, \
                 patch("backend.lifecycle.time.sleep"):
                Lifecycle._download(path, url, hashlib.sha256(asset).hexdigest(), len(asset))
            self.assertEqual(request.call_args_list, [call(url, 0), call(url, offset)])
            self.assertEqual(path.read_bytes(), asset)

    def test_official_download_resumes_and_checks_the_complete_digest(self):
        original = b"original AppImage bytes"
        offset = 7
        url = "https://github.com/example/release/AppImage"
        response = io.BytesIO(original[offset:])
        response.status = 206
        response.headers = {"Content-Range": f"bytes {offset}-{len(original)-1}/{len(original)}"}
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "asset.partial"
            image.write_bytes(original[:offset])
            with patch("backend.lifecycle.open_asset", return_value=response) as request:
                Lifecycle._download(image, url, hashlib.sha256(original).hexdigest(), len(original))
            request.assert_called_once_with(url, offset)
            self.assertEqual(image.read_bytes(), original)
            with self.assertRaisesRegex(LifecycleError, "SHA-256"):
                Lifecycle._download(image, url, "0" * 64, len(original))
            self.assertFalse(image.exists())

    def test_verified_mirror_cancels_and_cleans_other_downloads(self):
        with tempfile.TemporaryDirectory() as directory:
            partial = Path(directory) / "asset.partial"
            lifecycle = Lifecycle(root=Path(directory))
            official_started = threading.Event()
            cancelled = threading.Event()

            def download(path, url, digest, size, stop):
                if url == "official":
                    path.write_bytes(b"partial")
                    official_started.set()
                    if stop.wait(2):
                        cancelled.set()
                    raise LifecycleError("Official download stopped.")
                if url == "corrupt":
                    path.write_bytes(b"corrupt")
                    raise LifecycleError("SHA-256 mismatch.")
                if official_started.wait(2):
                    path.write_bytes(b"verified")
                    return
                raise LifecycleError("Official download did not start.")

            with patch.object(lifecycle, "_download", side_effect=download):
                lifecycle._download_first(partial, ["official", "corrupt", "mirror"], "digest", 8)
            self.assertTrue(cancelled.is_set())
            self.assertEqual(partial.read_bytes(), b"verified")
            self.assertEqual(list(partial.parent.iterdir()), [partial])

    def test_failed_race_keeps_longest_partial_for_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            partial = Path(directory) / "asset.partial"
            lifecycle = Lifecycle(root=Path(directory))

            def download(path, url, digest, size, stop):
                path.write_bytes(b"abc" if url == "official" else b"abcdef")
                raise LifecycleError("Download interrupted.")

            sources = ["https://github.com/asset", "https://dl.clashwall.com/asset"]
            with patch.object(lifecycle, "_download", side_effect=download):
                with self.assertRaisesRegex(LifecycleError, "dl.clashwall.com: Download interrupted"):
                    lifecycle._download_first(partial, sources, "digest", 8)
            self.assertEqual(partial.read_bytes(), b"abcdef")
            seeded = []

            def resume(path, url, digest, size, stop):
                seeded.append(path.read_bytes())
                raise LifecycleError("Download interrupted.")

            with patch.object(lifecycle, "_download", side_effect=resume):
                with self.assertRaisesRegex(LifecycleError, "any source"):
                    lifecycle._download_first(partial, sources, "digest", 8)
            self.assertEqual(seeded, [b"abcdef", b"abcdef"])
            self.assertEqual(list(partial.parent.iterdir()), [partial])

    def test_rollback_restores_exact_program_data_and_running_intent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lifecycle = Lifecycle(root=root)
            for path in (lifecycle.flags, lifecycle.private, lifecycle.data, lifecycle.snapshot):
                path.mkdir()
            (lifecycle.data / "profile").write_bytes(b"migrated data")
            (lifecycle.snapshot / "profile").write_bytes(b"previous data")
            lifecycle.journal.write_text(json.dumps(
                {"old": "v0.9.3", "version": "v0.9.4", "was_running": True, "was_ready": True}
            ))
            (lifecycle.flags / "upgrade").touch()
            with patch.object(lifecycle, "_halt"), patch.object(lifecycle, "_ctl"), \
                    patch.object(lifecycle, "_wait_helper"), patch.object(lifecycle, "_point") as point, \
                    patch.object(lifecycle, "_launch") as launch:
                self.assertEqual(lifecycle._rollback(), "v0.9.3")
            point.assert_called_once_with("v0.9.3")
            launch.assert_called_once_with(upgrade=True)
            self.assertEqual((lifecycle.data / "profile").read_bytes(), b"previous data")
            self.assertFalse(lifecycle.journal.exists())
            self.assertFalse(lifecycle.upgrade_pending())
            self.assertTrue(lifecycle.config_ready())

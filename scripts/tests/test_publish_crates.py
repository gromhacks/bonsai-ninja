#!/usr/bin/env python3
"""Unit tests for crates.io publication retry behavior."""

from __future__ import annotations

import datetime as dt
import gzip
import importlib.util
import io
import tarfile
import unittest
import urllib.error
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "publish-crates.py"
SPEC = importlib.util.spec_from_file_location("publish_crates", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
publish_crates = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(publish_crates)


class FakeProcess:
    def __init__(self, output: str, returncode: int) -> None:
        self.stdout = iter(output.splitlines(keepends=True))
        self.returncode = returncode

    def wait(self) -> int:
        return self.returncode


def crate_archive(files: dict[str, bytes], *, gzip_mtime: int) -> bytes:
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w") as archive:
        for path, payload in sorted(files.items()):
            member = tarfile.TarInfo(path)
            member.mode = 0o644
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode="wb", mtime=gzip_mtime) as compressed:
        compressed.write(tar_buffer.getvalue())
    return output.getvalue()


class CratesIoRetryDelayTests(unittest.TestCase):
    def test_uses_server_retry_timestamp_with_safety_margin(self) -> None:
        now = dt.datetime(2026, 8, 16, 22, 0, 45, tzinfo=dt.timezone.utc)
        output = (
            "the remote server responded with an error (status 429 Too Many Requests): "
            "You have published too many new crates in a short period of time. "
            "Please try again after Sun, 16 Aug 2026 22:04:45 GMT"
        )
        self.assertEqual(
            publish_crates.crates_io_retry_delay(output, now=now),
            245.0,
        )

    def test_past_timestamp_still_gets_safety_margin(self) -> None:
        now = dt.datetime(2026, 8, 16, 22, 5, 0, tzinfo=dt.timezone.utc)
        output = "429 Too Many Requests: try again after Sun, 16 Aug 2026 22:04:45 GMT"
        self.assertEqual(
            publish_crates.crates_io_retry_delay(output, now=now),
            5.0,
        )

    def test_429_without_timestamp_uses_conservative_fallback(self) -> None:
        self.assertEqual(
            publish_crates.crates_io_retry_delay("status 429 Too Many Requests"),
            float(publish_crates.RATE_LIMIT_FALLBACK_SECONDS),
        )

    def test_malformed_timestamp_uses_conservative_fallback(self) -> None:
        output = "429 Too Many Requests: try again after definitely-not-a-date GMT"
        self.assertEqual(
            publish_crates.crates_io_retry_delay(output),
            float(publish_crates.RATE_LIMIT_FALLBACK_SECONDS),
        )

    def test_other_failures_are_not_retried(self) -> None:
        self.assertIsNone(
            publish_crates.crates_io_retry_delay("status 400 Bad Request")
        )

    def test_publish_retries_the_same_crate_after_429(self) -> None:
        limited = FakeProcess("status 429 Too Many Requests\n", 101)
        accepted = FakeProcess("Uploaded bonsai-ninja-vfs\n", 0)
        with (
            mock.patch.object(
                publish_crates.subprocess,
                "Popen",
                side_effect=[limited, accepted],
            ) as popen,
            mock.patch.object(publish_crates.time, "sleep") as sleep,
            redirect_stdout(io.StringIO()),
        ):
            publish_crates.publish_crate("bonsai-ninja-vfs", "0.2.2")
        self.assertEqual(popen.call_count, 2)
        sleep.assert_called_once_with(
            float(publish_crates.RATE_LIMIT_FALLBACK_SECONDS)
        )
        targets = {
            call.kwargs["env"]["CARGO_TARGET_DIR"]
            for call in popen.call_args_list
        }
        self.assertEqual(len(targets), 1)
        self.assertFalse(Path(targets.pop()).exists())

    def test_registry_api_retries_429_using_retry_after_header(self) -> None:
        limited = urllib.error.HTTPError(
            "https://crates.io/api/v1/crates/demo",
            429,
            "Too Many Requests",
            {"Retry-After": "2"},
            io.BytesIO(b"rate limited"),
        )
        accepted = mock.MagicMock()
        accepted.__enter__.return_value.read.return_value = b'{"crate": {}}'
        accepted.__exit__.return_value = False
        with (
            mock.patch.object(
                publish_crates.urllib.request,
                "urlopen",
                side_effect=[limited, accepted],
            ) as urlopen,
            mock.patch.object(publish_crates.time, "sleep") as sleep,
            redirect_stdout(io.StringIO()),
        ):
            payload = publish_crates.registry_json("demo")
        self.assertEqual(payload, {"crate": {}})
        self.assertEqual(urlopen.call_count, 2)
        sleep.assert_called_once_with(7.0)


class PublicationPreflightTests(unittest.TestCase):
    def test_publish_preflights_every_archive_before_first_upload(self) -> None:
        order = ["bonsai-ninja-a", "bonsai-ninja-b"]
        excluded = {"bonsai-ninja-testkit"}
        with (
            mock.patch.object(publish_crates, "assert_clean_checkout"),
            mock.patch.object(publish_crates, "assert_registry_credentials"),
            mock.patch.object(
                publish_crates, "preflight_package_archives"
            ) as preflight,
            mock.patch.object(
                publish_crates, "registry_version_exists", return_value=False
            ),
            mock.patch.object(publish_crates, "publish_crate") as upload,
            mock.patch.object(publish_crates, "wait_for_registry"),
            redirect_stdout(io.StringIO()),
        ):
            publish_crates.publish(
                order,
                "0.2.10",
                resume=False,
                excluded_packages=excluded,
            )
        preflight.assert_called_once_with(
            order,
            "0.2.10",
            excluded_packages=excluded,
        )
        self.assertEqual(
            upload.call_args_list,
            [
                mock.call("bonsai-ninja-a", "0.2.10"),
                mock.call("bonsai-ninja-b", "0.2.10"),
            ],
        )

    def test_preflight_packages_workspace_once_and_inspects_every_archive(self) -> None:
        order = ["bonsai-ninja-a", "bonsai-ninja-b"]
        excluded = {"bonsai-ninja-testkit", "bonsai-ninja-conformance"}
        with (
            mock.patch.object(publish_crates, "run") as run,
            mock.patch.object(
                publish_crates.Path,
                "read_bytes",
                side_effect=[b"archive-a", b"archive-b"],
            ),
            mock.patch.object(
                publish_crates, "canonical_crate_contents"
            ) as inspect,
            mock.patch.object(publish_crates, "remove_package_artifacts") as remove,
            redirect_stdout(io.StringIO()),
        ):
            publish_crates.preflight_package_archives(
                order,
                "0.2.10",
                excluded_packages=excluded,
            )

        run.assert_called_once_with(
            "cargo",
            "package",
            "--workspace",
            "--locked",
            "--no-verify",
            "--exclude",
            "bonsai-ninja-conformance",
            "--exclude",
            "bonsai-ninja-testkit",
        )
        self.assertEqual(
            inspect.call_args_list,
            [
                mock.call(b"archive-a", expected_root="bonsai-ninja-a-0.2.10"),
                mock.call(b"archive-b", expected_root="bonsai-ninja-b-0.2.10"),
            ],
        )
        self.assertEqual(
            remove.call_args_list,
            [
                mock.call("bonsai-ninja-a", "0.2.10"),
                mock.call("bonsai-ninja-b", "0.2.10"),
            ],
        )


class CanonicalCrateContentsTests(unittest.TestCase):
    def test_ignores_container_compression_metadata(self) -> None:
        files = {
            "demo-0.1.0/.cargo_vcs_info.json": b'{"git":{"sha1":"abc"}}',
            "demo-0.1.0/src/lib.rs": b"pub fn demo() {}\n",
        }
        first = crate_archive(files, gzip_mtime=1)
        second = crate_archive(files, gzip_mtime=2)
        self.assertNotEqual(first, second)
        self.assertEqual(
            publish_crates.canonical_crate_contents(
                first, expected_root="demo-0.1.0"
            ),
            publish_crates.canonical_crate_contents(
                second, expected_root="demo-0.1.0"
            ),
        )

    def test_detects_changed_package_file(self) -> None:
        first = crate_archive(
            {"demo-0.1.0/src/lib.rs": b"pub fn demo() {}\n"}, gzip_mtime=1
        )
        second = crate_archive(
            {"demo-0.1.0/src/lib.rs": b"pub fn changed() {}\n"}, gzip_mtime=1
        )
        self.assertNotEqual(
            publish_crates.canonical_crate_contents(
                first, expected_root="demo-0.1.0"
            ),
            publish_crates.canonical_crate_contents(
                second, expected_root="demo-0.1.0"
            ),
        )

    def test_rejects_member_outside_expected_package_root(self) -> None:
        archive = crate_archive({"other/src/lib.rs": b""}, gzip_mtime=1)
        with self.assertRaisesRegex(ValueError, "outside"):
            publish_crates.canonical_crate_contents(
                archive, expected_root="demo-0.1.0"
            )


if __name__ == "__main__":
    unittest.main()

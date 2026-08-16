#!/usr/bin/env python3
"""Unit tests for crates.io publication retry behavior."""

from __future__ import annotations

import datetime as dt
import importlib.util
import io
import unittest
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
            publish_crates.publish_crate("bonsai-ninja-vfs")
        self.assertEqual(popen.call_count, 2)
        sleep.assert_called_once_with(
            float(publish_crates.RATE_LIMIT_FALLBACK_SECONDS)
        )


if __name__ == "__main__":
    unittest.main()

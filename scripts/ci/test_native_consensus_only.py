#!/usr/bin/env python3
"""Source-scan false-pass regressions on isolated, non-authoritative inputs."""
from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import check_native_consensus_only as scanner


class NativeSourceScanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()

    def file(self, name: str, content: bytes = b"native source\n") -> Path:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def rejected(self, paths: list[Path], reason: str) -> None:
        result = scanner.scan(self.root, paths)
        self.assertEqual(result["result"], "FAIL")
        self.assertIn(reason, [finding["reason"] for finding in result["findings"]])

    def test_native_utf8_and_binary_are_accepted(self) -> None:
        paths = [self.file("native.rs"), self.file("image.bin", b"\xff\x00\xfe")]
        self.assertEqual(scanner.scan(self.root, paths)["result"], "PASS")

    def test_each_forbidden_token_in_non_utf8_content_is_detected(self) -> None:
        for label, token in scanner.FORBIDDEN.items():
            with self.subTest(label=label):
                path = self.file("opaque.bin", b"\xff\n" + token.upper().encode("ascii"))
                self.rejected([path], label)

    def test_retired_path_is_detected(self) -> None:
        label, token = next(iter(scanner.FORBIDDEN.items()))
        self.rejected([self.file(token + ".rs")], label)

    def test_missing_tracked_file_fails_closed(self) -> None:
        self.rejected([self.root / "missing.rs"], "unreadable-tracked-file")

    def test_unreadable_tracked_file_fails_closed(self) -> None:
        path = self.file("private.rs")
        with mock.patch.object(Path, "read_bytes", side_effect=PermissionError("fixture")):
            self.rejected([path], "unreadable-tracked-file")

    def test_tracked_directory_is_not_silently_skipped(self) -> None:
        path = self.root / "directory"
        path.mkdir()
        self.rejected([path], "non-regular-tracked-file")

    def test_link_to_tracked_internal_file_is_accepted(self) -> None:
        target = self.file("plan.md")
        link = self.root / "compat.md"
        link.symlink_to(target.name)
        self.assertEqual(scanner.scan(self.root, [link, target])["result"], "PASS")

    def test_untracked_link_target_fails_closed(self) -> None:
        target = self.file("untracked.md")
        link = self.root / "link.md"
        link.symlink_to(target.name)
        self.rejected([link], "untracked-or-external-symlink")

    def test_external_target_is_rejected_without_reading(self) -> None:
        with tempfile.TemporaryDirectory() as outside:
            target = Path(outside) / "outside.md"
            target.write_bytes(b"native")
            link = self.root / "link.md"
            link.symlink_to(target)
            with mock.patch.object(Path, "read_bytes", side_effect=AssertionError("external read")):
                self.rejected([link], "untracked-or-external-symlink")

    def test_broken_link_fails_closed(self) -> None:
        link = self.root / "broken.md"
        link.symlink_to("absent.md")
        self.rejected([link], "unreadable-tracked-file")

    def test_link_loop_fails_closed(self) -> None:
        link = self.root / "loop.md"
        link.symlink_to(link.name)
        self.rejected([link], "unreadable-tracked-file")

    def test_retired_directory_dangling_link_is_detected(self) -> None:
        path = self.root / scanner.RETIRED_DIRS[0].relative_to(scanner.ROOT)
        path.parent.mkdir(parents=True)
        path.symlink_to("absent")
        self.rejected([], "retired-directory-present")

    def test_git_inventory_failure_cannot_report_pass(self) -> None:
        output = io.StringIO()
        with mock.patch.object(scanner, "tracked_paths", side_effect=subprocess.CalledProcessError(1, "git")):
            with contextlib.redirect_stdout(output):
                self.assertEqual(scanner.main(), 2)
        result = json.loads(output.getvalue())
        self.assertEqual(result["result"], "FAIL")
        self.assertEqual(result["findings"][0]["reason"], "tracked-inventory-unavailable")


if __name__ == "__main__":
    unittest.main()

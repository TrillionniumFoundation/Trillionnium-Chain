#!/usr/bin/env python3
"""Real Git/file regressions for public locked-archive collection, not Rust tests."""
from pathlib import Path
import hashlib
import json
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import collect_locked_cargo_archives_v1 as collector


class LockedArchives(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / "source"
        (self.root / "trillionnium").mkdir(parents=True)
        self.cache = self.base / "cache"
        self.registry = self.cache / "index.crates.io-fixture"
        self.registry.mkdir(parents=True)
        self.data = b"bounded archive fixture\n"
        self.archive = self.registry / "example-1.0.0.crate"
        self.archive.write_bytes(self.data)
        self.lock = self.root / "trillionnium/Cargo.lock"
        self.lock.write_text('version = 4\n[[package]]\nname = "example"\nversion = "1.0.0"\nsource = "' + collector.PUBLIC_REGISTRY + '"\nchecksum = "' + hashlib.sha256(self.data).hexdigest() + '"\n')
        self.git("init", "-q")
        self.commit()
        self.output = self.base / "out"

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.root), *args], text=True, stderr=subprocess.DEVNULL).strip()

    def commit(self):
        self.git("add", ".")
        self.git("-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "fixture")
        self.head = self.git("rev-parse", "HEAD")

    def run_collector(self):
        return collector.collect(self.root, self.cache, self.output, self.head)

    def test_only_locked_public_archive_is_copied(self):
        (self.registry / "private-token.crate").write_bytes(b"not a lockfile input")
        (self.cache / "credentials.toml").write_text("secret-fixture")
        report = self.run_collector()
        self.assertTrue(report["all_locked_public_archives_captured"])
        self.assertEqual({p.name for p in self.output.iterdir()}, {self.archive.name, "Cargo.lock", "manifest.json"})
        self.assertEqual((self.output / self.archive.name).read_bytes(), self.data)
        self.assertEqual(json.loads((self.output / "manifest.json").read_text()), report)

    def test_missing_archive_is_reported_not_substituted(self):
        self.archive.unlink()
        (self.registry / "example-0.9.0.crate").write_bytes(self.data)
        report = self.run_collector()
        self.assertEqual(report["missing"], [self.archive.name])
        self.assertEqual(report["archives"], [])
        self.assertFalse(report["all_locked_public_archives_captured"])

    def test_corruption_and_symlink_are_rejected(self):
        self.archive.write_bytes(b"wrong")
        with self.assertRaisesRegex(ValueError, "checksum"):
            self.run_collector()
        self.assertFalse(self.output.exists())
        self.archive.unlink()
        other = self.base / "other"
        other.write_bytes(self.data)
        self.archive.symlink_to(other)
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.run_collector()
        self.assertFalse(self.output.exists())

    def test_source_change_or_wrong_head_prevents_output(self):
        with self.assertRaises(ValueError):
            collector.collect(self.root, self.cache, self.output, "0" * 40)
        self.lock.write_text(self.lock.read_text() + "# dirty\n")
        with self.assertRaises(ValueError):
            self.run_collector()
        self.assertFalse(self.output.exists())

    def test_changed_bytes_during_copy_do_not_publish(self):
        original = collector.shutil.copyfile
        def corrupt(*args, **kwargs):
            result = original(*args, **kwargs)
            Path(args[1]).write_bytes(b"substituted")
            return result
        with patch.object(collector.shutil, "copyfile", side_effect=corrupt):
            with self.assertRaisesRegex(ValueError, "changed while copying"):
                self.run_collector()
        self.assertFalse(self.output.exists())

    def test_existing_output_and_byte_limits_are_enforced(self):
        self.output.mkdir()
        with self.assertRaises(ValueError):
            self.run_collector()
        self.output.rmdir()
        for name in ("MAX_ARCHIVE_BYTES", "MAX_TOTAL_BYTES"):
            with self.subTest(name=name), patch.object(collector, name, 1):
                with self.assertRaisesRegex(ValueError, "byte limit"):
                    self.run_collector()
                self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()

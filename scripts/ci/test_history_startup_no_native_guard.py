#!/usr/bin/env python3
"""Small namespace-observer controls, never Native or death qualification."""
import fcntl
import os
from pathlib import Path
import tempfile
import unittest

from history_startup_no_native_process_guard import prepare, snapshot, strict


class EmptyNamespaceGuard(unittest.TestCase):
    def create(self, path):
        result = prepare(path, os.geteuid(), '11' * 32, '22' * 32, path.parent / 'journal')
        for fd in result[:3]:
            self.addCleanup(os.close, fd)
        return result

    def test_exclusive_creation_full_inventory_and_held_lease(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fresh'
            parent, native, lease, before = self.create(path)
            self.assertEqual(snapshot(parent, native, lease, path, os.geteuid()), before)
            body = strict(os.pread(lease, 4096, 0))
            self.assertEqual(body['namespace_parent'], str(path))
            self.assertEqual(body['journal_path'], str(path.parent / 'journal'))
            self.assertEqual(body['identity_sha256'], '11' * 32)
            self.assertEqual(body['preparation_sha256'], '22' * 32)
            self.assertEqual(len(body['reservation_id']), 64)
            original = (path / 'startup-namespace.lock').read_bytes()
            with self.assertRaises(FileExistsError):
                prepare(path, os.geteuid(), '33' * 32, '44' * 32, path.parent / 'journal')
            self.assertEqual((path / 'startup-namespace.lock').read_bytes(), original)
            with (path / 'startup-namespace.lock').open('r+b') as other:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertEqual(snapshot(parent, native, lease, path, os.geteuid()), before)

    def test_extra_native_entry_refuses_and_preserves_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fresh'
            parent, native, lease, _ = self.create(path)
            unexpected = path / 'native' / 'actual-state'
            unexpected.write_bytes(b'not empty and never reset')
            with self.assertRaises(AssertionError):
                snapshot(parent, native, lease, path, os.geteuid())
            self.assertEqual(unexpected.read_bytes(), b'not empty and never reset')

    def test_lease_replacement_and_parent_extra_entry_refuse(self):
        for change in ('lease-replacement', 'parent-extra-entry'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'fresh'
                parent, native, lease, _ = self.create(path)
                if change == 'lease-replacement':
                    old = path / 'startup-namespace.lock'
                    raw = old.read_bytes()
                    old.rename(path / 'preserved-old-lease')
                    old.write_bytes(raw)
                    old.chmod(0o600)
                else:
                    (path / 'additional-namespace').mkdir(mode=0o700)
                with self.assertRaises(AssertionError):
                    snapshot(parent, native, lease, path, os.geteuid())

    def test_duplicate_json_and_existing_namespace_never_become_fresh(self):
        with self.assertRaisesRegex(ValueError, 'duplicate JSON'):
            strict(b'{"identity":1,"identity":2}')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'occupied'
            path.mkdir(mode=0o700)
            existing = path / 'preserved'
            existing.write_bytes(b'existing Native bytes')
            before = dict(mode=path.stat().st_mode, inode=path.stat().st_ino)
            with self.assertRaises(FileExistsError):
                prepare(path, os.geteuid(), '11' * 32, '22' * 32, path.parent / 'journal')
            self.assertEqual(existing.read_bytes(), b'existing Native bytes')
            self.assertEqual(before, dict(mode=path.stat().st_mode, inode=path.stat().st_ino))
            self.assertEqual(sorted(p.name for p in path.iterdir()), ['preserved'])


if __name__ == '__main__':
    unittest.main()

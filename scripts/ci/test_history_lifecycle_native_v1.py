#!/usr/bin/env python3
"""Lifecycle lane reader controls; these do not prove native execution."""
import unittest
import fcntl
import os
from pathlib import Path
import tempfile
import time

from history_lifecycle_process_guard_v1 import prepare_birth, empty_snapshot

from run_history_lifecycle_native_v1 import PREFIX, ROSTER, roster, suite_passed


class LifecycleNativeLane(unittest.TestCase):
    def test_exact_twelve_executed_and_no_ignored_or_substituted_case(self):
        self.assertEqual(len(ROSTER), 12)
        self.assertEqual(roster('\n'.join(name + ': test' for name in ROSTER)), ROSTER)
        for changed in (ROSTER[:-1], ROSTER + [ROSTER[0]],
                        ROSTER[:-1] + [ROSTER[-1] + '_substitute']):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                roster('\n'.join(name + ': test' for name in changed))
        log = 'running 12 tests\n' + ''.join(f'test {name} ... ok\n' for name in ROSTER)
        summary = ('test result: ok. 12 passed; 0 failed; 0 ignored; '
                   '0 measured; 700 filtered out; finished in 100.00s')
        self.assertTrue(suite_passed(log + summary))
        for bad in (summary.replace('12 passed', '0 passed'),
                    summary.replace('0 ignored', '1 ignored'),
                    summary.replace('0 failed', '1 failed'), summary + '\n' + summary):
            self.assertFalse(suite_passed(log + bad))
        self.assertFalse(suite_passed(log.replace('... ok', '... ignored', 1) + summary))
        self.assertFalse(suite_passed(log.replace(ROSTER[0], ROSTER[1], 1) + summary))
        self.assertFalse(suite_passed(summary))
        self.assertFalse(suite_passed(log.replace(PREFIX, 'store::history_effect_v6::tests::') + summary))
        self.assertFalse(suite_passed(log + log + summary))


class LifecycleBirthObserverControls(unittest.TestCase):
    def test_real_exclusive_creation_lock_and_acquisition_time_preserve_complete_empty_birth(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            parent_path = root / 'reserved'
            before_ns = time.time_ns()
            parent, native, lease, birth, prepared_ns, acquired_ns = prepare_birth(
                parent_path, os.geteuid(), 'a' * 64, 'b' * 64, root / 'outside-journal')
            competitor = None
            try:
                self.assertLessEqual(before_ns, acquired_ns)
                self.assertLessEqual(acquired_ns, prepared_ns)
                self.assertLessEqual(prepared_ns, time.time_ns())
                self.assertEqual(birth, empty_snapshot(parent, native, lease, parent_path, os.geteuid()))
                competitor = os.open(parent_path / 'startup-namespace.lock', os.O_RDWR | os.O_CLOEXEC)
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(competitor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with self.assertRaises(FileExistsError):
                    prepare_birth(parent_path, os.geteuid(), 'a' * 64, 'b' * 64, root / 'outside-journal')
                self.assertEqual(birth, empty_snapshot(parent, native, lease, parent_path, os.geteuid()))
            finally:
                for fd in (competitor, native, lease, parent):
                    if fd is not None:
                        os.close(fd)
            # Merely reading/locking the same lease after release changes no
            # inode/ctime facts; this is not a second exclusive creation.
            parent = os.open(parent_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            native = os.open(parent_path / 'native', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            lease = os.open(parent_path / 'startup-namespace.lock', os.O_RDWR | os.O_NOFOLLOW)
            try:
                fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.assertEqual(birth, empty_snapshot(parent, native, lease, parent_path, os.geteuid()))
            finally:
                for fd in (lease, native, parent):
                    os.close(fd)


if __name__ == '__main__':
    unittest.main()

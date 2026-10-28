#!/usr/bin/env python3
"""Real owned-process observer controls; these are not native History evidence."""
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import history_effect_v6_process_guard as guard


CHILD = """
import threading, time
def worker():
    while True:
        time.sleep(0.05)
for _ in range(2):
    threading.Thread(target=worker, daemon=True).start()
print('READY', flush=True)
while True:
    time.sleep(0.05)
"""


class CompleteObservationPublication(unittest.TestCase):
    def test_final_name_is_absent_during_json_write_and_contains_complete_record(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'guardian-result.json'
            value = {'actual_wait4': True, 'wait_status': 9, 'passed': True}

            def checked_dump(record, output, **options):
                self.assertEqual(record, value)
                output.write('{"actual_wait4":')
                output.flush()
                self.assertFalse(path.exists())
                self.assertEqual(Path(output.name).stat().st_mode & 0o777, 0o600)
                output.write('true,"passed":true,"wait_status":9}')

            with patch.object(guard.json, 'dump', side_effect=checked_dump):
                guard.write(path, value)
            self.assertEqual(json.loads(path.read_bytes()), value)
            self.assertEqual(path.stat().st_nlink, 1)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(list(Path(directory).iterdir()), [path])

    def test_existing_final_observation_is_never_replaced(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'guardian-result.json'
            original = b'{"passed":false,"reason":"earlier observation"}\n'
            path.write_bytes(original)
            with self.assertRaises(FileExistsError):
                guard.write(path, {'passed': True})
            self.assertEqual(path.read_bytes(), original)
            self.assertEqual(json.loads(path.with_name(path.name + '.pending').read_bytes()),
                             {'passed': True})


class ActualOwnedObserver(unittest.TestCase):
    def setUp(self):
        self.child = subprocess.Popen([sys.executable, '-c', CHILD],
                                      stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE)
        self.pidfd = os.pidfd_open(self.child.pid, 0)
        self.addCleanup(self.closed)
        with selectors.DefaultSelector() as selector:
            selector.register(self.child.stdout, selectors.EVENT_READ)
            self.assertTrue(selector.select(5), 'owned fixture did not become ready')
        self.assertEqual(self.child.stdout.readline(), b'READY\n')
        self.record = {'scope': 'Python owned-process observer only; no Native or recovery authority'}
        self.deadline = time.monotonic() + 5
        self.proc, self.pinned, self.threads = guard.stop_owned_group(
            self.child, self.pidfd, guard.sha(Path(sys.executable)), self.deadline, self.record)
        self.assertIsNone(self.child.returncode, 'stopped is not terminal')
        self.assertGreaterEqual(len(self.threads), 3)

    def closed(self):
        if self.child.returncode is None:
            # Only this test's actual owned PID is signalled. No proc-visible
            # PID, inferred descendant or unrelated process is a kill target.
            os.kill(self.child.pid, signal.SIGKILL)
            pid, status, usage = os.wait4(self.child.pid, 0)
            self.assertEqual(pid, self.child.pid)
            self.assertTrue(os.WIFSIGNALED(status))
            self.assertEqual(os.WTERMSIG(status), signal.SIGKILL)
            self.child.returncode = os.waitstatus_to_exitcode(status)
            if hasattr(self, 'record'):
                self.record['actual_final_wait4'] = {
                    'signal': signal.SIGKILL, 'reported_user_seconds': str(usage.ru_utime),
                    'reported_system_seconds': str(usage.ru_stime),
                    'native_receipt_created': False,
                }
                print('HISTORY_V6_OBSERVER_COMPONENT ' + json.dumps(self.record, sort_keys=True))
        os.close(self.pidfd)
        self.child.stdout.close()
        self.child.stderr.close()

    def test_actual_stopped_threads_two_complete_graphs_and_final_sigkill_wait4(self):
        self.assertEqual(guard.stable_parent_observation(
            self.proc, self.pinned, self.deadline, self.record), [])
        self.assertEqual(self.record['complete_matching_parent_snapshots'], 2)
        observations = self.record['complete_parent_observations']
        self.assertLessEqual(len(observations), 4)
        self.assertGreaterEqual(sum(row['complete'] for row in observations), 2)
        self.assertTrue(observations[-2]['complete'] and observations[-1]['complete'])
        self.assertEqual(observations[-2]['parent_graph_sha256'], observations[-1]['parent_graph_sha256'])
        self.assertTrue(observations[-1]['matches_previous_complete'])
        self.assertIsNone(self.child.returncode)

    def test_missing_proc_rows_exhaust_four_whole_observations_without_empty_fact(self):
        def missing(_):
            raise FileNotFoundError('controlled whole-snapshot fault, no fabricated parent rows')
        with self.assertRaisesRegex(RuntimeError, 'four complete-snapshot attempts'):
            guard.stable_parent_observation(
                self.proc, self.pinned, self.deadline, self.record, reader=missing)
        self.assertEqual(len(self.record['complete_parent_observations']), 4)
        self.assertTrue(all(not row['complete'] for row in self.record['complete_parent_observations']))
        self.assertNotIn('complete_matching_parent_snapshots', self.record)
        self.assertIsNone(self.child.returncode)

    def test_denied_snapshot_remains_unknown_and_never_becomes_empty(self):
        def denied(_):
            raise PermissionError('controlled proc-read denial')
        with self.assertRaises(PermissionError):
            guard.stable_parent_observation(
                self.proc, self.pinned, self.deadline, self.record, reader=denied)
        self.assertEqual(len(self.record['complete_parent_observations']), 1)
        self.assertFalse(self.record['complete_parent_observations'][0]['complete'])
        self.assertNotIn('complete_matching_parent_snapshots', self.record)
        self.assertIsNone(self.child.returncode)


if __name__ == '__main__':
    unittest.main(verbosity=2)

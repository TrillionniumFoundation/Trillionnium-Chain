"""The diagnostic cursor leaves a bounded prefix without affecting qualification."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from hia.platform.service_settlement.qualification.native import Progress


class SettlementProgressTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'progress.jsonl'

    def rows(self):
        return [json.loads(row) for row in self.path.read_bytes().splitlines()]

    def test_exact_position_bounds_and_immediate_visibility(self):
        counters = {'fixtures': 232, 'fixture_operations': 900}
        capture = SimpleNamespace(calls=16698, public_dispatch_wall_ns=447)
        with patch.object(Progress, 'MAX_ROWS', 2), Progress(self.path) as progress:
            progress.record('stage_start')
            progress.record('operation_start', counters, capture, fixture_ordinal=233,
                            operation_ordinal=128, opcode=1)
            progress.record('stage_done')
            start, operation = self.rows()
            self.assertLessEqual(start['wall_ns'], operation.pop('wall_ns'))
            self.assertLessEqual(start['thread_cpu_ns'], operation.pop('thread_cpu_ns'))
            self.assertEqual(operation, {'phase': 'operation_start', 'fixture_ordinal': 233,
                                         'operation_ordinal': 128, 'opcode': 1,
                                         'completed_fixtures': 232, 'completed_operations': 900,
                                         'capture_records': 16698, 'public_dispatch_wall_ns': 447})

    def test_abrupt_process_exit_leaves_completed_rows(self):
        # No context manager exit or Python file cleanup occurs before os._exit.
        script = ('import os, sys; from pathlib import Path; '
                  'from hia.platform.service_settlement.qualification.native import Progress; '
                  'progress = Progress(Path(sys.argv[1])); progress.record("stage_start"); '
                  'os._exit(47)')
        completed = subprocess.run([sys.executable, '-B', '-c', script, str(self.path)], timeout=10)
        self.assertEqual(completed.returncode, 47)
        self.assertEqual([row['phase'] for row in self.rows()], ['stage_start'])

    def test_bad_diagnostic_storage_never_overwrites_or_raises(self):
        self.path.write_bytes(b'original')
        with Progress(self.path) as progress:
            progress.record('stage_start')
        self.assertEqual(self.path.read_bytes(), b'original')

    def test_oversized_row_closes_journal_without_damaging_prefix(self):
        with Progress(self.path) as progress:
            progress.record('stage_start')
            progress.record('operation_start', unused='x' * Progress.MAX_ROW_BYTES)
            progress.record('stage_done')
        self.assertEqual([row['phase'] for row in self.rows()], ['stage_start'])


if __name__ == '__main__':
    unittest.main()

"""Fresh-cwd startup regression only; the full Delta gate has its own CI step."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[2]


class NodeDeltaEntrypoints(unittest.TestCase):
    def check_help(self, name):
        environment = dict(os.environ)
        environment.pop('PYTHONPATH', None)
        environment.pop('PYTHONHOME', None)
        with tempfile.TemporaryDirectory(prefix='node-delta-cli-') as working:
            completed = subprocess.run([sys.executable, '-B',
                str(REPO/'hia/platform/node_delta'/name), '--help'], cwd=working,
                env=environment, capture_output=True, text=True, timeout=15)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn('usage:', completed.stdout)

    def test_native_qualification_help(self):
        self.check_help('qualify.py')

    def test_original_reference_help(self):
        self.check_help('rust_delta_oracle.py')


if __name__ == '__main__':
    unittest.main()

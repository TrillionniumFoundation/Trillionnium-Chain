"""Go/Python error taxonomy parity for rejected ASERT scalar inputs.

Supplementary research only: skips when Go is unavailable, does not invoke
native Rust, PoN consensus, proof mining, or public-node admission.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch
import shutil
import subprocess
import tempfile
import unittest

from daa_go_differential import run


class DaaGoErrorParity(unittest.TestCase):
    @unittest.skipUnless(shutil.which('go'), 'Go compiler unavailable')
    def test_actual_go_rejects_bad_parameters_separately_from_i128_range(self):
        source = Path(__file__).with_name('daa_reference_go') / 'main.go'
        base = {
            'anchor_target': 1 << 128,
            'pow_limit': (1 << 255) - 1,
            'anchor_parent_time': 1000,
            'parent_time': 1200,
            'anchor_height': 1,
            'candidate_height': 20,
            'spacing': 10,
            'half_life': 7200,
        }
        cases = [
            dict(base),
            dict(base, anchor_target=0),
            dict(base, anchor_target=(1 << 255)),
            dict(base, anchor_height=0),
            dict(base, candidate_height=1),
            dict(base, spacing=0),
            dict(base, half_life=0),
            dict(base, candidate_height=(1 << 64)-1,
                 spacing=(1 << 64)-1),
            dict(base, candidate_height=(1 << 64)-1,
                 spacing=1 << 62),
        ]
        with tempfile.TemporaryDirectory(prefix='pon-asert-go-error-') as tmp:
            binary = Path(tmp) / 'asert-go'
            subprocess.run(
                ['go','build','-o',str(binary),str(source)],
                capture_output=True, text=True, check=True, timeout=90,
            )
            with patch('daa_go_differential.cases',
                       return_value=iter(cases)):
                report = run(binary, count=len(cases), seed=20261026,
                             expose_rows=True)
        self.assertEqual(report['cases'], 9)
        self.assertEqual(report['compared'], 1)
        self.assertEqual(report['rejected'], 8)
        self.assertEqual(
            [row['kind'] for row in report['rows']],
            ['target'] + ['rejected-parameters']*6 + ['rejected-range']*2
        )
        self.assertEqual(
            [row['go_result'] for row in report['rows'][1:]],
            ['ASERT_RESEARCH_PARAMETERS']*6
            + ['ASERT_RESEARCH_RANGE']*2,
        )


if __name__ == '__main__':
    unittest.main()

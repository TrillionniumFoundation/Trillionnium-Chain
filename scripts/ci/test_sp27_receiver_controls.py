#!/usr/bin/env python3
"""Exact adapter dispatch and preservation checks; no native service claims."""
import unittest
from pathlib import Path
from unittest.mock import patch

import run_from_zero_host as host
import run_sp27_receiver_controls as sp27
import public_host_ci_observation as observation


class AdapterControls(unittest.TestCase):
    def test_only_exact_command_and_external_output_are_admitted(self):
        command = ['python3', sp27.SCRIPT, '--out', '/tmp/sp27-receiver-controls']
        self.assertEqual(host.validate_command(command), Path(command[-1]))
        for bad in (command + ['--relax-host'], ['python3', '/tmp/foreign.py', '--out', command[-1]],
                    [*command[:3], str(host.ROOT / 'within-checkout')]):
            with self.subTest(command=bad), self.assertRaises(ValueError):
                host.validate_command(bad)

    def test_preparation_and_readback_use_only_new_adapter(self):
        command = ['python3', sp27.SCRIPT, '--out', '/tmp/sp27-receiver-controls']
        output = Path(command[-1])
        with patch.object(sp27, 'validate_preparation', return_value={'prepared': True}) as callback:
            self.assertEqual(host.prepare_command(command, output, Path('/tmp/host')), {'prepared': True})
            callback.assert_called_once_with(output)
        with patch.object(sp27, 'bind_execution', return_value={'bound': True}) as callback:
            self.assertEqual(host.bind_command(command, {'prepared': True}, output), {'bound': True})
            callback.assert_called_once_with({'prepared': True}, output)

    def test_original_resources_and_outer_timeout_are_preserved(self):
        self.assertEqual(sp27.NATIVE_TIMEOUT_SECONDS, 90)
        self.assertEqual(observation.LIMITS, {'cpu.max': '25000 100000', 'cpu.max.burst': '0',
            'memory.max': '2147483648', 'memory.swap.max': '0', 'pids.max': '256'})
        self.assertNotIn('TRNM_SP27_RECEIVER_CONTROLS_DIR', host.ENVIRONMENT)


if __name__ == '__main__':
    unittest.main()

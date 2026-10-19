#!/usr/bin/env python3
"""Reader counterexamples only; these synthetic records are not native evidence."""
from pathlib import Path
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pon_public_v3_phase_read as reader


def record():
    return {'complete': True, 'observation_failed': False, 'dispatch_started': True,
            'dispatch_accepted': False, 'dispatch_thread_cpu_ns': 100,
            'full_work_started': True, 'full_work_accepted': False, 'full_work_thread_cpu_ns': 30,
            'submit_phases': [{'phase': phase, 'started': False, 'completed': False,
                               'accepted': None, 'wall_ns': None, 'thread_cpu_ns': None}
                              for phase in reader.PHASES]}


class ReaderTests(unittest.TestCase):
    def test_late_ack_is_separate_from_on_time_and_confirmation(self):
        rows = [{'status': 'ok', 'returned_after_window': late, 'packet_index': 0,
                 'elapsed_wall_ns': 12, 'calling_process_cpu_ns': None} for late in (False, True)]
        value = reader.call_summary(rows)
        self.assertEqual(value['attempts'], 2)
        self.assertEqual(value['acknowledged_on_time'], 1)
        self.assertEqual(value['acknowledged_after_window'], 1)
        self.assertEqual(value['on_time_unique_packet_indices'], [0])
        self.assertEqual(value['calling_process_cpu_ns']['unknown_count'], 2)
        self.assertNotIn('confirmed', value)

    def test_v1_does_not_fabricate_phase_cost_from_dispatch(self):
        row = record()
        del row['submit_phases']
        value = reader.execution_summary([row], False)
        self.assertIsNone(value['submit_phases'])
        self.assertFalse(value['submit_phase_measurements_available'])
        self.assertEqual(value['dispatch_thread_cpu_ns']['sum_known_ns'], 100)
        self.assertEqual(value['full_work_thread_cpu_ns']['sum_known_ns'], 30)
        self.assertNotIn('total_cpu_ns', value)

    def test_unentered_and_entered_unknown_cpu_are_distinct(self):
        row = record()
        row['submit_phases'][2].update(started=True, completed=True, accepted=False,
                                       wall_ns=150, thread_cpu_ns=None)
        value = reader.execution_summary([row], True)['submit_phases']
        self.assertEqual(value[2]['thread_cpu_ns']['unknown_count'], 1)
        self.assertEqual(value[2]['outcomes'], {'rejected': 1})
        self.assertEqual(value[3]['not_started'], 1)
        self.assertEqual(value[3]['thread_cpu_ns']['unknown_count'], 0)
        self.assertIsNone(value[3]['thread_cpu_ns']['mean_known_ns'])

    def test_unfinished_outcome_is_not_successful_or_rejected(self):
        row = record()
        row['complete'] = False
        row['submit_phases'][4].update(started=True, wall_ns=500, thread_cpu_ns=5)
        value = reader.execution_summary([row], True)
        phase = value['submit_phases'][4]
        self.assertEqual(value['record_complete'], 0)
        self.assertEqual((phase['started'], phase['completed'], phase['unfinished']), (1, 0, 1))
        self.assertEqual(phase['outcomes'], {'unknown': 1})
        self.assertEqual(phase['wall_ns']['sum_known_ns'], 500)

    def test_missing_v2_phase_slot_rejects(self):
        row = record()
        row['submit_phases'].pop()
        with self.assertRaisesRegex(ValueError, 'seven ordered'):
            reader.execution_summary([row], True)

    def test_failed_startup_does_not_change_fixed_round_denominator(self):
        value = reader.phase_summary({'mode': 'baseline', 'state_backend': 'authenticated-v1',
                                      'startup_or_campaign_error': 'preserved native startup failure'})
        self.assertEqual(value['scheduled_confirmation_rounds'], 3)
        self.assertIsNone(value['confirmed_rounds'])
        self.assertFalse(value['observations_available'])

    def test_repeated_confirmation_round_and_inflated_aggregate_reject(self):
        phase = {'mode': 'baseline', 'state_backend': 'authenticated-v1', 'duration_seconds': 30,
                 'confirmations': [{'round': 0, 'confirmed_inside_pressure_window': True}] * 2,
                 'all_signed_rounds_confirmed_in_window': True}
        with self.assertRaisesRegex(ValueError, 'unique scheduled'):
            reader.phase_summary(phase)
        phase['confirmations'].pop()
        with self.assertRaisesRegex(ValueError, 'aggregate'):
            reader.phase_summary(phase)

    def test_exact_hash_mismatch_rejects_before_parsing(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'report.json'
            raw = b'{"not":"native evidence"}\n'
            path.write_bytes(raw)
            with self.assertRaisesRegex(ValueError, 'SHA256 mismatch'):
                reader.read_report(path, '00' * 32)
            self.assertEqual(path.read_bytes(), raw)

    def test_boolean_and_negative_timing_are_not_integer_cpu(self):
        for value in (-1, True, 1.5):
            with self.assertRaises(ValueError):
                reader.stats([value])


if __name__ == '__main__':
    unittest.main()

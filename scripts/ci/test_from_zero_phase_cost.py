#!/usr/bin/env python3
"""Negative controls for process scope; synthetic numbers are not service evidence."""
import copy
import unittest
from from_zero_phase_cost import BOUNDARIES, read_phase_process_cost


def sample():
    cpu = [100, 120, 400, 450]
    wall = [0, 50, 4_000_000_050, 4_000_000_100]
    samples = [dict(boundary=name, elapsed_ns=wall[i], process_cpu_counter_ns=cpu[i])
               for i, name in enumerate(BOUNDARIES)]
    def interval(a, b):
        return dict(from_=BOUNDARIES[a], to=BOUNDARIES[b], wall_ns=wall[b] - wall[a],
                    process_cpu_ns=cpu[b] - cpu[a], cpu_state='observed')
    def fixed(a, b):
        row = interval(a, b)
        row['from'] = row.pop('from_')
        return row
    return dict(schema='public-v3-confirmation-phase-process-cost-v1',
                cpu_clock='CLOCK_PROCESS_CPUTIME_ID', process_id=1,
                samples=samples, intervals=[fixed(i, i + 1) for i in range(3)],
                whole_phase=fixed(0, 3),
                retained_files_before=dict(state='absent', regular_files=0, logical_file_bytes=0, error=None),
                retained_files_after=dict(state='observed', regular_files=2, logical_file_bytes=90, error=None),
                physical_network_bytes=None, energy_joules=None, business_acceptance_authority=False)


class PhaseProcessCostTests(unittest.TestCase):
    def test_complete_envelope_does_not_become_window_cost_or_success(self):
        result = read_phase_process_cost(sample())
        self.assertEqual(result['whole_phase']['process_cpu_ns'], 350)
        self.assertEqual(result['retained_logical_file_growth_bytes'], 90)
        self.assertIsNone(result['exact_original_window_cpu_ns'])
        self.assertIsNone(result['physical_disk_io_bytes'])
        self.assertFalse(result['business_acceptance_authority'])

    def test_missing_endpoint_retains_other_intervals_and_unknown_whole(self):
        raw = sample()
        raw['samples'][0]['process_cpu_counter_ns'] = None
        for row in (raw['intervals'][0], raw['whole_phase']):
            row.update(process_cpu_ns=None, cpu_state='clock_unavailable')
        result = read_phase_process_cost(raw)
        self.assertIsNone(result['whole_phase']['process_cpu_ns'])
        self.assertEqual(result['intervals'][1]['process_cpu_ns'], 280)

    def test_reversed_counter_never_becomes_zero(self):
        raw = sample()
        raw['samples'][1]['process_cpu_counter_ns'] = 90
        raw['intervals'][0].update(process_cpu_ns=None, cpu_state='counter_rewind')
        raw['intervals'][1]['process_cpu_ns'] = 310
        self.assertIsNone(read_phase_process_cost(raw)['intervals'][0]['process_cpu_ns'])
        raw['intervals'][0]['process_cpu_ns'] = 0
        with self.assertRaisesRegex(ValueError, 'PHASE_COST_CPU_DELTA'):
            read_phase_process_cost(raw)

    def test_forged_totals_boolean_cpu_boundaries_and_authority_rejected(self):
        original = sample()
        mutations = (
            lambda r: r['whole_phase'].update(process_cpu_ns=351),
            lambda r: r['whole_phase'].update(process_cpu_ns=True),
            lambda r: r['samples'][1].update(boundary='after_join'),
            lambda r: r['samples'][1].update(elapsed_ns=-1),
            lambda r: r.update(business_acceptance_authority=True),
            lambda r: r.update(physical_network_bytes=0),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                raw = copy.deepcopy(original)
                mutation(raw)
                with self.assertRaises(ValueError):
                    read_phase_process_cost(raw)

    def test_disk_error_is_unknown_not_a_partial_or_zero_total(self):
        raw = sample()
        raw['retained_files_after'].update(state='unavailable', regular_files=None,
                                           logical_file_bytes=None, error='non_regular_entry')
        self.assertIsNone(read_phase_process_cost(raw)['retained_logical_file_growth_bytes'])
        raw['retained_files_after']['logical_file_bytes'] = 0
        with self.assertRaisesRegex(ValueError, 'PHASE_COST_UNKNOWN_DISK'):
            read_phase_process_cost(raw)

    def test_signed_disk_growth_keeps_deletions(self):
        raw = sample()
        raw['retained_files_before'].update(state='observed', regular_files=3, logical_file_bytes=100)
        self.assertEqual(read_phase_process_cost(raw)['retained_logical_file_growth_bytes'], -10)


if __name__ == '__main__':
    unittest.main()

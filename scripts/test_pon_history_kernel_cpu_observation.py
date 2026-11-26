#!/usr/bin/env python3
"""Synthetic data-contract controls only; no native or kernel qualification."""
from __future__ import annotations

import copy
import unittest

from pon_public_v3_phase_read import (
    HISTORY_KERNEL_CPU_CLOCK_SCOPE,
    HISTORY_KERNEL_CPU_COST_SCOPE,
    HISTORY_KERNEL_CPU_COUNTER_SCOPE,
    HISTORY_KERNEL_CPU_FIELDS,
    HISTORY_KERNEL_CPU_PHASES,
    HISTORY_KERNEL_CPU_SCHEMA,
    parse_history_kernel_cpu_stat,
    validate_history_kernel_cpu_observation,
)


CPU = ('usage_usec 600\nuser_usec 400\nsystem_usec 200\nnr_periods 16\n'
       'nr_throttled 4\nthrottled_usec 150\nnr_bursts 0\n')


def phase(name, started=False):
    return {'phase': name, 'started': started, 'completed': started,
            'accepted': True if started else None,
            'started_ns': 0 if started else None, 'ended_ns': 100 if started else None}


def sample(raw, begin, end):
    parsed, error = parse_history_kernel_cpu_stat(raw)
    return {'sample_started_ns': begin, 'sample_ended_ns': end,
            'sample_wall_ns': end - begin, 'sample_calling_thread_cpu_ns': 1,
            'expected_parent_identity': {
                'parent': '/sys/fs/cgroup/trnmponpublic.slice', 'device': 7,
                'inode': 11, 'uid': 0, 'boot_id': 'data-only-fixture',
                'cpu_quota_us': 25_000, 'cpu_period_us': 100_000,
                'memory_max_bytes': 2 * 1024 * 1024 * 1024, 'pids_max': 256},
            'raw_cpu_stat': raw, 'counters': parsed, 'observation_error': error,
            'original_read_error_code': None}


def fixture():
    before, after = sample(CPU, 10, 20), sample(CPU.replace('600', '620'), 90, 100)
    delta = {key: after['counters'][key] - before['counters'][key]
             for key in HISTORY_KERNEL_CPU_FIELDS}
    return {'measurement_failures': 0, 'phases': [phase('work', True)],
            'packets': [], 'kernel_cpu_observation': {
                'schema': HISTORY_KERNEL_CPU_SCHEMA,
                'selected_phases': list(HISTORY_KERNEL_CPU_PHASES),
                'native_parent_identity_bound': True,
                'interval_capacity': 51, 'sample_capacity': 102,
                'raw_cpu_stat_capacity_bytes': 2048,
                'records': [{'packet_index': None, 'phase': 'work',
                             'native_returned': True, 'native_accepted': True,
                             'before': before, 'after': after,
                             'whole_parent_delta': {'counters': delta,
                                                    'minimum_elapsed_ns': 70,
                                                    'maximum_elapsed_ns': 90},
                             'qualification_error': None}],
                'measurement_failures': 0, 'original_phase_measurement_failures': 0,
                'native_phase_snapshot_coherent': True,
                'all_observed_intervals_qualified': True,
                'has_control_authority': False,
                'clock_scope': HISTORY_KERNEL_CPU_CLOCK_SCOPE,
                'counter_scope': HISTORY_KERNEL_CPU_COUNTER_SCOPE,
                'cost_scope': HISTORY_KERNEL_CPU_COST_SCOPE}}


class KernelCpuReadbackControls(unittest.TestCase):
    def test_exact_raw_delta_and_phase_binding_remain_data_consistency_only(self):
        out = validate_history_kernel_cpu_observation(fixture())
        self.assertTrue(out['all_observed_intervals_qualified'])
        self.assertEqual(out['qualified_intervals'], 1)
        self.assertFalse(out['has_service_or_consensus_authority'])

    def test_observed_linux_core_sched_field_preserves_raw_counters_and_delta(self):
        # Original run45757278209 head artifact15090531717, first pressure
        # History page/cpu_wait before sample. This is a parser fixture only.
        raw = ('usage_usec 18393406\nuser_usec 12013212\nsystem_usec 6380194\n'
               'nice_usec 0\ncore_sched.force_idle_usec 0\nnr_periods 749\n'
               'nr_throttled 730\nthrottled_usec 67260306\nnr_bursts 0\nburst_usec 0\n')
        expected = {'usage_usec': 18_393_406, 'user_usec': 12_013_212,
                    'system_usec': 6_380_194, 'nr_periods': 749,
                    'nr_throttled': 730, 'throttled_usec': 67_260_306}
        self.assertEqual(parse_history_kernel_cpu_stat(raw), (expected, None))
        value = fixture()
        row = value['kernel_cpu_observation']['records'][0]
        row['before'] = sample(raw, 10, 20)
        row['after'] = sample(raw.replace('18393406', '18393426'), 90, 100)
        out = validate_history_kernel_cpu_observation(value)
        self.assertEqual(row['before']['raw_cpu_stat'], raw)
        self.assertEqual(out['qualified_intervals'], 1)
        self.assertTrue(out['all_observed_intervals_qualified'])
        self.assertFalse(out['has_service_or_consensus_authority'])

    def test_only_exact_core_sched_dotted_field_name_is_supported(self):
        for key in ('future.counter', '.core_sched.force_idle_usec',
                    'core_sched.force_idle_usec.', 'core_sched..force_idle_usec',
                    'core_sched.force.idle_usec', 'core_sched.force_idle_usec_extra',
                    'core_sched.force_idle_usec/', 'Core_sched.force_idle_usec',
                    'core_sched\uff0eforce_idle_usec', 'core_sched.\0force_idle_usec'):
            with self.subTest(key=key):
                self.assertEqual(parse_history_kernel_cpu_stat(CPU + f'{key} 0\n'),
                                 (None, 'malformed_cpu_stat'))

    def test_core_sched_field_keeps_duplicate_unsigned_and_required_refusals(self):
        raw = CPU + 'core_sched.force_idle_usec 0\n'
        self.assertEqual(
            parse_history_kernel_cpu_stat(raw + 'core_sched.force_idle_usec 1\n'),
            (None, 'duplicate_cpu_stat_counter'))
        for number in ('+1', '-1', '1.0', '0x10', '1e3', '١', '1 2'):
            with self.subTest(number=number):
                self.assertEqual(
                    parse_history_kernel_cpu_stat(CPU + f'core_sched.force_idle_usec {number}\n'),
                    (None, 'malformed_cpu_stat'))
        self.assertEqual(
            parse_history_kernel_cpu_stat(CPU + 'core_sched.force_idle_usec 18446744073709551616\n'),
            (None, 'cpu_stat_counter_overflow'))
        self.assertEqual(
            parse_history_kernel_cpu_stat(CPU + 'core_sched.force_idle_usec 18446744073709551615\n'),
            parse_history_kernel_cpu_stat(CPU))
        self.assertEqual(parse_history_kernel_cpu_stat(raw.replace('usage_usec 600\n', '')),
                         (None, 'missing_cpu_stat_counter'))

    def test_historical_absence_does_not_create_zero_cost_or_qualification(self):
        value = fixture()
        del value['kernel_cpu_observation']
        self.assertIsNone(validate_history_kernel_cpu_observation(value))

    def test_missing_duplicate_signed_unicode_overflow_and_extra_input_refuse(self):
        for key in HISTORY_KERNEL_CPU_FIELDS:
            missing = '\n'.join(line for line in CPU.splitlines()
                                if line.split()[0] != key)
            self.assertEqual(parse_history_kernel_cpu_stat(missing)[1],
                             'missing_cpu_stat_counter')
            self.assertEqual(parse_history_kernel_cpu_stat(CPU + f'{key} 1\n')[1],
                             'duplicate_cpu_stat_counter')
        for value in ('+1', '-1', '0x10', '1.0', '1e3', '١',
                      '18446744073709551616', '1 2'):
            with self.subTest(value=value):
                self.assertIsNotNone(parse_history_kernel_cpu_stat(
                    CPU.replace('usage_usec 600', f'usage_usec {value}'))[1])
        self.assertIsNotNone(parse_history_kernel_cpu_stat(CPU + 'future 1\nfuture 2\n')[1])

    def test_exact_raw_capacity_is_not_a_truncation_allowance(self):
        padding = 2048 - len(CPU) - len('future 0\n')
        exact = CPU + 'future' + 'x' * padding + ' 0\n'
        self.assertEqual(len(exact.encode()), 2048)
        self.assertIsNone(parse_history_kernel_cpu_stat(exact)[1])
        self.assertEqual(parse_history_kernel_cpu_stat(exact + ' ')[1], 'cpu_stat_too_large')
        value = fixture()
        value['kernel_cpu_observation']['records'][0]['before']['raw_cpu_stat'] = exact + ' '
        with self.assertRaises(ValueError):
            validate_history_kernel_cpu_observation(value)

    def test_bad_raw_counters_cannot_be_replaced_by_a_forged_parsed_value(self):
        for mutation in ('raw', 'parsed', 'delta', 'bool_delta'):
            value = fixture()
            row = value['kernel_cpu_observation']['records'][0]
            if mutation == 'raw':
                row['after']['raw_cpu_stat'] = CPU
            elif mutation == 'parsed':
                row['after']['counters']['usage_usec'] += 1
            elif mutation == 'bool_delta':
                row['whole_parent_delta']['counters']['user_usec'] = False
            else:
                row['whole_parent_delta']['counters']['usage_usec'] += 1
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                validate_history_kernel_cpu_observation(value)

    def test_counter_reset_is_retained_as_unqualified_never_zero_filled(self):
        value = fixture()
        kernel = value['kernel_cpu_observation']
        row = kernel['records'][0]
        row['after'] = sample(CPU.replace('600', '599'), 90, 100)
        row['whole_parent_delta'] = None
        row['qualification_error'] = 'counter_rewind_or_reset'
        kernel['all_observed_intervals_qualified'] = False
        out = validate_history_kernel_cpu_observation(value)
        self.assertFalse(out['all_observed_intervals_qualified'])
        kernel['all_observed_intervals_qualified'] = True
        with self.assertRaises(ValueError):
            validate_history_kernel_cpu_observation(value)

    def test_parent_identity_or_scope_substitution_cannot_qualify(self):
        for mutation in ('inode', 'boot', 'parent', 'scope', 'authority'):
            value = fixture()
            kernel = value['kernel_cpu_observation']
            identity = kernel['records'][0]['after']['expected_parent_identity']
            if mutation == 'inode':
                identity['inode'] += 1
            elif mutation == 'boot':
                identity['boot_id'] += '-other'
            elif mutation == 'parent':
                identity['parent'] += '/other'
            elif mutation == 'scope':
                kernel['counter_scope'] = 'importer thread CPU'
            else:
                kernel['has_control_authority'] = True
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                validate_history_kernel_cpu_observation(value)

    def test_moved_duplicate_or_missing_original_phase_is_rejected(self):
        for mutation in ('moved', 'duplicate', 'missing', 'outside'):
            value = fixture()
            kernel = value['kernel_cpu_observation']
            row = kernel['records'][0]
            if mutation == 'moved':
                row['phase'] = 'admission_prepare'
            elif mutation == 'duplicate':
                kernel['records'].append(copy.deepcopy(row))
            elif mutation == 'outside':
                row['after']['sample_ended_ns'] = 101
                row['after']['sample_wall_ns'] = 11
            else:
                kernel['records'].clear()
                kernel['all_observed_intervals_qualified'] = False
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                validate_history_kernel_cpu_observation(value)

    def test_sample_time_and_delta_window_are_recomputed(self):
        for mutation in ('wall', 'clock', 'window', 'unknown'):
            value = fixture()
            row = value['kernel_cpu_observation']['records'][0]
            if mutation == 'wall':
                row['before']['sample_wall_ns'] += 1
            elif mutation == 'clock':
                row['after']['sample_started_ns'] = 19
                row['after']['sample_wall_ns'] = 81
            elif mutation == 'window':
                row['whole_parent_delta']['minimum_elapsed_ns'] += 1
            else:
                row['before']['sample_calling_thread_cpu_ns'] = None
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                validate_history_kernel_cpu_observation(value)

    def test_read_failure_remains_valid_failed_observation_with_no_service_authority(self):
        value = fixture()
        kernel = value['kernel_cpu_observation']
        row = kernel['records'][0]
        row['before'].update(expected_parent_identity=None, raw_cpu_stat=None,
                             counters=None, observation_error='parent_or_cpu_stat_unavailable',
                             original_read_error_code='PUBLIC_HOST_KERNEL_COUNTERS')
        row['whole_parent_delta'] = None
        row['qualification_error'] = 'boundary_sample_unqualified'
        kernel['measurement_failures'] = 1
        kernel['all_observed_intervals_qualified'] = False
        out = validate_history_kernel_cpu_observation(value)
        self.assertFalse(out['all_observed_intervals_qualified'])
        self.assertFalse(out['has_service_or_consensus_authority'])
        kernel['measurement_failures'] = 0
        with self.assertRaises(ValueError):
            validate_history_kernel_cpu_observation(value)

    def test_native_error_and_original_observation_failure_are_not_overwritten(self):
        value = fixture()
        value['phases'][0]['accepted'] = False
        kernel = value['kernel_cpu_observation']
        kernel['records'][0]['native_accepted'] = False
        out = validate_history_kernel_cpu_observation(value)
        self.assertTrue(out['all_observed_intervals_qualified'])
        self.assertFalse(kernel['records'][0]['native_accepted'])
        value['measurement_failures'] = 1
        kernel['original_phase_measurement_failures'] = 1
        kernel['all_observed_intervals_qualified'] = False
        self.assertFalse(validate_history_kernel_cpu_observation(value)[
            'all_observed_intervals_qualified'])

    def test_live_nonatomic_snapshot_is_explicitly_unqualified(self):
        value = fixture()
        value['phases'][0].update(completed=False, accepted=None, ended_ns=None)
        kernel = value['kernel_cpu_observation']
        row = kernel['records'][0]
        row.update(whole_parent_delta=None, qualification_error='native_phase_snapshot_incomplete')
        kernel['native_phase_snapshot_coherent'] = False
        kernel['all_observed_intervals_qualified'] = False
        out = validate_history_kernel_cpu_observation(value)
        self.assertFalse(out['all_observed_intervals_qualified'])
        kernel['native_phase_snapshot_coherent'] = True
        with self.assertRaises(ValueError):
            validate_history_kernel_cpu_observation(value)

    def test_unwound_native_phase_cannot_be_presented_as_a_completed_delta(self):
        value = fixture()
        value['phases'][0].update(completed=False, accepted=None)
        kernel = value['kernel_cpu_observation']
        row = kernel['records'][0]
        row.update(native_returned=False, native_accepted=None, whole_parent_delta=None,
                   qualification_error='phase_unfinished_or_unwound')
        kernel['all_observed_intervals_qualified'] = False
        self.assertFalse(validate_history_kernel_cpu_observation(value)[
            'all_observed_intervals_qualified'])


if __name__ == '__main__':
    unittest.main()

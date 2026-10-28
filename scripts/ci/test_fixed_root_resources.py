#!/usr/bin/env python3
"""R11 parser-only resource controls; every positive object is synthetic.

No native process, Host, cgroup, /proc read, or systemd command is exercised.
The frozen legacy counterexample really passed the old readers on ca4fcb.
"""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import run_fixed_host_root_f0 as runner
import finalize_fixed_root_f0 as finalizer
import fixed_root_f0_resources as resource

FIXTURE = Path(__file__).resolve().parent / 'fixtures/fixed_root_f0_legacy_resource_counterexample.json'
FIXTURE_SHA = 'd0494d73cd52eadc414290b01543ecb4cecbca686f4a0531f080a3f5aef04c6a'


def legacy_fixture():
    raw = FIXTURE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != FIXTURE_SHA:
        raise ValueError('EXACT_RETAINED_OLD_READER_COUNTEREXAMPLE_REQUIRED')
    return json.loads(raw)


def complete_fixture():
    value = legacy_fixture()
    identity = value['controller_identity_before']
    value['controller_resource_schema'] = resource.SCHEMA
    value['controller_resources_complete'] = True
    for index, phase in enumerate(value['phases']):
        expected = 0 if index == 0 else 24
        phase.setdefault('children', [])
        manifest = phase['external_controller_observation']['actual_attack_process_contexts']
        for ordinal, actor in enumerate(manifest):
            actor['actual_cgroup'] = '0::' + identity['process']['cgroup']
            phase['fixed_root_external_actor_membership']['actors'][ordinal]['observation']['Ok']['spawn_observation'] = copy.deepcopy(actor)
        snapshots = {}
        for stage_index, stage in enumerate(resource.STAGES):
            slot = index * 3 + stage_index + 1
            members = [{'ordinal': row['ordinal'], 'pid': row['pid'],
                        'identity': {'Ok': copy.deepcopy(row['identity'])}}
                       for row in manifest] if stage == 'actors_ready' else []
            counters = {'cpu_usage_usec': slot * 1000, 'memory_current_bytes': 128,
                        'memory_peak_lifetime_bytes': slot * 1024}
            snapshots[stage] = {
                'schema': resource.SAMPLE_SCHEMA, 'stage': stage, 'scope': resource.SCOPE,
                'controller_identity': copy.deepcopy(identity),
                'controller_before': {'Ok': copy.deepcopy(identity)},
                'controller_after': {'Ok': copy.deepcopy(identity)},
                'expected_live_actors': len(members), 'actors_before': members,
                'actors_after': copy.deepcopy(members),
                'started_monotonic_ns': slot * 10**9,
                'ended_monotonic_ns': slot * 10**9 + 1000,
                'reads': {'cpu_stat': {'Ok': f'usage_usec {slot*1000}\nuser_usec 1\nsystem_usec 1\n'},
                          'memory_current': {'Ok': '128\n'},
                          'memory_peak': {'Ok': f'{slot*1024}\n'}},
                'counters': {'Ok': counters}, 'complete': True, 'validation': {'Ok': None},
            }
        phase['controller_resource_ready'] = copy.deepcopy(snapshots['actors_ready'])
        phase['external_controller_resources'] = {
            'schema': resource.SCHEMA, 'scope': resource.SCOPE, 'phase': phase['mode'],
            'controller_identity': copy.deepcopy(identity), 'expected_phase_actors': expected,
            'actor_manifest': copy.deepcopy(manifest),
            'reaped_actor_pids': [row['pid'] for row in manifest], **snapshots,
            'cpu_interval_scope': resource.CPU_SCOPE, 'memory_peak_scope': resource.PEAK_SCOPE,
            'per_actor_rss_qualified': False, 'old_public_rss_diagnostics_preserved': True,
            'cpu_usage_delta_usec': 2000, 'complete': True, 'validation': {'Ok': 2000},
        }
    return value


def set_counter(sample, field, number):
    sample['counters']['Ok'][field] = number
    raw = {'cpu_usage_usec': 'cpu_stat', 'memory_current_bytes': 'memory_current',
           'memory_peak_lifetime_bytes': 'memory_peak'}[field]
    sample['reads'][raw] = {'Ok': f'usage_usec {number}\n' if raw == 'cpu_stat' else f'{number}\n'}


class ControllerResourceControls(unittest.TestCase):
    def check(self, value):
        return resource.check_controller_resources(value, value['controller_identity_before']['process']['cgroup'])

    def test_actual_old_reader_counterexample_now_fails_both_original_reader_functions(self):
        value = legacy_fixture()
        old_rss = value['phases'][1]['budget_samples'][0]['attacker_process_rss']
        self.assertFalse(old_rss['complete'])
        self.assertIsNone(old_rss['sum_rss_bytes'])
        self.assertEqual(len(old_rss['processes']), 24)
        for check in (runner.check_report, runner.check_f0_placement_and_timing):
            with self.subTest(reader=check.__name__), self.assertRaisesRegex(
                    ValueError, 'COMPLETE_CONTROLLER_RESOURCE_COVERAGE_REQUIRED'):
                check(copy.deepcopy(value), value['controller_identity_before']['process']['cgroup'])

    def test_complete_synthetic_group_has_six_samples_while_old_unknown_rss_is_unchanged(self):
        value = complete_fixture()
        group = value['controller_identity_before']['process']['cgroup']
        summary = self.check(value)
        self.assertEqual(summary['observed_boundary_samples'], 6)
        self.assertEqual([row['expected_phase_actors'] for row in summary['phases']], [0, 24])
        self.assertFalse(summary['per_actor_rss_qualified'])
        runner.check_report(value, group)
        runner.check_f0_placement_and_timing(value, group)
        self.assertEqual(value['phases'][1]['budget_samples'], legacy_fixture()['phases'][1]['budget_samples'])

    def test_positive_total_flags_cannot_replace_missing_group_observations(self):
        value = legacy_fixture()
        value.update(controller_resource_schema=resource.SCHEMA, controller_resources_complete=True)
        for check in (runner.check_report, runner.check_f0_placement_and_timing):
            with self.subTest(reader=check.__name__), self.assertRaisesRegex(
                    ValueError, 'COMPLETE_EXPLICIT_CONTROLLER_GROUP_RESOURCE_REQUIRED'):
                check(copy.deepcopy(value), value['controller_identity_before']['process']['cgroup'])

    def test_every_missing_boundary_and_error_is_unknown_not_zero(self):
        for phase in range(2):
            for stage in resource.STAGES:
                for change in ('missing', 'error', 'false_complete'):
                    value = complete_fixture()
                    target = value['phases'][phase]['external_controller_resources']
                    if change == 'missing':
                        del target[stage]
                    elif change == 'error':
                        target[stage]['reads']['memory_peak'] = {'Err': 'kernel file unavailable'}
                    else:
                        target[stage]['complete'] = False
                    with self.subTest(phase=phase, stage=stage, change=change), self.assertRaises((ValueError, KeyError)):
                        self.check(value)

    def test_missing_cpu_stat_or_peak_never_falls_back_to_legacy_rss_or_rusage(self):
        for field in ('cpu_stat', 'memory_current', 'memory_peak'):
            value = complete_fixture()
            target = value['phases'][1]['external_controller_resources']['after_reap']
            del target['reads'][field]
            value['phases'][1]['children_os_usage_after'] = {'user_cpu_ns': 1000, 'system_cpu_ns': 1000}
            value['phases'][1]['budget_samples'][0]['attacker_process_rss'].update(
                complete=True, sum_rss_bytes=123)
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.check(value)

    def test_counter_text_is_complete_unique_bounded_and_not_boolean_or_max(self):
        sample = complete_fixture()['phases'][0]['external_controller_resources']['before_launch']['reads']
        for raw in ('', 'user_usec 1\n', 'usage_usec 1\nusage_usec 2\n', 'usage_usec -1\n',
                    'usage_usec true\n', 'usage_usec max\n', 'usage_usec 0\n', 'usage_usec 1 extra\n',
                    'usage_usec 18446744073709551616\n', 'usage_usec 1\n' + 'x' * 2048):
            changed = copy.deepcopy(sample)
            changed['cpu_stat'] = {'Ok': raw}
            with self.subTest(raw=raw[:80]), self.assertRaises(ValueError):
                resource.parse_counters(changed)
        changed = copy.deepcopy(sample)
        changed['cpu_stat']['Ok'] += 'future_kernel_counter 9\n'
        self.assertEqual(resource.parse_counters(changed)['cpu_usage_usec'], 1000)

    def test_memory_peak_is_positive_bounded_and_at_least_current(self):
        for current, peak in [('0', '1'), ('2', '1'), ('128', 'max'), ('128', ''),
                              ('128', '17179869185'), ('true', '256'), ('128', '-1')]:
            sample = complete_fixture()['phases'][0]['external_controller_resources']['before_launch']['reads']
            sample.update(memory_current={'Ok': current}, memory_peak={'Ok': peak})
            with self.subTest(current=current, peak=peak), self.assertRaises(ValueError):
                resource.parse_counters(sample)

    def test_raw_counter_and_redundant_positive_summary_cannot_disagree(self):
        for value in (None, False, True, -1, 2**64, 9999):
            report = complete_fixture()
            report['phases'][0]['external_controller_resources']['before_launch']['counters']['Ok']['cpu_usage_usec'] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.check(report)
        report = complete_fixture()
        report['phases'][0]['external_controller_resources']['cpu_usage_delta_usec'] = 0
        with self.assertRaises(ValueError):
            self.check(report)

    def test_controller_boot_inode_birth_executable_or_cgroup_drift_is_rejected(self):
        for path, change in [(('process', 'boot_id'), '00000000-0000-0000-0000-000000000002'),
                             (('process', 'start_ticks'), 2), (('process', 'pid'), 124),
                             (('process', 'cgroup'), '/system.slice/other.service'),
                             (('cgroup', 'inode'), 100), (('cgroup', 'mode'), 511)]:
            value = complete_fixture()
            actual = value['phases'][0]['external_controller_resources']['before_launch']['controller_after']['Ok']
            actual[path[0]][path[1]] = change
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.check(value)
        value = complete_fixture()
        value['phases'][0]['external_controller_resources']['after_reap']['controller_after']['Ok']['process']['executable']['inode'] += 1
        with self.assertRaises(ValueError):
            self.check(value)

    def test_all_24_births_are_reobserved_before_and_after_real_counter_reads(self):
        for field, change in [('pid', 1001), ('parent_pid', 124), ('start_ticks', 1),
                              ('boot_id', '00000000-0000-0000-0000-000000000002'),
                              ('cgroup', '/system.slice/other.service')]:
            value = complete_fixture()
            value['phases'][1]['external_controller_resources']['actors_ready']['actors_after'][0]['identity']['Ok'][field] = change
            # Keep the public-phase copy consistent; the actual birth comparison must reject it.
            value['phases'][1]['controller_resource_ready'] = copy.deepcopy(
                value['phases'][1]['external_controller_resources']['actors_ready'])
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.check(value)

    def test_partial_duplicate_boolean_or_unreaped_actor_set_is_never_24(self):
        for change in ('partial', 'duplicate', 'boolean', 'missing_reap', 'wrong_reap'):
            value = complete_fixture()
            group = value['phases'][1]['external_controller_resources']
            if change == 'partial':
                group['actors_ready']['actors_before'].pop()
            elif change == 'duplicate':
                group['actors_ready']['actors_before'][1] = copy.deepcopy(group['actors_ready']['actors_before'][0])
            elif change == 'boolean':
                group['actors_ready']['actors_before'][0]['ordinal'] = False
            elif change == 'missing_reap':
                group['reaped_actor_pids'].pop()
            else:
                group['reaped_actor_pids'][0] = 123
            value['phases'][1]['controller_resource_ready'] = copy.deepcopy(group['actors_ready'])
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.check(value)

    def test_counter_and_peak_rewind_across_phases_or_within_phase_are_rejected(self):
        for phase, stage, field, number in [(0, 'after_reap', 'cpu_usage_usec', 500),
                (0, 'after_reap', 'memory_peak_lifetime_bytes', 128),
                (1, 'before_launch', 'cpu_usage_usec', 500),
                (1, 'before_launch', 'memory_peak_lifetime_bytes', 128)]:
            value = complete_fixture()
            set_counter(value['phases'][phase]['external_controller_resources'][stage], field, number)
            with self.subTest(phase=phase, stage=stage, field=field), self.assertRaises(ValueError):
                self.check(value)

    def test_current_memory_can_fall_but_lifetime_peak_is_never_subtracted(self):
        value = complete_fixture()
        set_counter(value['phases'][0]['external_controller_resources']['after_reap'], 'memory_current_bytes', 1)
        summary = self.check(value)
        self.assertEqual(summary['phases'][0]['observations'][-1]['memory_current_bytes'], 1)
        self.assertEqual(summary['phases'][0]['observations'][-1]['memory_peak_lifetime_bytes'], 3072)

    def test_clock_scope_cannot_skip_prior_phase_or_claim_a_per_actor_peak(self):
        value = complete_fixture()
        value['phases'][1]['external_controller_resources']['before_launch']['started_monotonic_ns'] = 1
        with self.assertRaises(ValueError):
            self.check(value)
        for field, replacement in [('scope', 'per-actor RSS'), ('per_actor_rss_qualified', True),
                                    ('memory_peak_scope', 'memory.peak after minus before')]:
            value = complete_fixture()
            value['phases'][0]['external_controller_resources'][field] = replacement
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.check(value)

    def finalizer_fixture(self, root, value, *, resource_claim=True):
        raw = root / 'execution/raw'
        raw.mkdir(parents=True)
        prepared = root / 'prepared'
        prepared.mkdir()
        (raw / 'report.json').write_text(json.dumps(value))
        (prepared / 'prepared.json').write_text('{}')
        try:
            summary = self.check(value)
        except (ValueError, KeyError, TypeError):
            summary = {'complete': True, 'forged': True}
        result = {'schema': 'pon-fixed-host-root-f0-execution-v1', 'failure': None,
            'head': 'a'*40, 'tree': 'b'*40, 'inputs': runner.INPUTS,
            'prepared_sha256': runner.sha(prepared/'prepared.json'),
            'report_sha256': runner.sha(raw/'report.json'),
            'all_planned_rounds': runner.f0_rounds(value),
            'all_planned_business_packets': runner.f0_packets(value),
            'complete_success': True, 'native_execution_observed': True,
            'report_validation_failure': None, 'native_result_failure': None,
            'step': {'complete_success': True},
            'post_observations': {key: {'complete_success': True} for key in ('binary','source','resources')},
            'controller_resources_complete': resource_claim, 'controller_resource_summary': summary}
        (root/'execution/results.json').write_text(json.dumps(result))
        (root/'execution/controller-live.json').write_text(json.dumps(
            {'cgroup': value['controller_identity_before']['process']['cgroup']}))

    def test_finalizer_independently_refuses_legacy_or_false_resource_complete_claim(self):
        for report, claim in ((legacy_fixture(), True), (complete_fixture(), False)):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.finalizer_fixture(root, report, resource_claim=claim)
                result = finalizer.final_report(root, 'a'*40, 'b'*40)
            self.assertFalse(result['native_complete_success'])
            self.assertIsNotNone(result['native_result_failure'])
            self.assertEqual(len(result['all_planned_rounds']), 6)
            self.assertEqual(len(result['all_planned_business_packets']), 42)

    def test_finalizer_recomputes_complete_synthetic_resource_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.finalizer_fixture(root, complete_fixture())
            result = finalizer.final_report(root, 'a'*40, 'b'*40)
        self.assertTrue(result['native_complete_success'])
        self.assertTrue(result['controller_resources_complete'])
        self.assertEqual(result['controller_resource_summary']['observed_boundary_samples'], 6)
        self.assertIsNone(result['controller_resource_failure'])

    def test_original_five_native_selectors_remain_before_two_new_resource_controls(self):
        self.assertEqual(runner.SOURCE_CONTROLS[:5], (
            'phase_host::separate_broker_scope_clears_on_unwind_and_refuses_missing_actors',
            'root_phase_host::fixed_root_denominators_retain_all_missing_failed_and_duplicate_rounds',
            'root_phase_host::fixed_root_proc_identity_requires_exact_pid_and_start_despite_command_parentheses',
            'root_phase_host::fixed_root_four_second_slo_cannot_remove_queue_or_prior_round_delay',
            'root_phase_host::fixed_root_job_requires_its_exact_profile_and_complete_workload'))
        self.assertEqual(len(set(runner.SOURCE_CONTROLS)), 7)


if __name__ == '__main__':
    unittest.main()

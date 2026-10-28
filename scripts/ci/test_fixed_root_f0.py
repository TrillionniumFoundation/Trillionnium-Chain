#!/usr/bin/env python3
"""Adversarial F0 reader/cleanup controls; all service observations are fixtures.

No systemd command, native proof, Host provisioning or network call is executed
by this module. Real resource, cleanup-cut and service claims require the pilot.
"""
import copy
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import run_fixed_host_root_f0 as runner
import finalize_fixed_root_f0 as finalizer
import fixed_root_f0_ownership as owner
import run_fixed_root_phase_host as phase_launcher


class F0DenominatorControls(unittest.TestCase):
    @staticmethod
    def report():
        return {'phases': [{'mode': phase, 'confirmations': [
            {'round': number, 'started_ns': (1+4*number)*10**9,
             'ended_ns': (2+4*number)*10**9, 'confirmed_inside_pressure_window': True}
            for number in range(3)], 'submissions': [
            {'packet_index': number, 'status': 'ok', 'returned_after_window': False}
            for number in range(21)]} for phase in ('baseline', 'valid-work-root')]}

    def test_missing_setup_report_retains_all_six_and_42_non_successes(self):
        for value in (None, {}, {'phases': []}, {'phases': None}, {'phases': [None, None]}):
            with self.subTest(value=value):
                rounds, packets = runner.f0_rounds(value), runner.f0_packets(value)
                self.assertEqual((len(rounds), len(packets)), (6, 42))
                self.assertEqual(sum(row['four_second_slo_met'] for row in rounds), 0)
                self.assertEqual(sum(row['timely_network_ack'] for row in packets), 0)

    def test_valid_fixture_is_six_of_six_but_no_host_or_work_qualification(self):
        value = self.report()
        self.assertTrue(all(row['four_second_slo_met'] for row in runner.f0_rounds(value)))
        with self.assertRaises((KeyError, ValueError)):
            runner.check_report(value, '/fixture/controller.service')

    def test_queue_wait_is_never_removed_by_using_actual_start(self):
        value = self.report()
        value['phases'][0]['confirmations'][0].update(started_ns=4_000_000_000, ended_ns=5_000_000_001)
        row = runner.f0_rounds(value)[0]
        self.assertFalse(row['four_second_slo_met'])
        self.assertEqual(row['elapsed_from_scheduled_ns'], 4_000_000_001)
        self.assertEqual(row['start_lateness_from_schedule_ns'], 3_000_000_000)
        self.assertEqual(row['end_lateness_from_four_second_deadline_ns'], 1)

    def test_four_seconds_exact_and_old_whole_window_success_are_not_new_slo(self):
        for ended in (5_000_000_000, 29_000_000_000, 31_000_000_000):
            value = self.report()
            value['phases'][0]['confirmations'][0]['ended_ns'] = ended
            row = runner.f0_rounds(value)[0]
            self.assertTrue(row['confirmed_inside_original_window'])
            self.assertFalse(row['four_second_slo_met'])

    def test_duplicate_round_and_boolean_index_do_not_invent_success(self):
        value = self.report()
        value['phases'][0]['confirmations'].append(copy.deepcopy(value['phases'][0]['confirmations'][0]))
        value['phases'][1]['confirmations'][1]['round'] = True
        rows = runner.f0_rounds(value)
        self.assertEqual(len(rows), 6)
        self.assertFalse(rows[0]['observed_exactly_once'])
        self.assertFalse(rows[4]['observed_exactly_once'])
        self.assertEqual(sum(row['four_second_slo_met'] for row in rows), 4)

    def test_wrong_phase_order_and_negative_or_reversed_clocks_cannot_pass(self):
        value = self.report()
        value['phases'].reverse()
        self.assertFalse(any(row['four_second_slo_met'] for row in runner.f0_rounds(value)))
        for start, end in ((-1, 2_000_000_000), (True, 2_000_000_000),
                           (3_000_000_000, 2_000_000_000), (0, 2_000_000_000)):
            value = self.report()
            value['phases'][0]['confirmations'][0].update(started_ns=start, ended_ns=end)
            self.assertFalse(runner.f0_rounds(value)[0]['four_second_slo_met'])

    def test_all_ack_attempts_stay_distinct_from_confirmations_and_late_acks(self):
        value = self.report()
        value['phases'][0]['confirmations'] = []
        value['phases'][0]['submissions'].append({'packet_index': 0, 'status': 'error', 'returned_after_window': False})
        value['phases'][1]['submissions'][20]['returned_after_window'] = True
        rows = runner.f0_packets(value)
        self.assertEqual(len(rows), 42)
        self.assertEqual(rows[0]['observed_attempts'], 2)
        self.assertEqual(sum(row['timely_network_ack'] for row in rows), 41)
        self.assertTrue(all(row['ack_is_not_confirmation'] for row in rows))
        self.assertEqual(sum(row['four_second_slo_met'] for row in runner.f0_rounds(value)), 3)

    def test_absent_final_native_result_is_unknown_not_passing_zero_experiment(self):
        with tempfile.TemporaryDirectory() as path:
            value = finalizer.final_report(Path(path))
        self.assertFalse(value['native_complete_success'])
        self.assertFalse(value['native_result_observed'])
        self.assertFalse(value['report_observed'])
        self.assertEqual((value['planned_confirmations'], value['planned_business_packet_exposures']), (6, 42))
        self.assertIsNotNone(value['report_failure'])


class F0ActorMembershipControls(unittest.TestCase):
    @staticmethod
    def cohort():
        identity = {'process': {'pid': 123, 'cgroup': '/system.slice/f0.service',
                    'boot_id': 'fixture-boot', 'executable': {'inode': 17}}}
        actors, spawned = [], []
        for number in range(24):
            process = {'pid': 1000 + number, 'parent_pid': 123,
                       'start_ticks': 2000 + number, **{
                           key: identity['process'][key]
                           for key in ('cgroup', 'boot_id', 'executable')}}
            observation = {'ordinal': number, 'pid': process['pid'],
                           'identity': process}
            spawned.append(observation)
            actors.append({'ordinal': number, 'pid': process['pid'], 'verified': True,
                           'observation': {'Ok': {'identity': process,
                               'spawn_observation': observation,
                               'ready': {'pid': process['pid'], 'mode': 'valid-work-root',
                                         'cgroup': process['cgroup']}}}})
        membership = {'verified': True, 'controller_check': {'Ok': None},
                      'controller_identity': identity, 'expected_actors': 24,
                      'observed_actors': 24, 'distinct_pids': 24, 'actors': actors}
        controller = {'launched': 24, 'reaped': 24, 'actual_attack_process_contexts': spawned}
        return membership, controller, identity

    def test_counts_cannot_substitute_for_distinct_actual_pids(self):
        membership, controller, identity = self.cohort()
        runner.check_f0_actor_membership(membership, controller, identity, 24)
        # Change every redundant copy coherently; reported distinct_pids stays 24.
        actor = membership['actors'][23]
        actor['pid'] = 1000
        actor['observation']['Ok']['identity']['pid'] = 1000
        actor['observation']['Ok']['ready']['pid'] = 1000
        controller['actual_attack_process_contexts'][23]['pid'] = 1000
        with self.assertRaisesRegex(ValueError, 'ACTOR_IDENTITY_BINDING'):
            runner.check_f0_actor_membership(membership, controller, identity, 24)

    def test_boolean_pid_or_ordinal_and_unknown_process_start_are_rejected(self):
        for field, value in (('pid', True), ('start_ticks', 0), ('start_ticks', True)):
            membership, controller, identity = self.cohort()
            actor = membership['actors'][0]
            actor['observation']['Ok']['identity'][field] = value
            if field == 'pid':
                actor['pid'] = value
                actor['observation']['Ok']['ready']['pid'] = value
                controller['actual_attack_process_contexts'][0]['pid'] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                runner.check_f0_actor_membership(membership, controller, identity, 24)
        membership, controller, identity = self.cohort()
        membership['actors'][0]['ordinal'] = False
        with self.assertRaises(ValueError):
            runner.check_f0_actor_membership(membership, controller, identity, 24)

    def test_partial_cohort_or_changed_parent_cannot_inherit_controller_authority(self):
        membership, controller, identity = self.cohort()
        membership['actors'].pop()
        with self.assertRaises(ValueError):
            runner.check_f0_actor_membership(membership, controller, identity, 24)
        membership, controller, identity = self.cohort()
        membership['actors'][7]['observation']['Ok']['identity']['parent_pid'] = 456
        with self.assertRaises(ValueError):
            runner.check_f0_actor_membership(membership, controller, identity, 24)


class F0OwnershipControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='fixed-root-f0-source-controls-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.identity = {'run_id': '12', 'run_attempt': '3', 'job_id': 'fixed-host-root-f0'}
        self.service = 'trnm-fixed-root-12-3-fixed-host-root-f0-valid-work-root-1234.service'
        self.boot = '00000000-0000-0000-0000-000000000001'
        self.owned = {'phase': 'valid-work-root', 'service': self.service,
                      'uid': 1001, 'gid': 1001, 'source_root': '/source',
                      'job_sha256': 'a'*64, 'binary_sha256': 'b'*64,
                      'expected_cgroup': '/trnmponpublic.slice/'+self.service,
                      'description': 'Trillionnium F0 ROOT job '+'a'*64}
        self.live = {'phase': 'valid-work-root', 'service': self.service,
                     'uid': 1001, 'gid': 1001, 'job_sha256': 'a'*64, 'binary_sha256': 'b'*64,
                     'pid': 5678, 'parent_pid': 1, 'process_start_ticks': 8765,
                     'invocation_id': 'c'*32, 'boot_id': self.boot,
                     'cgroup': self.owned['expected_cgroup'],
                     'cgroup_identity': {'device': 28, 'inode': 29, 'uid': 0, 'gid': 0, 'mode': 0o755}}
        self.manager = dict.fromkeys(owner.MANAGER_PROPERTIES, '')
        self.manager.update(Id=self.service, LoadState='loaded', ActiveState='active', SubState='running',
                            ControlGroup=self.live['cgroup'], MainPID='5678', User='1001', Group='1001',
                            Slice='trnmponpublic.slice', Transient='yes', KillMode='control-group',
                            Restart='no', WorkingDirectory='/source', InvocationID='c'*32,
                            Description=self.owned['description'])
        self.absent = dict.fromkeys(owner.MANAGER_PROPERTIES, '')
        self.absent.update(Id=self.service, LoadState='not-found', ActiveState='inactive', SubState='dead', MainPID='0')
        self.populated = {'exists': True, 'empty': False}
        self.empty = {'exists': False, 'empty': True}

    def test_phase_names_never_select_other_run_attempt_job_or_parent(self):
        self.assertTrue(owner.phase_unit_matches(self.service, self.identity, 'valid-work-root'))
        for candidate in (self.service.replace('-12-', '-13-'), self.service.replace('-3-', '-4-'),
                          self.service.replace('valid-work-root', 'baseline'), self.service+'extra',
                          '*', 'trnmponpublic.slice', '../'+self.service):
            self.assertFalse(owner.phase_unit_matches(candidate, self.identity, 'valid-work-root'))
        with self.assertRaises(ValueError):
            owner.phase_unit_matches(self.service, self.identity, 'f1')

    def test_missing_or_unbounded_environment_has_no_default_identity(self):
        for environment in ({}, {'GITHUB_RUN_ID':'12','GITHUB_RUN_ATTEMPT':'3','GITHUB_JOB':'*'},
                            {'GITHUB_RUN_ID':'1'*31,'GITHUB_RUN_ATTEMPT':'3','GITHUB_JOB':'fixed'}):
            with patch.dict(os.environ, environment, clear=True), self.assertRaises(ValueError):
                owner.identity_environment()

    def test_receipt_duplicates_symlinks_fifo_and_excess_size_are_rejected(self):
        file = self.root/'receipt.json'
        file.write_text('{"a":1,"a":2}')
        with self.assertRaisesRegex(ValueError, 'DUPLICATE'):
            owner.receipt(file)
        file.write_text('{"a":1}')
        link = self.root/'linked.json'
        link.symlink_to(file)
        with self.assertRaises((ValueError, OSError)):
            owner.receipt(link)
        pipe = self.root/'fifo'
        os.mkfifo(pipe)
        with self.assertRaisesRegex(ValueError, 'BOUNDED_REGULAR'):
            owner.regular_bytes(pipe, 16)
        with self.assertRaisesRegex(ValueError, 'BOUNDED_REGULAR'):
            owner.regular_bytes(file, 3)

    def test_same_unit_name_with_new_invocation_or_working_directory_is_not_owned(self):
        owner.manager_matches(self.manager, self.owned, self.live)
        for key, value in (('InvocationID','d'*32), ('WorkingDirectory','/other'),
                           ('User','0'), ('Group','0'), ('Slice','system.slice'),
                           ('ControlGroup','/other'), ('MainPID','5679'),
                           ('Description','another job'), ('KillMode','process'), ('Restart','always')):
            changed = dict(self.manager, **{key:value})
            with self.subTest(key=key), self.assertRaises(ValueError):
                owner.manager_matches(changed, self.owned, self.live)

    def test_live_receipt_requires_current_boot_and_non_boolean_inode_identity(self):
        with patch.object(owner, 'kernel_text', return_value=self.boot):
            owner.validate_live(self.owned, self.live)
            for field, value in (('boot_id','different'), ('job_sha256','d'*64), ('binary_sha256','d'*64),
                                  ('pid',True), ('process_start_ticks',True), ('cgroup','/different')):
                with self.subTest(field=field), self.assertRaises(ValueError):
                    owner.validate_live(self.owned, dict(self.live, **{field:value}))
            changed = copy.deepcopy(self.live)
            changed['cgroup_identity']['inode'] = True
            with self.assertRaises(ValueError):
                owner.validate_live(self.owned, changed)

    def test_manager_property_duplicates_partial_output_and_extra_fields_fail(self):
        raw = '\n'.join(key+'='+self.manager[key] for key in owner.MANAGER_PROPERTIES)
        self.assertEqual(owner.parse_manager(raw), self.manager)
        for value in (raw+'\nId='+self.service, raw+'\nUnexpected=1', raw.split('\n',1)[1], 'bad'):
            with self.assertRaises(ValueError):
                owner.parse_manager(value)

    def test_cgroup_descendant_population_is_not_erased_by_empty_direct_procs(self):
        with (patch.object(owner, 'group_identity', return_value=self.live['cgroup_identity']),
              patch.object(owner, 'kernel_text', side_effect=['populated 1\nfrozen 0', ''])):
            self.assertFalse(owner.observe_group(self.live)['empty'])
        with (patch.object(owner, 'group_identity', return_value=self.live['cgroup_identity']),
              patch.object(owner, 'kernel_text', side_effect=['populated 0\nfrozen 0', ''])):
            self.assertTrue(owner.observe_group(self.live)['empty'])
        with patch.object(owner, 'group_identity', return_value=dict(self.live['cgroup_identity'], inode=30)):
            with self.assertRaisesRegex(ValueError, 'IDENTITY_CHANGED'):
                owner.observe_group(self.live)

    def cleanup(self, manager=None, after=None, before_group=None, after_group=None, stop_ok=True):
        manager = self.manager if manager is None else manager
        after = self.absent if after is None else after
        before_group = self.populated if before_group is None else before_group
        after_group = self.empty if after_group is None else after_group
        with (patch.object(finalizer, 'show_service', side_effect=[manager, after]) as show,
              patch.object(finalizer, 'observe_group', side_effect=[before_group, after_group]),
              patch.object(finalizer, 'current_process_matches') as current,
              patch.object(finalizer, 'run_step', return_value={'complete_success':stop_ok}) as command):
            result = finalizer.cleanup_one(self.root, self.owned, self.live)
        return result, show, current, command

    def test_only_exact_verified_service_is_stopped_and_actual_empty_readback_is_required(self):
        result, show, current, command = self.cleanup()
        self.assertTrue(result['known_empty'])
        self.assertEqual(result['remaining'], 'observed-empty')
        self.assertEqual(show.call_count, 2)
        current.assert_called_once()
        self.assertEqual(command.call_args.args[2], ['sudo','-n','systemctl','stop',self.service])

    def test_stop_success_with_remaining_descendants_stays_unknown(self):
        result, _show, _current, command = self.cleanup(after_group=self.populated)
        self.assertTrue(result['stop_step']['complete_success'])
        self.assertFalse(result['known_empty'])
        self.assertEqual(result['remaining'], 'unknown')
        command.assert_called_once()

    def test_changed_manager_or_cgroup_identity_cannot_authorize_a_stop(self):
        for manager in (dict(self.manager, InvocationID='d'*32), dict(self.manager, User='0'),
                        dict(self.manager, Description='other owner')):
            result, _show, _current, command = self.cleanup(manager=manager)
            self.assertFalse(result['known_empty'])
            command.assert_not_called()
        with (patch.object(finalizer, 'show_service', return_value=self.manager),
              patch.object(finalizer, 'observe_group', side_effect=ValueError('changed inode')),
              patch.object(finalizer, 'run_step') as command):
            result = finalizer.cleanup_one(self.root, self.owned, self.live)
        self.assertFalse(result['known_empty'])
        command.assert_not_called()

    def test_current_pid_reuse_is_not_a_live_owner(self):
        fields = ['0']*20
        fields[0], fields[1], fields[19] = 'S', '1', '8766'
        with patch.object(finalizer, 'kernel_text', return_value='5678 (same name) '+' '.join(fields)):
            with self.assertRaisesRegex(ValueError, 'PROCESS_CHANGED'):
                finalizer.current_process_matches(self.manager, self.live)

    def test_already_collected_unit_needs_actual_empty_group_but_no_stop(self):
        result, show, _current, command = self.cleanup(manager=self.absent, before_group=self.empty)
        self.assertTrue(result['known_empty'])
        self.assertEqual(show.call_count, 2)
        command.assert_not_called()
        result, _show, _current, command = self.cleanup(manager=self.absent, before_group=self.populated)
        self.assertFalse(result['known_empty'])
        command.assert_not_called()

    def test_stop_failure_remains_a_failure_even_if_later_observed_empty(self):
        result, _show, _current, _command = self.cleanup(stop_ok=False)
        self.assertTrue(result['known_empty'])
        self.assertEqual(result['failure'], 'EXACT_OWNED_STOP_FAILED_OR_TIMED_OUT')

    def test_immediate_launcher_cleanup_cannot_follow_replaced_owned_receipt(self):
        changed = dict(self.owned, service=self.service + '.other')
        (self.root/'owned-service.json').write_text(json.dumps(changed))
        with patch.object(finalizer, 'cleanup_one') as cleanup:
            with self.assertRaisesRegex(ValueError, 'ORIGINAL_PHASE_OWNERSHIP_RECEIPT_CHANGED'):
                phase_launcher.cleanup_recorded_phase(self.root, self.owned)
        cleanup.assert_not_called()

    def test_immediate_launcher_cleanup_has_no_name_only_missing_live_fallback(self):
        (self.root/'owned-service.json').write_text(json.dumps(self.owned))
        with patch.object(finalizer, 'cleanup_one') as cleanup:
            with self.assertRaises(FileNotFoundError):
                phase_launcher.cleanup_recorded_phase(self.root, self.owned)
        cleanup.assert_not_called()

    def test_immediate_launcher_cleanup_reuses_full_checks_and_keeps_unknown(self):
        (self.root/'owned-service.json').write_text(json.dumps(self.owned))
        live = dict(self.live, schema='fixed-root-owned-service-live-v1')
        (self.root/'owned-service-live.json').write_text(json.dumps(live))
        unknown = {'known_empty': False, 'remaining': 'unknown',
                   'failure': 'ACTUAL_SERVICE_OR_DESCENDANTS_REMAIN', 'cleanup_attempted': True}
        with (patch.object(owner, 'kernel_text', return_value=self.boot),
              patch.object(finalizer, 'cleanup_one', return_value=unknown) as cleanup):
            result = phase_launcher.cleanup_recorded_phase(self.root, self.owned)
        cleanup.assert_called_once_with(self.root/'verified-cleanup', self.owned, live)
        self.assertEqual(result, unknown)
        self.assertEqual(json.loads((self.root/'verified-cleanup/result.json').read_text()), unknown)

    def test_immediate_launcher_cleanup_rejects_wrong_boot_and_boolean_pid(self):
        (self.root/'owned-service.json').write_text(json.dumps(self.owned))
        for change in ({'boot_id': 'another-boot'}, {'pid': True}):
            live = dict(self.live, schema='fixed-root-owned-service-live-v1', **change)
            (self.root/'owned-service-live.json').write_text(json.dumps(live))
            with (patch.object(owner, 'kernel_text', return_value=self.boot),
                  patch.object(finalizer, 'cleanup_one') as cleanup):
                with self.assertRaises(ValueError):
                    phase_launcher.cleanup_recorded_phase(self.root, self.owned)
            cleanup.assert_not_called()

    def test_no_receipts_never_imply_no_service_or_remove_failure_denominators(self):
        args = SimpleNamespace(expected_head='a'*40, expected_tree='b'*40)
        with (patch.object(finalizer, 'hosted_context', return_value=self.identity),
              patch.object(finalizer, 'owner_inputs', side_effect=FileNotFoundError('missing live receipt')),
              patch.object(finalizer, 'show_service') as show,
              patch.object(finalizer, 'run_step') as command):
            self.assertFalse(finalizer.finalize(args, self.root))
        value = json.loads((self.root/'finalization/result.json').read_text())
        self.assertEqual(len(value['services']), 3)
        self.assertTrue(all(row['remaining'] == 'unknown' for row in value['services']))
        self.assertFalse(value['all_services_known_empty'])
        self.assertEqual(len(value['denominator']['all_planned_rounds']), 6)
        self.assertEqual(len(value['denominator']['all_planned_business_packets']), 42)
        show.assert_not_called()
        command.assert_not_called()

    def test_no_hosted_context_cannot_start_even_manager_observation(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(finalizer, 'show_service') as show:
            with self.assertRaisesRegex(ValueError, 'HOSTED_UNPRIVILEGED'):
                finalizer.hosted_context()
            show.assert_not_called()

    def test_nonterminal_controller_prevents_final_phase_empty_claim(self):
        args = SimpleNamespace(expected_head='a'*40, expected_tree='b'*40)
        observed_order = []

        def inputs(_args, _out, phase):
            observed_order.append(phase)
            return {'phase': phase}, {'phase': phase}

        def cleanup(_directory, owned, _live):
            terminal = owned['phase'] != 'controller'
            return {'phase': owned['phase'], 'known_empty': terminal,
                    'remaining': 'observed-empty' if terminal else 'unknown',
                    'failure': None, 'cleanup_attempted': True}

        with (patch.object(finalizer, 'hosted_context', return_value=self.identity),
              patch.object(finalizer, 'owner_inputs', side_effect=inputs),
              patch.object(finalizer, 'cleanup_one', side_effect=cleanup) as stop):
            self.assertFalse(finalizer.finalize(args, self.root))
        result = json.loads((self.root/'finalization/result.json').read_text())
        self.assertEqual(observed_order, ['controller', 'baseline', 'valid-work-root'])
        self.assertEqual(stop.call_count, 3)
        self.assertFalse(result['all_services_known_empty'])
        for row in result['services'][1:]:
            self.assertTrue(row['observed_empty_at_readback'])
            self.assertFalse(row['controller_terminal_before_phase_observation'])
            self.assertFalse(row['known_empty'])
            self.assertEqual(row['remaining'], 'unknown-controller-not-terminal')
        self.assertEqual(len(result['denominator']['all_planned_rounds']), 6)
        self.assertEqual(len(result['denominator']['all_planned_business_packets']), 42)


if __name__ == '__main__':
    unittest.main()

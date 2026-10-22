#!/usr/bin/env python3
"""Supplement runner guards; no native execution or resource experiment."""
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import run_pon_root_supplement as runner


class RootSupplementTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name)

    def prepared(self):
        binary = self.path / 'public_v3_multiprocess.bin'
        binary.write_bytes(b'good')
        binary.chmod(0o500)
        value = dict(schema='pon-root-supplement-prepared-v1', prepared=True,
                     pressure_selector_executed=False, head='a' * 40, tree='b' * 40,
                     inputs=copy.deepcopy(runner.INPUTS), runner_sha256=runner.sha(runner.__file__),
                     binary=dict(path=str(binary), bytes=4, sha256=runner.sha(binary)))
        return value, binary, self.path / 'prepared.json'

    def read_prepared(self, value, path):
        path.write_text(json.dumps(value))
        return runner.prepared_input(path, runner.sha(path), 'a' * 40, 'b' * 40)

    def test_binary_requires_one_release_artifact_inside_target(self):
        target = self.path / 'target'
        target.mkdir()
        binary = target / 'test-bin'
        binary.write_bytes(b'not executed')
        profile = dict(debug_assertions=False, debuginfo=0, opt_level='3', overflow_checks=False, test=True)
        row = dict(reason='compiler-artifact', target={'name': 'public_v3_multiprocess'},
                   profile=profile, executable=str(binary))
        build = self.path / 'build.jsonl'
        build.write_text(json.dumps(row) + '\n')
        self.assertEqual(runner.binary_from_build(build, target), (binary, profile))
        for rows in ([dict(row, profile=dict(profile, debug_assertions=True))], [row, row],
                     [dict(row, executable=str(build))]):
            build.write_text('\n'.join(map(json.dumps, rows)))
            with self.assertRaises(ValueError):
                runner.binary_from_build(build, target)

    def test_preparation_manifest_is_exact_and_checksum_pinned(self):
        value, binary, manifest = self.prepared()
        self.assertEqual(self.read_prepared(value, manifest), (value, binary))
        for key, changed in (('inputs', dict(runner.INPUTS, actor_call_cap=481)),
                             ('runner_sha256', '0' * 64), ('head', 'c' * 40),
                             ('pressure_selector_executed', True), ('prepared', False)):
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'FROZEN_PREPARATION'):
                self.read_prepared(dict(value, **{key: changed}), manifest)
        self.read_prepared(value, manifest)
        digest = runner.sha(manifest)
        manifest.write_text(manifest.read_text() + ' ')
        with self.assertRaisesRegex(ValueError, 'PREPARED_MANIFEST_SHA'):
            runner.prepared_input(manifest, digest, 'a' * 40, 'b' * 40)

    def test_frozen_binary_rejects_writable_tampered_and_symlink_inputs(self):
        value, binary, manifest = self.prepared()
        binary.chmod(0o700)
        with self.assertRaisesRegex(ValueError, 'FROZEN_BINARY_SHA'):
            self.read_prepared(value, manifest)
        binary.write_bytes(b'evil')
        binary.chmod(0o500)
        with self.assertRaisesRegex(ValueError, 'FROZEN_BINARY_SHA'):
            self.read_prepared(value, manifest)
        retained = self.path / 'moved.bin'
        binary.rename(retained)
        binary.symlink_to(retained)
        with self.assertRaisesRegex(ValueError, 'FROZEN_BINARY_SHA'):
            self.read_prepared(value, manifest)

    def test_report_unknown_missing_and_wrong_modes_never_qualify(self):
        value = dict(schema='native-public-v3-root-supplement-v1', **{k: False for k in runner.QUALIFICATIONS})
        value.update({k: runner.INPUTS[k] for k in ('seed_transfers', 'seed_blocks', 'business_blocks',
                      'phase_seconds', 'actor_call_cap', 'planned_complete_runs', 'm06_workers')})
        root = dict.fromkeys(('criteria_met aggregate_membership_verified whole_domain_paid_reconciled '
                             'hostile_packets_absent_live hostile_packets_absent_cold cold_state_equal '
                             'expected_legal_counts_and_tip').split(), True)
        root.update(controller_cgroup='/service', aggregate_scoped_cpu_ns=0)
        value['phases'] = [dict(mode='baseline', finite_phase_criteria_met=True),
                           dict(mode='valid-work-root', root_supplement=root)]
        for key in root:
            value['phases'][1]['root_supplement'] = dict(root, **{key: None})
            with self.subTest(unknown=key), self.assertRaisesRegex(ValueError, 'ROOT_COHORT_CLOSED_EVIDENCE'):
                runner.check_report(value, '/service')
            value['phases'][1]['root_supplement'] = {k: v for k, v in root.items() if k != key}
            with self.subTest(missing=key), self.assertRaisesRegex(KeyError, key):
                runner.check_report(value, '/service')
        for index, mode in ((0, 'valid-work-root'), (1, 'late-product')):
            bad = copy.deepcopy(value)
            bad['phases'][index]['mode'] = mode
            with self.assertRaisesRegex(ValueError, 'BASELINE_MUST_PASS'):
                runner.check_report(bad, '/service')

    def test_service_identity_requires_current_owner_and_finite_group_cleanup(self):
        unit = 'trnm-pn1-root-unittest.service'
        cgroup = '/user.slice/' + unit
        values = dict(ControlGroup=cgroup, MainPID=str(os.getpid()), KillMode='control-group', RuntimeMaxUSec='10min')
        def observe(output, label, command, env, timeout):
            self.assertEqual(command[:4], ['systemctl', '--user', 'show', unit])
            (output / 'identity.stdout').write_text('\n'.join(f'{k}={v}' for k, v in values.items()))
            return dict(complete_success=True, stdout='identity.stdout')
        with patch.object(runner, 'run_step', side_effect=observe):
            runner.service_identity(self.path, unit, {'cgroup': cgroup}, {})
            for key, bad in (('MainPID', '0'), ('ControlGroup', '/parent.service'),
                             ('KillMode', 'process'), ('RuntimeMaxUSec', 'infinity')):
                saved, values[key] = values[key], bad
                with self.assertRaisesRegex(ValueError, 'SERVICE_OWNERSHIP_AND_CLEANUP'):
                    runner.service_identity(self.path, unit, {'cgroup': cgroup}, {})
                values[key] = saved
        with patch.object(runner, 'run_step') as observed:
            for name, group in (('parent.service', cgroup), (unit, '/parent.service')):
                with self.assertRaises(ValueError):
                    runner.service_identity(self.path, name, {'cgroup': group}, {})
            observed.assert_not_called()

    def test_depletion_uses_original_numeric_thresholds_and_whole_sample(self):
        flow = dict(schema='public-v3-local-actual-cpu-flow-v1', balance_identity_verified=True,
                    initial_credit_ns=2_000_000_000, credited_refill_ns=0, paid_cpu_debit_ns=1_950_000_001,
                    live_debited_cpu_ns=1_950_000_001, settlement_residual_cpu_ns=0,
                    remaining_paid_credit_ns=49_999_999, settlement_discard_ns=0,
                    stored_credit_ns=49_999_999, booked_reservation_ns=0, live_owners=0,
                    unsettled_known_live_cpu_ns=0, settled_full_cpu_ns=1_950_000_001)
        meter = dict(schema='public-v3-local-stored-cpu-budget-v1', burst_ns=2_000_000_000,
                     start_reserve_ns=100_000_000, refill_ns_per_second=250_000_000,
                     worker_limit=2, accounting_unavailable=False)
        snapshot = dict(meter=meter, actual_flow=flow, depleted=True, clock_failures=0, sample_at_ns=3)
        sample = dict(observation_started_ns=2, observation_ended_ns=4, meter={'Ok': snapshot})
        phase = dict(budget_samples=[sample], genuine_budget_depletion_observed=True, depletion_meter=snapshot)
        self.assertEqual(runner.checked_depletion_samples(phase), [(2, 4, snapshot)])
        for changed in (
            dict(remaining_paid_credit_ns=100_000_000, stored_credit_ns=100_000_000, credited_refill_ns=50_000_001),
            dict(paid_cpu_debit_ns=1_900_000_000, live_debited_cpu_ns=1_900_000_000,
                 settled_full_cpu_ns=1_900_000_000, settlement_discard_ns=50_000_001),
            dict(paid_cpu_debit_ns=None), dict(remaining_paid_credit_ns=None),
        ):
            bad = copy.deepcopy(phase)
            bad['budget_samples'][0]['meter']['Ok']['actual_flow'].update(changed)
            with self.subTest(changed=changed), self.assertRaises((ValueError, TypeError)):
                runner.checked_depletion_samples(bad)
        for changed in ({'observation_started_ns': 5}, {'meter': {'Err': 'clock'}}, {'meter': {}}):
            bad = copy.deepcopy(phase)
            bad['budget_samples'][0].update(changed)
            with self.subTest(sample=changed), self.assertRaises((ValueError, KeyError)):
                runner.checked_depletion_samples(bad)


if __name__ == '__main__':
    unittest.main()

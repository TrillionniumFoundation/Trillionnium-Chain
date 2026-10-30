#!/usr/bin/env python3
"""Synthetic semantic-rehash controls for the real finite reader predicates.

These fixtures are not native/prepared/process/paid-work evidence. They execute
phase_readback through metadata validation, stopping at the unrelated FD replay
boundary. Only that replay is replaced; flow and resource validators stay real.
Every mutated fixture and all duplicate copies are serialized and rehashed.
"""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import resource
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'scripts/ci'))
sys.path.insert(0, str(ROOT / 'formal/pon-nakamoto-v1'))
import check_pon_native_io_component as reader


class ReachedUnrelatedFdReplay(Exception):
    pass


def work_snapshot(retained):
    return dict(schema='public-v3-live-owner-completion-work-v1',
        identity_domain='public-v3-complete-work-identity-v1',
        identity_capacity=4096, identity_storage_bytes=4096*32,
        epoch_scope='same-shared-live-cpu-owner', evicts_live_epoch_identities=False,
        survives_process_restart=False, full_capacity_disables_ordinary_verification=False,
        retained_identities=retained, live_completions=0,
        repeated_identity_skips=0, full_capacity_skips=0)


def cpu_flow():
    value = dict.fromkeys(('credited_refill_ns', 'discarded_refill_ns',
        'booked_reservation_ns', 'live_debited_cpu_ns', 'settlement_residual_cpu_ns',
        'settled_full_cpu_ns', 'unsettled_known_live_cpu_ns', 'paid_cpu_debit_ns',
        'settlement_discard_ns', 'live_owners'), 0)
    return dict(value, schema='public-v3-local-actual-cpu-flow-v1',
        initial_credit_ns=2_000_000_000, remaining_paid_credit_ns=2_000_000_000,
        stored_credit_ns=2_000_000_000, balance_identity_verified=True)


def limits(role, pid, group):
    caps = reader.component.CAPS
    def observation():
        return dict(pid=pid, cgroup=group,
            address_space=dict.fromkeys(('soft_bytes', 'hard_bytes'),
                caps['actor_vm_bytes'] if role == 'actor' else caps['parent_vm_bytes']),
            file_size=dict.fromkeys(('soft_bytes', 'hard_bytes'),
                caps['actor_file_bytes'] if role == 'actor' else caps['parent_file_bytes']))
    return dict(schema=caps['schema'], role=role, original_cgroup_required=True,
        full_ledger_implemented=False, before=observation(), after=observation())


class SyntheticBundle:
    """Rehashed in-memory JSON members plus a real fixture-only directory FD."""
    def __init__(self, records, fd):
        self.fd = fd
        self.raw_records = {name: json.dumps(value, sort_keys=True,
            separators=(',', ':')).encode() for name, value in records.items()}
        self.files = {name: dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
            for name, raw in self.raw_records.items()}

    def json(self, name):
        return json.loads(self.raw_records[name])


class FiniteReaderSemanticCounterexamples(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print(json.dumps(dict(synthetic_predicate_fixtures=True,
            native_or_prepared_qualification=False, actual_nice=os.getpriority(os.PRIO_PROCESS, 0),
            actual_AS=list(resource.getrlimit(resource.RLIMIT_AS))), sort_keys=True), flush=True)

    def fixture(self):
        native_pid, pid, worker = 600, 601, 0
        group = '0::/synthetic-r03-component\n'
        source, tree, binary = '1'*40, '2'*40, '3'*64
        ready = dict(schema=reader.component.ACTOR_SCHEMA, kind='actor-ready',
            worker=worker, pid=pid, ppid=native_pid, cgroup=group,
            source_commit=source, source_tree=tree, binary_sha256=binary,
            setup_calls=1, producer='prepared-generic', setup_cpu_ns=1,
            setup_wall_ns=1, execution_binding={})
        result = dict(schema=reader.component.ACTOR_SCHEMA, kind='actor', worker=worker,
            pid=pid, cgroup=group, prefix_slots=[], pressure_slots=[],
            prefix_cpu_ns=1, pressure_cpu_ns=1, entire_actor_cpu_ns=3,
            entire_actor_wall_ns=1)
        finished = dict(schema=reader.component.ACTOR_SCHEMA, kind='actor-prefix',
            worker=worker, pid=pid, slots=[])
        child = dict(pid=pid, started_ns=10, reaped_ns=20, exit_success=True,
            parent_forced_kill=False, ready=deepcopy(ready), report=deepcopy(result),
            prefix_finished=deepcopy(finished), execution_binding=dict(binding=dict(fds=[7, 8, 9, 10])))
        phase = dict(schema=reader.component.NATIVE_SCHEMA, kind='phase', mode=reader.MODE,
            parent_pid=native_pid, plan=deepcopy(reader.component.PLAN), controller_cgroup=group,
            source_commit=source, source_tree=tree, binary_sha256=binary,
            prefix_epoch_ns=100, prefix_end_ns=30_000_000_100,
            pressure_epoch_ns=30_000_000_100, pressure_end_ns=32_000_000_100,
            initial_work=work_snapshot(0), post_prefix_work=work_snapshot(2),
            final_work=work_snapshot(6), children=[child, deepcopy(child)],
            actor_readiness=[deepcopy(ready), deepcopy(ready)])
        for name in ('initial_flow', 'post_prefix_flow', 'pressure_final_flow', 'final_flow'):
            phase[name] = cpu_flow()
        prefix = reader.PHASE+'actor-00/'
        job = dict(schema='native-public-v3-identity-actor-job-v2', worker=0,
            mode=reader.MODE, plan=deepcopy(reader.component.PLAN), template_packet='synthetic-wire',
            source_commit=source, source_tree=tree, binary_sha256=binary,
            output='/proc/self/fd/8/actor-00', prefix_marker='/proc/self/fd/8/prefix-start.json',
            pressure_marker='/proc/self/fd/8/pressure-start.json')
        records = {prefix+'job.json': job, prefix+'ready.json': ready,
            prefix+'report.json': result, prefix+'prefix-finished.json': finished,
            prefix+'process-limits.json': limits('actor', pid, group),
            'raw/process-limits.json': limits('campaign-parent', native_pid, group)}
        for stage in ('prefix', 'pressure'):
            records[reader.PHASE+stage+'-start.json'] = dict(schema=reader.component.NATIVE_SCHEMA,
                epoch_ns=phase[stage+'_epoch_ns'], end_ns=phase[stage+'_end_ns'])
        return phase, records

    def crosses_metadata_boundary(self, case, phase, records):
        # A malicious change updates every unsigned copy and its byte inventory.
        prefix = reader.PHASE+'actor-00/'
        child = phase['children'][0]
        child['ready'] = deepcopy(records[prefix+'ready.json'])
        child['report'] = deepcopy(records[prefix+'report.json'])
        child['prefix_finished'] = deepcopy(records[prefix+'prefix-finished.json'])
        phase['actor_readiness'][0] = deepcopy(child['ready'])
        records['synthetic-phase.json'] = phase
        with tempfile.TemporaryDirectory(prefix='pn1-r03-synthetic-') as temp:
            fd = os.open(temp, os.O_RDONLY | os.O_DIRECTORY)
            try:
                bundle = SyntheticBundle(records, fd)
                inventory = json.dumps(bundle.files, sort_keys=True, separators=(',', ':')).encode()
                print(json.dumps(dict(case=case, synthetic=True,
                    semantic_rehash=True, fixture_inventory_sha256=hashlib.sha256(inventory).hexdigest(),
                    fixture_members=len(bundle.files)), sort_keys=True), flush=True)
                try:
                    with patch.object(reader.original, 'descendant_actor_record',
                            side_effect=ReachedUnrelatedFdReplay):
                        reader.phase_readback(bundle, bundle.json('synthetic-phase.json'),
                            [{}, {}, {}, {}, {'wire': 'synthetic-wire'}], {'value': {}},
                            {'sha256': '3'*64}, 600, {'cgroup': '/synthetic-r03-component'})
                except ReachedUnrelatedFdReplay:
                    return True
                except (ValueError, KeyError, TypeError):
                    return False
                self.fail('synthetic predicate probe unexpectedly completed native readback')
            finally:
                os.close(fd)

    def test_producer_shaped_metadata_and_work_reach_fd_replay_only(self):
        phase, records = self.fixture()
        self.assertTrue(self.crosses_metadata_boundary('producer-shaped-synthetic-only', phase, records))

    def test_rehashed_actor_identity_and_setup_mutations_are_rejected(self):
        changes = [('ready.json', 'schema', 'future-schema'),
            ('report.json', 'schema', 'future-schema'),
            ('prefix-finished.json', 'schema', 'future-schema'),
            ('ready.json', 'worker', 1), ('report.json', 'worker', 1),
            ('prefix-finished.json', 'worker', 1),
            ('ready.json', 'worker', False), ('report.json', 'worker', False),
            ('prefix-finished.json', 'worker', False),
            ('ready.json', 'source_commit', '4'*40), ('ready.json', 'source_tree', '5'*40),
            ('ready.json', 'binary_sha256', '6'*64), ('ready.json', 'setup_calls', 0),
            ('ready.json', 'setup_calls', 2), ('ready.json', 'setup_calls', True),
            ('ready.json', 'producer', 'unbounded-or-unknown'),
            ('ready.json', 'setup_cpu_ns', 0), ('ready.json', 'setup_wall_ns', False),
            ('report.json', 'prefix_cpu_ns', 0), ('report.json', 'pressure_cpu_ns', False),
            ('report.json', 'entire_actor_cpu_ns', 0), ('report.json', 'entire_actor_wall_ns', False)]
        for member, key, bad in changes:
            with self.subTest(member=member, key=key, bad=bad):
                phase, records = self.fixture()
                records[reader.PHASE+'actor-00/'+member][key] = bad
                self.assertFalse(self.crosses_metadata_boundary(member+':'+key+':'+str(bad), phase, records))

    def test_rehashed_completion_work_domain_and_counters_are_rejected(self):
        changes = [('schema', 'future-schema'), ('identity_domain', 'per-key-domain'),
            ('identity_capacity', 8192), ('identity_storage_bytes', 1),
            ('epoch_scope', 'new-owner-per-request'), ('evicts_live_epoch_identities', True),
            ('survives_process_restart', True), ('full_capacity_disables_ordinary_verification', True),
            ('live_completions', 3), ('repeated_identity_skips', -1),
            ('full_capacity_skips', True), ('extra_unknown_field', 0)]
        for stage in ('initial_work', 'post_prefix_work', 'final_work'):
            for key, bad in changes:
                with self.subTest(stage=stage, key=key, bad=bad):
                    phase, records = self.fixture()
                    phase[stage][key] = bad
                    self.assertFalse(self.crosses_metadata_boundary(stage+':'+key, phase, records))
        for key in ('repeated_identity_skips', 'full_capacity_skips'):
            with self.subTest(initial_nonempty=key):
                phase, records = self.fixture()
                phase['initial_work'][key] = 1
                self.assertFalse(self.crosses_metadata_boundary('initial-not-empty:'+key, phase, records))


if __name__ == '__main__':
    unittest.main(verbosity=2)

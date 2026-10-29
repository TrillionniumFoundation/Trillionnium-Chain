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


def event(sequence, action, **changes):
    value = dict(sequence=sequence, action=action, generation=1,
        basename='native.sqlite', device=None, inode=None, linked=True,
        handles=0, pending_opens=0, shm_references=0, high_water_bytes=0,
        actual_last_bytes=0)
    value.update(changes)
    return value


def reserialize_lifecycle(row):
    # Match the Rust struct order even after semantically rehashing the JSON.
    row['lifecycle_serialized_bytes'] = sum(len(json.dumps(
        {key:item[key] for key in reader.EVENT_FIELDS}, ensure_ascii=False,
        separators=(',', ':')).encode()) for item in row['lifecycle']+row['cleanup_lifecycle'])


def object_from_event(row):
    return {key:value for key,value in dict(row, actual_last_allocated_blocks_512=1,
        reserved_pending_open=False).items() if key not in ('sequence', 'action')}


class RootLedgerSemanticCounterexamples(unittest.TestCase):
    """Real private fixture inodes, synthetic ledger; never native qualification."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='pn1-root-ledger-synthetic-')
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        directory = root/'raw/honest-miner'
        directory.mkdir(parents=True, mode=0o700)
        path = directory/'native.sqlite'
        path.write_bytes(b'fixture-only-raw!')
        path.chmod(0o600)
        info, root_info = path.stat(), directory.stat()
        inode = dict(device=info.st_dev, inode=info.st_ino,
            high_water_bytes=info.st_size, actual_last_bytes=info.st_size)
        events = [event(0, 'reserve-open'), event(1, 'reserve-handle', pending_opens=1),
            event(2, 'bind-real-inode', pending_opens=1, **inode),
            event(3, 'opened', handles=1, **inode), event(4, 'underlying-close', **inode)]
        row = dict(schema='pn1-owned-sqlite-real-inode-v1', owner_pid=600,
            root_device=root_info.st_dev, root_inode=root_info.st_ino,
            logical_bytes_limit=48*reader.MIB, retained_object_limit=3,
            high_water_sum=info.st_size, retained_logical_bytes_peak=info.st_size,
            retained_objects_peak=1, objects=[object_from_event(events[-1])],
            failed=False, first_failure=None, first_failure_sqlite_code=None,
            secondary_failures=[], secondary_failures_complete=True,
            callback_operations=2, denied_operations=0,
            allocated_blocks_hard_cap_implemented=False, lifecycle=events[:4],
            cleanup_lifecycle=events[4:], lifecycle_complete=True,
            lifecycle_serialized_bytes=0, lifecycle_serialized_bytes_cap=655360,
            quarantined_actual_states=0, quarantined_sqlite_codes=[],
            quarantine_entries_complete=True)
        reserialize_lifecycle(row)
        self.role = dict(index=0, role='honest-miner', registered_vfs='synthetic-root-vfs', receipt=row)
        self.layout = dict(roles=[dict(index=0, role='honest-miner',
            root_dev_ino=[root_info.st_dev, root_info.st_ino], registered_vfs='synthetic-root-vfs')])
        self.bundle = SyntheticBundle({}, os.open(root, os.O_RDONLY|os.O_DIRECTORY))
        self.bundle.path_parts = reader.Bundle.path_parts
        self.bundle.files = {'raw/honest-miner/native.sqlite':
            dict(bytes=info.st_size, sha256=hashlib.sha256(path.read_bytes()).hexdigest())}
        self.addCleanup(os.close, self.bundle.fd)

    def accepted(self, row=None):
        role = deepcopy(self.role)
        if row is not None: role['receipt'] = row
        return reader.root_terminal(self.bundle, role, 600, self.layout)

    def rejected(self, row, recalculate=True):
        if recalculate: reserialize_lifecycle(row)
        with self.assertRaises((ValueError, KeyError, TypeError)):
            self.accepted(row)

    def test_actual_fixture_inode_and_producer_shaped_ledger_pass_only_predicate(self):
        self.assertEqual(self.accepted(), 0)

    def test_original_unknown_action_and_zero_byte_count_counterexamples_reject(self):
        row = deepcopy(self.role['receipt'])
        row['lifecycle'][1]['action'] = 'invented-action'
        self.rejected(row)
        row = deepcopy(self.role['receipt'])
        row['lifecycle_serialized_bytes'] = 0
        self.rejected(row, recalculate=False)

    def test_root_object_and_event_require_exact_existing_schema(self):
        for target in ('root', 'object', 'event'):
            for change in ('extra', 'missing'):
                with self.subTest(target=target, change=change):
                    row = deepcopy(self.role['receipt'])
                    item = row if target == 'root' else row['objects'][0] if target == 'object' else row['lifecycle'][0]
                    if change == 'extra': item['unexpected_authority'] = True
                    else: del item['callback_operations' if target == 'root' else 'generation']
                    self.rejected(row, recalculate=False)

    def test_typed_integer_and_boolean_fields_reject_coercions(self):
        changes = [('owner_pid', True), ('logical_bytes_limit', float(48*reader.MIB)),
            ('retained_object_limit', 3.0), ('callback_operations', True),
            ('retained_objects_peak', True), ('lifecycle_serialized_bytes', False),
            ('denied_operations', False), ('quarantined_actual_states', False),
            ('high_water_sum', 16.0), ('failed', 0), ('lifecycle_complete', 1)]
        for field,value in changes:
            with self.subTest(field=field):
                row = deepcopy(self.role['receipt']); row[field] = value
                self.rejected(row, recalculate=False)
        for field,value in [('generation', True), ('device', True), ('inode', 1.5),
                ('linked', 1), ('handles', False), ('pending_opens', False),
                ('shm_references', False), ('actual_last_bytes', False),
                ('high_water_bytes', -1), ('actual_last_allocated_blocks_512', False),
                ('reserved_pending_open', 0)]:
            with self.subTest(object_field=field):
                row = deepcopy(self.role['receipt']); row['objects'][0][field] = value
                self.rejected(row)

    def test_action_channel_and_within_channel_order_are_not_interchangeable(self):
        row = deepcopy(self.role['receipt'])
        row['lifecycle'].append(row['cleanup_lifecycle'].pop())
        self.rejected(row)
        row = deepcopy(self.role['receipt'])
        row['lifecycle'][1:3] = reversed(row['lifecycle'][1:3])
        self.rejected(row)
        for sequence in (True, -1, 1280, 2):
            row = deepcopy(self.role['receipt']); row['lifecycle'][0]['sequence'] = sequence
            self.rejected(row)

    def test_deleted_open_or_close_cannot_reconcile_final_zero_references(self):
        row = deepcopy(self.role['receipt'])
        row['lifecycle'].pop()
        row['cleanup_lifecycle'][0]['sequence'] = 3
        self.rejected(row)
        row = deepcopy(self.role['receipt'])
        row['cleanup_lifecycle'].clear()
        self.rejected(row)

    def test_rehashed_generation_inode_and_reference_transitions_reject(self):
        changes = [(0, 'generation', 2), (1, 'pending_opens', 2),
            (2, 'generation', 2), (3, 'handles', 2), (3, 'pending_opens', 1),
            (3, 'shm_references', 1), (4, 'handles', 1), (4, 'device', 1),
            (4, 'inode', self.role['receipt']['objects'][0]['inode']+1),
            (4, 'basename', 'native.sqlite-wal')]
        for position,field,value in changes:
            with self.subTest(position=position, field=field):
                row = deepcopy(self.role['receipt'])
                (row['lifecycle']+row['cleanup_lifecycle'])[position][field] = value
                self.rejected(row)

    def test_final_objects_are_exactly_the_retained_generations(self):
        for change in ('omitted', 'duplicate', 'generation', 'inode', 'refs', 'high-water'):
            with self.subTest(change=change):
                row = deepcopy(self.role['receipt'])
                if change == 'omitted': row['objects'] = []; row['high_water_sum'] = 0
                elif change == 'duplicate': row['objects'] *= 2; row['high_water_sum'] *= 2
                else:
                    key = {'generation':'generation', 'inode':'inode', 'refs':'handles',
                        'high-water':'high_water_bytes'}[change]
                    row['objects'][0][key] = 2 if change == 'generation' else 1
                self.rejected(row)

    def test_uninventoried_sqlite_object_is_not_covered_by_linked_terminal(self):
        self.bundle.files['raw/honest-miner/native.sqlite-wal'] = dict(bytes=0, sha256='0'*64)
        self.rejected(deepcopy(self.role['receipt']))

    def test_retained_peaks_and_admissions_cover_recorded_lifetimes(self):
        for field,value in [('retained_objects_peak', 0), ('retained_objects_peak', 2),
                ('retained_logical_bytes_peak', 15), ('callback_operations', 1),
                ('retained_logical_bytes_peak', 48*reader.MIB+1),
                ('lifecycle_serialized_bytes_cap', 655361)]:
            with self.subTest(field=field,value=value):
                row = deepcopy(self.role['receipt']); row[field] = value
                self.rejected(row)

    def test_repeated_bind_size_refresh_is_not_fabricated_as_a_missing_event(self):
        row = deepcopy(self.role['receipt'])
        row['lifecycle'][2]['actual_last_bytes'] = 0
        row['lifecycle'][2]['high_water_bytes'] = 0
        row['lifecycle'][3]['actual_last_bytes'] = 0
        row['lifecycle'][3]['high_water_bytes'] = 0
        # A repeated bind may update size/high water without an emitted record.
        # The final close records the resulting observation, not a new I/O claim.
        reserialize_lifecycle(row)
        self.assertEqual(self.accepted(row), 0)

    def test_shm_reference_before_first_actual_inode_bind_is_legal(self):
        row = deepcopy(self.role['receipt'])
        actual = dict(device=5, inode=8, high_water_bytes=32768, actual_last_bytes=32768)
        base = dict(generation=2, basename='native.sqlite-shm')
        additions = [event(4,'reserve-open',**base),
            event(5,'reserve-growth',high_water_bytes=32768,**base),
            event(6,'shm-reference',high_water_bytes=32768,shm_references=1,**base),
            event(7,'bind-real-inode',shm_references=1,**base,**actual),
            event(8,'underlying-shm-unmap',**base,**actual)]
        row['lifecycle'] += additions[:4]
        row['cleanup_lifecycle'][0]['sequence'] = 9
        row['cleanup_lifecycle'].insert(0, additions[-1])
        row['objects'].append(object_from_event(additions[-1]))
        row['retained_objects_peak'] = 2
        row['high_water_sum'] += 32768
        row['retained_logical_bytes_peak'] = row['high_water_sum']
        row['callback_operations'] += 2
        reserialize_lifecycle(row)
        reader.root_lifecycle(row)

    def test_collected_inode_may_be_reused_but_retained_alias_may_not(self):
        row = deepcopy(self.role['receipt'])
        events = row['lifecycle'][:]
        actual = dict(device=5, inode=8, high_water_bytes=12, actual_last_bytes=12)
        journal = dict(generation=2, basename='native.sqlite-journal')
        wal = dict(generation=3, basename='native.sqlite-wal')
        events += [event(4,'reserve-open',**journal),
            event(5,'bind-real-inode',**journal,**actual),
            event(6,'unlinked',linked=False,**journal,**actual),
            event(7,'reserve-open',**wal), event(8,'bind-real-inode',**wal,**actual)]
        row['cleanup_lifecycle'][0]['sequence'] = 9
        events += row['cleanup_lifecycle']
        row['lifecycle'] = [item for item in events if item['action'] in reader.ORDINARY_ACTIONS]
        row['cleanup_lifecycle'] = [item for item in events if item['action'] in reader.HEALTHY_CLEANUP_ACTIONS]
        row['objects'].append(object_from_event(events[-2]))
        row['retained_objects_peak'] = 2
        row['high_water_sum'] += 12
        row['retained_logical_bytes_peak'] = row['high_water_sum']
        row['callback_operations'] += 2
        reserialize_lifecycle(row)
        reader.root_lifecycle(row)
        # Keep journal linked and charged: the same inode cannot bind a new slot.
        row['cleanup_lifecycle'].pop(0)
        for number,item in enumerate(sorted(row['lifecycle']+row['cleanup_lifecycle'],
                key=lambda item:item['sequence'])):
            item['sequence'] = number
        reserialize_lifecycle(row)
        with self.assertRaises(ValueError): reader.root_lifecycle(row)

    def test_historical_capacity_failure_remains_failure_after_recorded_ledger_readback(self):
        path = ROOT/'evidence/pon-native-io-pn1-20261026-v21/actual399/execution/raw/preparation.json'
        role = json.loads(path.read_bytes())['native_io_terminal_roots'][0]
        self.assertIs(role['receipt']['failed'], True)
        reader.root_lifecycle(role['receipt'])
        with self.assertRaises(ValueError):
            reader.root_terminal(None, role, role['receipt']['owner_pid'], None)


if __name__ == '__main__':
    unittest.main(verbosity=2)

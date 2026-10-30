#!/usr/bin/env python3
"""Synthetic, recharged root-history counterexamples; never native I/O evidence."""
from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_pon_native_io_reservation_v2 as reader
import check_pon_native_io_component as original


def event(seq, action, *, device=7, inode=11, water=0, actual=0, handles=0,
          pending=0, shm=0, linked=True, request=None, name='native.sqlite', generation=1):
    row = dict(sequence=seq, action=action, generation=generation, basename=name,
               device=device, inode=inode, linked=linked, handles=handles,
               pending_opens=pending, shm_references=shm,
               high_water_bytes=water, actual_last_bytes=actual)
    if request is not None:
        row['requested_endpoint'] = request
    return row


def recharge(row):
    row['lifecycle_serialized_bytes'] = sum(len(json.dumps(item, ensure_ascii=False,
        separators=(',', ':'), allow_nan=False).encode())
        for item in row['lifecycle'] + row['cleanup_lifecycle'])
    return row


def fixture():
    q = reader.QUANTUM
    events = [event(0, 'reserve-open', device=None, inode=None),
              event(1, 'bind-real-inode'),
              event(2, 'reserve-handle', pending=1),
              event(3, 'opened', handles=1),
              event(4, 'reserve-growth', handles=1, water=q, request=1)]
    cleanup = [event(5, 'underlying-close', water=q, actual=1)]
    obj = {key:cleanup[-1][key] for key in reader.OBJECT_FIELDS if key in cleanup[-1]}
    obj.update(actual_last_allocated_blocks_512=1, reserved_pending_open=False)
    return recharge(dict(schema=reader.DOMAIN, owner_pid=123, root_device=7, root_inode=99,
        logical_bytes_limit=reader.ROOT_BYTES, retained_object_limit=3, high_water_sum=q,
        retained_logical_bytes_peak=q, retained_objects_peak=1, objects=[obj],
        failed=False, first_failure=None, first_failure_sqlite_code=None,
        secondary_failures=[], secondary_failures_complete=True, callback_operations=10,
        denied_operations=0, allocated_blocks_hard_cap_implemented=False,
        lifecycle=events, cleanup_lifecycle=cleanup, lifecycle_complete=True,
        lifecycle_serialized_bytes=0, lifecycle_serialized_bytes_cap=655360,
        quarantined_actual_states=0, quarantined_sqlite_codes=[], quarantine_entries_complete=True,
        growth_reservation_quantum_bytes=q))


def large_history(reopens):
    """Fixture generated from permitted state transitions, never native evidence."""
    row = fixture(); ordinary, cleanup, objects = [], [], []
    seq = 0
    for index, name in enumerate(('native.sqlite', 'native.sqlite-wal', 'native.sqlite-journal')):
        kw = dict(name=name, generation=index+1, inode=11+index)
        ordinary.append(event(seq, 'reserve-open', device=None, inode=None,
                              name=name, generation=index+1)); seq += 1
        ordinary.append(event(seq, 'bind-real-inode', **kw)); seq += 1
        ordinary.append(event(seq, 'reserve-handle', pending=1, **kw)); seq += 1
        ordinary.append(event(seq, 'opened', handles=1, **kw)); seq += 1
        for step in range(256):
            ordinary.append(event(seq, 'reserve-growth', handles=1,
                water=(step+1)*reader.QUANTUM, actual=step*reader.QUANTUM,
                request=step*reader.QUANTUM+1, **kw)); seq += 1
        last = event(seq, 'underlying-close', water=reader.FILE_BYTES,
                     actual=reader.FILE_BYTES, **kw); seq += 1
        cleanup.append(last)
        obj = {key:last[key] for key in reader.OBJECT_FIELDS if key in last}
        obj.update(actual_last_allocated_blocks_512=0, reserved_pending_open=False)
        objects.append(obj)
    for _ in range(reopens):
        ordinary.append(event(seq, 'reserve-handle', pending=1,
            water=reader.FILE_BYTES, actual=reader.FILE_BYTES)); seq += 1
        ordinary.append(event(seq, 'opened', handles=1,
            water=reader.FILE_BYTES, actual=reader.FILE_BYTES)); seq += 1
        cleanup.append(event(seq, 'underlying-close',
            water=reader.FILE_BYTES, actual=reader.FILE_BYTES)); seq += 1
    row.update(lifecycle=ordinary, cleanup_lifecycle=cleanup, objects=objects,
        high_water_sum=reader.ROOT_BYTES, retained_logical_bytes_peak=reader.ROOT_BYTES,
        retained_objects_peak=3, callback_operations=5000)
    return recharge(row)


class ReservationV2Counterexamples(unittest.TestCase):
    def reject(self, row):
        recharge(row)
        with self.assertRaises(ValueError):
            reader.check_root(row)

    def test_original_admission_margin_is_replayed_before_each_admitted_event(self):
        boundary = large_history(119)
        self.assertEqual(len(boundary['lifecycle']), 1018)
        # The final handle was admitted with 1016 ordinary entries; opened and
        # cleanup consume pre-reserved space and do not add a fictitious gate.
        reader.check_root(boundary)
        for reopens in (120, 122):
            with self.subTest(reopens=reopens):
                denied = large_history(reopens)
                self.assertLessEqual(len(denied['lifecycle']), 1024)
                with self.assertRaisesRegex(ValueError, 'ADMISSION_AFTER_EXHAUSTION'):
                    reader.check_root(denied)

    def test_named_pre_io_observation_requires_a_linked_name(self):
        row = fixture()
        row['lifecycle'][1].update(action='bind-existing-before-io-v2',
                                  linked=False, requested_endpoint=0)
        for event_row in row['lifecycle'][2:]+row['cleanup_lifecycle']:
            event_row['linked'] = False
        row['objects'][0]['linked'] = False
        self.reject(row)

    def test_valid_complete_history_grants_no_host_or_component_authority(self):
        result = reader.check_root(fixture())
        self.assertEqual(result['recorded_events'], 6)
        self.assertEqual(result['reservation_peak_bytes'], reader.QUANTUM)
        for key in ('original_host_authenticated', 'native_component_qualified',
                    'physical_blocks_quota', 'public_fairness_qualified'):
            self.assertIs(result[key], False)

    def test_namespace_quantum_exact_fields_and_typed_limits(self):
        for key, value in [('schema', 'pn1-owned-sqlite-real-inode-v1'),
                           ('growth_reservation_quantum_bytes', 32768),
                           ('growth_reservation_quantum_bytes', True),
                           ('logical_bytes_limit', reader.ROOT_BYTES+1),
                           ('retained_object_limit', 4),
                           ('lifecycle_serialized_bytes_cap', 655361)]:
            with self.subTest(key=key, value=value):
                row = fixture(); row[key] = value; self.reject(row)
        row = fixture(); row['invented'] = True; self.reject(row)
        row = fixture(); del row['growth_reservation_quantum_bytes']; self.reject(row)

    def test_requested_endpoint_types_non_growth_and_wrong_rounding(self):
        for value in (True, 1.0, -1, 0, reader.FILE_BYTES+1, reader.QUANTUM+1):
            with self.subTest(value=value):
                row = fixture(); row['lifecycle'][4]['requested_endpoint'] = value; self.reject(row)
        row = fixture(); del row['lifecycle'][4]['requested_endpoint']; self.reject(row)
        row = fixture(); row['lifecycle'][3]['requested_endpoint'] = 1; self.reject(row)

    def test_nonreservation_event_and_terminal_cannot_silently_raise_high_water(self):
        row = fixture(); row['cleanup_lifecycle'][0]['high_water_bytes'] *= 2
        row['objects'][0]['high_water_bytes'] *= 2; row['high_water_sum'] *= 2
        row['retained_logical_bytes_peak'] *= 2; self.reject(row)
        row = fixture(); row['objects'][0]['high_water_bytes'] *= 2
        row['high_water_sum'] *= 2; row['retained_logical_bytes_peak'] *= 2; self.reject(row)
        row = fixture(); row['retained_logical_bytes_peak'] *= 2; self.reject(row)
        row = fixture(); row['lifecycle'][4]['high_water_bytes'] += 1; self.reject(row)

    def test_growth_cannot_retroactively_cover_already_observed_unreserved_bytes(self):
        row = fixture(); row['lifecycle'][4]['actual_last_bytes'] = 1; self.reject(row)
        row = fixture(); row['objects'][0]['actual_last_bytes'] = reader.QUANTUM+1; self.reject(row)
        # A later observation within the previously recorded reservation is legal.
        row = fixture(); row['objects'][0]['actual_last_bytes'] = reader.QUANTUM
        reader.check_root(recharge(row))

    def test_first_post_io_bind_cannot_supply_implicit_initial_reservation(self):
        row = fixture()
        row['lifecycle'][1]['high_water_bytes'] = reader.QUANTUM
        row['lifecycle'][1]['actual_last_bytes'] = 1
        self.reject(row)

    def test_explicit_existing_inode_observation_has_exact_endpoint_and_first_bind(self):
        q = reader.QUANTUM
        row = fixture()
        row['lifecycle'] = [event(0, 'reserve-open', device=None, inode=None),
            event(1, 'bind-existing-before-io-v2', water=2*q, actual=q+1, request=q+1),
            event(2, 'reserve-handle', water=2*q, actual=q+1, pending=1),
            event(3, 'opened', water=2*q, actual=q+1, handles=1)]
        row['cleanup_lifecycle'] = [event(4, 'underlying-close', water=2*q, actual=q+1)]
        row['objects'][0].update(high_water_bytes=2*q, actual_last_bytes=q+1)
        row['high_water_sum'] = row['retained_logical_bytes_peak'] = 2*q
        reader.check_root(recharge(row))
        altered = deepcopy(row); altered['lifecycle'][1]['requested_endpoint'] -= 1; self.reject(altered)
        altered = deepcopy(row); altered['lifecycle'][2] = event(2,
            'bind-existing-before-io-v2', water=2*q, actual=q+1, request=q+1); self.reject(altered)

    def test_unbound_shm_growth_is_reserved_before_real_inode_bind(self):
        q = reader.QUANTUM
        row = fixture(); name = 'native.sqlite-shm'
        row['lifecycle'] = [event(0, 'reserve-open', device=None, inode=None, name=name),
            event(1, 'reserve-growth', device=None, inode=None, name=name, water=q, request=3),
            event(2, 'shm-reference', device=None, inode=None, name=name, water=q, shm=1),
            event(3, 'bind-real-inode', name=name, water=q, actual=32768, shm=1)]
        row['cleanup_lifecycle'] = [event(4, 'underlying-shm-unmap', name=name, water=q, actual=32768)]
        row['objects'][0].update(basename=name, actual_last_bytes=32768)
        reader.check_root(recharge(row))
        altered = deepcopy(row); altered['lifecycle'][1]['requested_endpoint'] = 0; self.reject(altered)
        altered = deepcopy(row); altered['lifecycle'][3]['high_water_bytes'] *= 2; self.reject(altered)

    def test_omitted_rehashed_reservation_cannot_be_hidden_by_renumbering(self):
        row = fixture(); del row['lifecycle'][4]
        for index, item in enumerate(row['lifecycle'] + row['cleanup_lifecycle']):
            item['sequence'] = index
        self.reject(row)
        row = fixture(); row['cleanup_lifecycle'][0]['sequence'] += 1; self.reject(row)

    def test_reference_generations_and_terminal_failure_flags_remain_strict(self):
        for key, value in [('failed', True), ('lifecycle_complete', False),
                           ('allocated_blocks_hard_cap_implemented', True),
                           ('quarantine_entries_complete', False), ('denied_operations', 1),
                           ('callback_operations', 0)]:
            row = fixture(); row[key] = value
            with self.subTest(key=key): self.reject(row)
        row = fixture(); row['cleanup_lifecycle'][0]['handles'] = 1; self.reject(row)
        row = fixture(); row['objects'][0]['generation'] = 2; self.reject(row)
        row = fixture(); row['objects'][0]['inode'] = 12; self.reject(row)

    def test_original_serialized_byte_charge_is_recomputed_not_trusted(self):
        row = fixture(); row['lifecycle_serialized_bytes'] += 1
        with self.assertRaises(ValueError): reader.check_root(row)
        row = fixture(); row['lifecycle'][4]['invented'] = 0; self.reject(row)
        row = fixture(); row['cleanup_lifecycle'] *= 257; self.reject(row)

    def test_v1_reader_remains_separate_and_v2_has_no_v1_fallback(self):
        row = fixture()
        del row['growth_reservation_quantum_bytes']
        row['schema'] = 'pn1-owned-sqlite-real-inode-v1'
        del row['lifecycle'][4]['requested_endpoint']
        row['lifecycle'][4]['high_water_bytes'] = 1
        row['cleanup_lifecycle'][0]['high_water_bytes'] = 1
        row['objects'][0]['high_water_bytes'] = 1
        row['high_water_sum'] = row['retained_logical_bytes_peak'] = 1
        original.root_lifecycle(recharge(row))
        self.reject(row)


if __name__ == '__main__':
    unittest.main()

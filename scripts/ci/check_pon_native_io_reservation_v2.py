#!/usr/bin/env python3
"""Replay one healthy, closed V2 root's complete logical reservations.

The V1 reader and its lower-bound semantics are unchanged. This helper has no
native execution or GitHub capability and grants no component/host qualification.
A full caller must separately bind source, PID, root inode, actual files, all
three FDs, the original workload and original-host evidence. A rounded logical
reservation is not actual length, allocated blocks, or a physical filesystem quota.
"""
from __future__ import annotations
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'scripts/ci'))
sys.path.insert(0, str(ROOT / 'formal/pon-nakamoto-v1'))
from check_pon_native_io_component import (
    EVENT_FIELDS, HEALTHY_CLEANUP_ACTIONS, OBJECT_FIELDS, ORDINARY_ACTIONS,
    REF_FIELDS, ROOT_FIELDS, exact_fields, positive, require, root_object_fields, same,
)

DOMAIN = 'pn1-owned-sqlite-reservation-v2'
QUANTUM = 65536
FILE_BYTES = 16 * 1024**2
ROOT_BYTES = 3 * FILE_BYTES
ROOT_FIELDS_V2 = ROOT_FIELDS + ('growth_reservation_quantum_bytes',)
REQUEST_ACTIONS = frozenset(('reserve-growth', 'bind-existing-before-io-v2'))
ORDINARY_ACTIONS_V2 = ORDINARY_ACTIONS | {'bind-existing-before-io-v2'}
ADMISSION_ACTIONS = frozenset(('reserve-open', 'reserve-handle', 'reserve-growth',
                               'bind-existing-before-io-v2'))


def reserved_endpoint(endpoint):
    positive(endpoint, 0, FILE_BYTES)
    return (endpoint + QUANTUM - 1) // QUANTUM * QUANTUM


def object_fields(value):
    root_object_fields(value)
    require(value['high_water_bytes'] % QUANTUM == 0,
            'RESERVATION_V2_NONCANONICAL_QUANTUM')


def check_root(row):
    """Require exact recorded reservation state; never repair a claimed history."""
    exact_fields(row, ROOT_FIELDS_V2, 'RESERVATION_V2_ROOT_FIELDS')
    same(row['schema'], DOMAIN)
    same(row['growth_reservation_quantum_bytes'], QUANTUM)
    positive(row['owner_pid'], 1, 2**32-1)
    positive(row['root_device'], 0, 2**64-1)
    positive(row['root_inode'], 1, 2**64-1)
    same(row['logical_bytes_limit'], ROOT_BYTES)
    same(row['retained_object_limit'], 3)
    for name in ('failed', 'allocated_blocks_hard_cap_implemented'):
        same(row[name], False)
    for name in ('secondary_failures_complete', 'lifecycle_complete', 'quarantine_entries_complete'):
        same(row[name], True)
    for name in ('first_failure', 'first_failure_sqlite_code'):
        same(row[name], None)
    for name in ('denied_operations', 'quarantined_actual_states'):
        same(row[name], 0)
    for name in ('secondary_failures', 'quarantined_sqlite_codes'):
        same(row[name], [])
    ordinary, cleanup = row['lifecycle'], row['cleanup_lifecycle']
    require(type(ordinary) is list and type(cleanup) is list
            and len(ordinary) <= 1024 and len(cleanup) <= 256,
            'RESERVATION_V2_ORIGINAL_EVENT_CAPS')
    events, charged = [], 0
    for series, actions in ((ordinary, ORDINARY_ACTIONS_V2), (cleanup, HEALTHY_CLEANUP_ACTIONS)):
        prior = -1
        for event in series:
            require(type(event) is dict and type(event.get('action')) is str
                    and event['action'] in actions, 'RESERVATION_V2_ACTION')
            request = event['action'] in REQUEST_ACTIONS
            fields = EVENT_FIELDS + (('requested_endpoint',) if request else ())
            exact_fields(event, fields, 'RESERVATION_V2_EVENT_FIELDS')
            positive(event['sequence'], 0, 1279)
            require(event['sequence'] > prior, 'RESERVATION_V2_SERIES_ORDER')
            prior = event['sequence']
            object_fields(event)
            if request:
                positive(event['requested_endpoint'], 0, FILE_BYTES)
            size = len(json.dumps({key:event[key] for key in fields}, ensure_ascii=False,
                                  separators=(',', ':'), allow_nan=False).encode('utf-8'))
            require(size <= 512, 'RESERVATION_V2_ORIGINAL_EVENT_BYTES')
            charged += size
            events.append(event)
    same(positive(row['lifecycle_serialized_bytes'], 0, 655360), charged)
    same(row['lifecycle_serialized_bytes_cap'], 655360)
    events.sort(key=lambda event: event['sequence'])
    same([event['sequence'] for event in events], list(range(len(events))))
    active, generations, peak_objects, peak_bytes, admissions = {}, 0, 0, 0, 0
    ordinary_seen = 0
    for event in events:
        action, generation = event['action'], event['generation']
        if action in ADMISSION_ACTIONS:
            # Replay the original admission margin at the event's actual
            # sequence, not merely the final 1024-entry storage bound. Bind,
            # opened and shm-reference may use already reserved record space.
            require(ordinary_seen + 8 <= 1024, 'RESERVATION_V2_ADMISSION_AFTER_EXHAUSTION')
        if action in ORDINARY_ACTIONS_V2:
            ordinary_seen += 1
        if action == 'reserve-open':
            generations += 1
            same(generation, generations)
            require(len(active) < 3 and not any(old['linked']
                    and old['basename'] == event['basename'] for old in active.values()),
                    'RESERVATION_V2_SLOT_OR_NAME')
            same([event[key] for key in ('device', 'inode', 'linked', *REF_FIELDS,
                  'high_water_bytes', 'actual_last_bytes')], [None, None, True, 0, 0, 0, 0, 0])
            state = dict(event, reserved_pending_open=True)
            admissions += 1
        else:
            require(generation in active, 'RESERVATION_V2_UNKNOWN_GENERATION')
            old = active[generation]
            same(event['basename'], old['basename'])
            require(old['linked'] or event['linked'] is False, 'RESERVATION_V2_RELINK')
            expected_refs = [old[key] for key in REF_FIELDS]
            if action in ('bind-real-inode', 'bind-existing-before-io-v2'):
                require(old['device'] is None and event['device'] is not None,
                        'RESERVATION_V2_FIRST_BIND')
            else:
                same([event['device'], event['inode']], [old['device'], old['inode']])
                if old['device'] is None:
                    same(event['actual_last_bytes'], 0)
                    same(event['linked'], True)
            if action == 'bind-existing-before-io-v2':
                same(event['linked'], True)
                same(event['requested_endpoint'], event['actual_last_bytes'])
                same(event['high_water_bytes'], max(old['high_water_bytes'],
                     reserved_endpoint(event['requested_endpoint'])))
                admissions += 1
            elif action == 'reserve-growth':
                require(event['requested_endpoint'] > old['high_water_bytes'],
                        'RESERVATION_V2_NON_GROWTH_REQUEST')
                same(event['high_water_bytes'], reserved_endpoint(event['requested_endpoint']))
                require(event['actual_last_bytes'] <= old['high_water_bytes'],
                        'RESERVATION_V2_RETROACTIVE_RESERVATION')
                admissions += 1
            else:
                same(event['high_water_bytes'], old['high_water_bytes'])
            if action == 'reserve-handle':
                expected_refs[1] += 1
                admissions += 1
            elif action == 'opened':
                require(old['pending_opens'] > 0 and event['device'] is not None,
                        'RESERVATION_V2_UNRESERVED_OPEN')
                expected_refs[0] += 1
                expected_refs[1] -= 1
            elif action == 'shm-reference':
                same(event['basename'], 'native.sqlite-shm')
                expected_refs[2] += 1
            elif action == 'underlying-close':
                require(old['handles'] > 0, 'RESERVATION_V2_UNOWNED_CLOSE')
                expected_refs[0] -= 1
            elif action == 'underlying-shm-unmap':
                require(old['shm_references'] > 0, 'RESERVATION_V2_UNOWNED_UNMAP')
                expected_refs[2] -= 1
            elif action == 'unlinked':
                same(event['linked'], False)
            same([event[key] for key in REF_FIELDS], expected_refs)
            state = dict(event, reserved_pending_open=(old['reserved_pending_open']
                and action not in ('bind-real-inode', 'bind-existing-before-io-v2')))
        active[generation] = state
        ids = [(entry['device'], entry['inode']) for entry in active.values()
               if entry['device'] is not None]
        require(len(ids) == len(set(ids)), 'RESERVATION_V2_INODE_ALIAS')
        peak_objects = max(peak_objects, len(active))
        peak_bytes = max(peak_bytes, sum(entry['high_water_bytes'] for entry in active.values()))
        if action in HEALTHY_CLEANUP_ACTIONS:
            main_refs = sum(entry['handles'] + entry['pending_opens']
                            for entry in active.values() if entry['basename'] == 'native.sqlite')
            active = {key:entry for key,entry in active.items() if not (
                entry['linked'] is False and entry['reserved_pending_open'] is False
                and all(entry[field] == 0 for field in REF_FIELDS)
                and (entry['basename'] != 'native.sqlite' or main_refs == 0))}
    objects = row['objects']
    require(type(objects) is list and len(objects) <= 3, 'RESERVATION_V2_OBJECT_CAP')
    seen, high_water = set(), 0
    for obj in objects:
        exact_fields(obj, OBJECT_FIELDS, 'RESERVATION_V2_OBJECT_FIELDS')
        object_fields(obj)
        positive(obj['actual_last_allocated_blocks_512'], 0, 2**64-1)
        require(obj['reserved_pending_open'] is False and obj['device'] is not None
                and obj['generation'] in active and obj['generation'] not in seen,
                'RESERVATION_V2_UNBOUND_OR_UNRECORDED_OBJECT')
        seen.add(obj['generation'])
        old = active[obj['generation']]
        for key in ('generation', 'device', 'inode', 'basename', 'linked',
                    *REF_FIELDS, 'reserved_pending_open', 'high_water_bytes'):
            same(obj[key], old[key])
        same([obj[key] for key in REF_FIELDS], [0, 0, 0])
        high_water += obj['high_water_bytes']
    same(seen, set(active))
    same(positive(row['high_water_sum'], 0, ROOT_BYTES), high_water)
    same(positive(row['retained_objects_peak'], 0, 3), peak_objects)
    same(positive(row['retained_logical_bytes_peak'], 0, ROOT_BYTES), peak_bytes)
    positive(row['callback_operations'], admissions, 2**64-1)
    return dict(schema='pn1-reservation-v2-root-replay-v1', recorded_events=len(events),
                retained_generations=len(active), reservation_peak_bytes=peak_bytes,
                original_host_authenticated=False, native_component_qualified=False,
                physical_blocks_quota=False, public_fairness_qualified=False)

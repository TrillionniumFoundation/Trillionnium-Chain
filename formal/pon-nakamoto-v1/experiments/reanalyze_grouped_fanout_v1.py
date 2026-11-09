#!/usr/bin/env python3
"""Recheck one SHA-pinned historical fanout report without running its workload.

Only accounting over the report's supplied worker observations is recomputed.
Source, binary, host, transport-readback and qualification observations remain
historical claims in the unchanged pinned input; this is not a new experiment.
The output uses v2 for producer-bound fixed-packet accounting; the historical
campaign input remains v0, and its stored reports are retained without edits.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
import sys

FORMAL_ROOT = Path(__file__).resolve().parents[1]
if str(FORMAL_ROOT) not in sys.path:
    sys.path.insert(0, str(FORMAL_ROOT))

import grouped_fresh_deployment_cost_v0 as accounting


SCHEMA = 'pon-grouped-fanout-reanalysis-v2'
INPUT_SCHEMA = 'pon-grouped-fresh-fanout-campaign-v0'
MAX_INPUT_BYTES = 16 * 1024 * 1024
TOPOLOGIES = (1, 2, 4)
QUALIFICATION_BOUNDARIES = {
    'external_demand_authenticated': False,
    'actual_consumer_uses_observed': 0,
    'native_payment_for_grouped_output_observed': False,
    'independent_operators': False,
    'global_verification_cap_enforced': False,
    'hidden_verifier_side_channel_model_verified': False,
    'minimum_fresh_neural_cost_proved': False,
    'physical_resource_lower_bound_proved': False,
    'quantum_security_proved': False,
    'pow_qualified': False,
    'production_activation': False,
    'chainwork_awarded': 0,
}


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('DUPLICATE_JSON_KEY')
        value[key] = item
    return value


def _nonfinite(_value):
    raise ValueError('NONFINITE_JSON_NUMBER')


def _float(value):
    value = float(value)
    if not math.isfinite(value):
        raise ValueError('NONFINITE_JSON_NUMBER')
    return value


def _parse_pinned(raw, expected_sha256):
    if (type(expected_sha256) is not str or len(expected_sha256) != 64
            or any(c not in '0123456789abcdef' for c in expected_sha256)):
        raise ValueError('EXPECTED_SHA256_REQUIRED')
    if type(raw) is not bytes or len(raw) > MAX_INPUT_BYTES:
        raise ValueError('INPUT_SIZE_OR_TYPE')
    if _sha(raw) != expected_sha256:
        raise ValueError('INPUT_SHA256_MISMATCH')
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique,
                           parse_constant=_nonfinite, parse_float=_float)
    except UnicodeDecodeError as error:
        raise ValueError('INPUT_UTF8') from error
    except json.JSONDecodeError as error:
        raise ValueError('INPUT_JSON') from error
    except RecursionError as error:
        raise ValueError('INPUT_JSON_DEPTH') from error
    if type(value) is not dict or value.get('schema') != INPUT_SCHEMA:
        raise ValueError('CAMPAIGN_SCHEMA')
    topologies = value.get('topologies')
    if (type(topologies) is not list or len(topologies) != len(TOPOLOGIES)
            or any(type(row) is not dict or type(row.get('planned_receivers')) is not int
                   or row['planned_receivers'] != size
                   for row, size in zip(topologies, TOPOLOGIES))):
        raise ValueError('TOPOLOGY_DENOMINATOR_EXPECTED_1_2_4')
    if any(type(row.get('workers')) is not list for row in topologies):
        raise ValueError('TOPOLOGY_WORKERS_MALFORMED')
    return value


def _checker_identity():
    return {
        'source': 'formal/pon-nakamoto-v1/grouped_fresh_deployment_cost_v0.py',
        'source_sha256': _sha(Path(accounting.__file__).read_bytes()),
        'reanalysis_source': 'formal/pon-nakamoto-v1/experiments/reanalyze_grouped_fanout_v1.py',
        'reanalysis_source_sha256': _sha(Path(__file__).read_bytes()),
        'python_version': sys.version,
    }


def _retained_inventory_issues(value, fields):
    issues = []
    for field in fields:
        rows = value.get(field)
        if type(rows) is not list:
            issues.append('ORIGINAL_' + field.upper() + '_UNAVAILABLE')
        elif rows:
            issues.append('ORIGINAL_' + field.upper() + '_RETAINED')
    return issues


def reanalyze(raw, *, expected_sha256):
    """Pure report transformation from exact bytes; old accounting is not input authority.

    All three precommitted topologies must be present in order. An old failure
    is retained for its owner's disposition even if the new arithmetic passes.
    Nothing here rereads original packet files, reruns source checks, or creates
    new demand, verification quota, payment or security-work qualification.
    """
    original = _parse_pinned(raw, expected_sha256)
    checker = _checker_identity()
    issues = _retained_inventory_issues(original, ('failures', 'not_started_topologies'))
    old_status = original.get('status')
    if old_status != 'PASS':
        issues.append('ORIGINAL_CAMPAIGN_NOT_PASS')
    for field, expected in QUALIFICATION_BOUNDARIES.items():
        observed = original.get(field)
        if type(observed) is not type(expected) or observed != expected:
            issues.append('ORIGINAL_QUALIFICATION_BOUNDARY_' + field.upper())
    if original.get('all_receptions_are_not_independent_tickets') is not True:
        issues.append('ORIGINAL_TICKET_REUSE_BOUNDARY_UNAVAILABLE')
    try:
        expected_work_ids = accounting.produced_work_ids(original.get('produced'))
    except ValueError as error:
        issues.append('ORIGINAL_' + str(error))
        # An explicit invalid map makes each accounting result incomplete while
        # retaining its costs. Never infer expected IDs from receiver claims.
        expected_work_ids = {}
    topologies = []
    new_failures = []
    for size, row in zip(TOPOLOGIES, original['topologies']):
        old_accounting = row.get('accounting')
        old_topology_status = old_accounting.get('status') if type(old_accounting) is dict else None
        # The denominator comes from this reader's fixed plan and the raw row,
        # never from the old accounting's counters, status or issue list.
        checked = accounting.topology_accounting(size, row['workers'],
                                                expected_work_ids=expected_work_ids)
        retained = _retained_inventory_issues(row, ('orchestration_failures', 'unstarted_clients'))
        if old_topology_status != 'PASS':
            retained.append('ORIGINAL_TOPOLOGY_NOT_PASS')
        for index, worker in enumerate(row['workers']):
            if type(worker) is not dict or worker.get('raw_readback_passed') is not True:
                retained.append(f'ORIGINAL_RECEIVER_{index}_READBACK_NOT_PASS')
        new_status = 'PASS' if checked['status'] == 'PASS' and not retained else 'FAIL'
        topologies.append({
            'planned_receivers': size,
            'raw_worker_count': len(row['workers']),
            'old_status': old_topology_status,
            'new_status': new_status,
            'status_changed': old_topology_status != new_status,
            'old_accounting': old_accounting,
            'new_accounting': checked,
            'retained_gate_issues': retained,
            'original_topology_metadata': {k: v for k, v in row.items()
                                           if k not in ('workers', 'accounting')},
        })
        if new_status == 'FAIL':
            issues.append(f'TOPOLOGY_{size}_NOT_PASS')
            if old_topology_status == 'PASS':
                new_failures.append({'planned_receivers': size,
                                     'accounting_issues': checked['issues'],
                                     'retained_gate_issues': retained})
    if checker != _checker_identity():
        raise ValueError('CHECKER_SOURCE_CHANGED_DURING_REANALYSIS')
    status = 'PASS' if not issues else 'FAIL'
    return {
        'schema': SCHEMA,
        'status': status,
        'old_status': old_status,
        'new_status': status,
        'status_changed': old_status != status,
        'input_sha256': expected_sha256,
        'input_bytes': len(raw),
        'external_input_pin_checked': True,
        'checker': checker,
        'scope': 'Offline cost reanalysis of pinned historical report bytes; no workload or original raw-file replay.',
        'checker_hash_scope': 'Accounting implementation and this replay reader, not a rebuilt native executable or full dependency closure.',
        'original_metadata_is_retained_observation_not_reauthenticated': True,
        'original_metadata': {k: v for k, v in original.items() if k != 'topologies'},
        'topology_denominator': list(TOPOLOGIES),
        'planned_receiver_slots': sum(TOPOLOGIES),
        'planned_transport_attempts': sum(TOPOLOGIES) * len(accounting.CASES),
        'topologies': topologies,
        'issues': issues,
        'new_failures': new_failures,
        'originals_modified': False,
        'new_experiment_executed': False,
        'source_and_binary_checks_reexecuted': False,
        'original_transport_files_reread': False,
        'qualification_status': 'HOLD',
        **QUALIFICATION_BOUNDARIES,
    }


def _read_bounded(path):
    with Path(path).open('rb') as stream:
        raw = stream.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError('INPUT_SIZE_OR_TYPE')
    return raw


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--expected-sha256', required=True)
    parser.add_argument('--out', type=Path, help='Create a new report; an existing path is refused.')
    args = parser.parse_args(argv)
    try:
        raw = _read_bounded(args.input)
        result = reanalyze(raw, expected_sha256=args.expected_sha256)
        if _read_bounded(args.input) != raw:
            raise ValueError('INPUT_CHANGED_DURING_REANALYSIS')
        result['input_path'] = str(args.input.resolve())
        result['input_unchanged_after_reanalysis'] = True
        encoded = json.dumps(result, sort_keys=True, indent=2, allow_nan=False) + '\n'
        if args.out is None:
            print(encoded, end='')
        else:
            with args.out.open('x', encoding='utf-8') as stream:
                stream.write(encoded)
            print(json.dumps({'schema': SCHEMA, 'status': result['status'],
                              'input_sha256': result['input_sha256'], 'out': str(args.out),
                              'topology_statuses': [[t['planned_receivers'], t['old_status'], t['new_status']]
                                                    for t in result['topologies']],
                              'new_failures': result['new_failures']}, sort_keys=True))
        return 0 if result['status'] == 'PASS' else 1
    except FileExistsError:
        print(json.dumps({'status': 'REJECTED', 'error': 'OUTPUT_ALREADY_EXISTS'}), file=sys.stderr)
        return 2
    except (ValueError, OSError) as error:
        print(json.dumps({'status': 'REJECTED', 'error': str(error)}), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())

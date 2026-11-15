#!/usr/bin/env python3
"""Check all 58 saved-v2 control observations and their retained identities.

This gate never executes a verifier or creates a proof. It checks consistency
of the runner's saved evidence, including the actual positive report. The CLI
binds paths and the verifier hash to the current CI run. Explicit recorded paths
in validate() also permit offline review of relocated historical evidence; that
review does not authenticate its execution or attest compilation.
"""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import w1_v2_receipt_controls as controls

ASSETS = (('receipt', 'succinct.bin'), ('header', 'header.bin'),
          ('artifacts', 'expected-artifacts.bin'))
OBSERVATION_FIELDS = {'passed', 'returncode', 'timed_out', 'panic_or_abort_detected',
                      'stdout_scan_truncated', 'stderr_scan_truncated',
                      'observed_rejection_layers', 'report_error', 'process', 'case_directory'}
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_LOG_BYTES = 4 * 1024 * 1024
HISTORICAL_STAGE_SCHEMA = 'TRNM-W1-STAGE-MEASUREMENT2'
CURRENT_STAGE_SCHEMA = 'TRNM-W1-STAGE-MEASUREMENT3'


def read_json(path):
    return controls.strict_json(controls.bounded(path, MAX_JSON_BYTES))


def require_fields(row, expected, context):
    controls.require(type(row) is dict, f'{context} must be an object')
    for key, value in expected.items():
        controls.require(key in row and type(row[key]) is type(value) and row[key] == value,
                         f'{context} differs: {key}')


def validate_process_observation(process, code, stage_schema=CURRENT_STAGE_SCHEMA):
    """Select one explicit schema; current CLI observations cannot downgrade to v2."""
    controls.require(type(stage_schema) is str and stage_schema in
                     (HISTORICAL_STAGE_SCHEMA, CURRENT_STAGE_SCHEMA),
                     'unsupported process observation version')
    require_fields(process, {
        'schema': stage_schema, 'returncode': code, 'timed_out': False,
        'completion_observed_before_deadline': True, 'termination_reasons': [], 'error': None,
        'owned_session_observation_complete': True, 'proc_scan_errors': [],
        'group_probe_errors': [], 'cleanup_errors': [], 'members_after_child_exit': [],
        'final_owned_session_members': [], 'process_group_remaining_after_child_exit': False,
        # A clean expected rejection is a nonzero stage exit, not a failed control.
        'stage_process_complete': code == 0, 'wall_limit_seconds': 120,
    }, 'process observation')
    if stage_schema == CURRENT_STAGE_SCHEMA:
        require_fields(process, {
            'cancellation_schema': 'TRNM-W1-CANCELLATION-HANDOFF1',
            'result_is_pre_handoff_snapshot': True,
            'canceled_signal': None, 'cancellation_event': None,
            'deadline_exhausted_at_snapshot': False,
            'prover_resource_completeness_established': False, 'complete_proof_claim': False,
        }, 'current process observation')
        for name in ('started_monotonic', 'wall_seconds', 'effective_deadline_monotonic',
                     'effective_remaining_seconds'):
            value = process.get(name)
            controls.require(type(value) in (int, float) and math.isfinite(value)
                             and value > 0, f'current process clock differs: {name}')
        started, wall, deadline, remaining = (process[name] for name in (
            'started_monotonic', 'wall_seconds', 'effective_deadline_monotonic',
            'effective_remaining_seconds'))
        # Use the producer's absolute endpoint arithmetic. Subtracting the
        # same finite endpoints can round the remaining duration above 120.
        controls.require(0 < remaining and deadline <= started + 120
                         and remaining == deadline - started
                         and started + wall < deadline,
                         'current process exceeds its original deadline')
    groups, pid = process['known_owned_groups'], process.get('pid')
    controls.require(type(groups) is list and groups
                     and all(type(group) is int and group > 0 for group in groups)
                     and groups == sorted(set(groups))
                     and type(pid) is int and pid > 0 and pid in groups
                     and process['final_known_group_probes'] ==
                     [{'group': group, 'state': 'ABSENT'} for group in groups]
                     and all(type(probe['group']) is int for probe in process['final_known_group_probes']),
                     'owned process groups were not all observed absent')


def validate(out, proof, *, verifier_path, verifier_sha256, recorded_out=None,
             stage_schema=HISTORICAL_STAGE_SCHEMA):
    """Validate retained evidence; default v2 preserves the original historical fixture.

    The current CLI selects v3 explicitly. Recorded paths are identities, never
    read or run. Neither version authenticates execution or claims qualification.
    """
    out, proof = Path(out), Path(proof)
    recorded_out = out.resolve() if recorded_out is None else Path(recorded_out)
    verifier_path = Path(verifier_path)
    controls.require(recorded_out.is_absolute() and verifier_path.is_absolute(),
                     'recorded output and verifier paths must be absolute')
    report = read_json(out / 'result.json')
    baseline = {key: controls.bounded(proof / name, controls.MAX_RECEIPT) for key, name in ASSETS}
    location = controls.locate_journal(baseline['receipt'], baseline['header'], baseline['artifacts'])
    plans = controls.plan_controls(baseline['receipt'], location)
    retained = read_json(proof / 'controls-result.json')['controls']
    cases = report['controls']
    controls.require(type(cases) is list and len(plans) == len(retained) == len(cases) == 58,
                     'all 58 original controls are required')
    controls.require(plans == [{key: value for key, value in row.items() if key not in OBSERVATION_FIELDS}
                              for row in retained], 'original control plan or required rejection text changed')
    require_fields(report, {
        'schema': 'TRNM-W1-V2-RECEIPT-CONTROLS1', 'profile_id': controls.PROFILE_ID,
        'total_wall_budget_seconds': 120, 'termination_settlement_adds_acceptance_budget': False,
        'planned_controls': 58, 'completed_controls': 58, 'positive_controls_passed': 1,
        'negative_controls_passed': 57, 'unexpected_acceptances': 0, 'panic_or_abort_count': 0,
        'timeout_count': 0, 'all_controls_passed': True, 'error': None, 'uncompleted_controls': [],
        'new_proofs_generated': 0, 'additional_work_tickets': 0, 'independent_proof_trials': 1,
        'quantum_security_qualified': False, 'consensus_admission': False,
        'parent_eligibility_checked': False, 'production_activation': False,
        'runner_sha256': controls.sha(Path(controls.__file__)), 'verifier_sha256': verifier_sha256,
        'journal_location': location,
    }, 'v2 controls summary')
    elapsed = report['elapsed_wall_seconds']
    controls.require(type(elapsed) in (int, float) and 0 < elapsed < 120,
                     'common 120-second deadline exceeded')
    if stage_schema == CURRENT_STAGE_SCHEMA:
        for name in ('started_monotonic', 'deadline_monotonic'):
            value = report.get(name)
            controls.require(type(value) in (int, float) and math.isfinite(value)
                             and value > 0, f'current common clock differs: {name}')
        controls.require(report['deadline_monotonic'] == report['started_monotonic'] + 120,
                         'current common deadline was extended')
    require_fields(read_json(out / 'identity.json'), {
        'verifier_path': str(verifier_path), 'verifier_sha256': verifier_sha256,
        'assets': {key: {'bytes': len(data), 'sha256': controls.digest(data)}
                   for key, data in baseline.items()},
        'journal_location': location,
    }, 'runner identity')
    controls.require(read_json(out / 'plan.json') == plans, 'saved control plan changed')
    for key, data in baseline.items():
        controls.require(controls.bounded(out / 'original' / f'{key}.bin', controls.MAX_RECEIPT) == data,
                         f'original input differs: {key}')
    for index, (plan, old, case) in enumerate(zip(plans, retained, cases)):
        for row in (old, case):
            require_fields(row, plan, 'original ordered control or expectation')
        case_name = f"{index:03}-{plan['name']}"
        require_fields(case, {
            'case_directory': case_name, 'passed': True, 'timed_out': False,
            'panic_or_abort_detected': False, 'report_error': None,
            'stdout_scan_truncated': False, 'stderr_scan_truncated': False,
        }, 'control observation')
        code, process = case['returncode'], case['process']
        controls.require(type(code) is int and (code == 0 if plan['expect'] == 'accept' else code > 0),
                         'control exit differs from expectation')
        validate_process_observation(process, code, stage_schema)
        if stage_schema == CURRENT_STAGE_SCHEMA:
            controls.require(process['effective_deadline_monotonic'] == report['deadline_monotonic']
                             and process['started_monotonic'] >= report['started_monotonic'],
                             'current process is outside the original common deadline')
            controls.require(process['started_monotonic'] + process['wall_seconds']
                             <= report['started_monotonic'] + elapsed,
                             'current summary does not cover process completion')
        case_dir = out / case_name
        controls.require(read_json(case_dir / 'result.json') == case,
                         'case result differs from aggregate observation')
        controls.require(read_json(case_dir / 'process/result.json') == process,
                         'retained process result differs from aggregate observation')
        mutated = controls.materialize(plan, baseline, location)
        expected_assets, command = {}, [str(verifier_path)]
        for key, data in mutated.items():
            relative = Path('original' if data == baseline[key] else case_name) / f'{key}.bin'
            path = str(recorded_out / relative)
            command.append(path)
            expected_assets[key] = {'bytes': len(data), 'sha256': controls.digest(data), 'path': path}
            controls.require(controls.bounded(out / relative, controls.MAX_RECEIPT) == data,
                             f'case input differs from planned mutation: {case_name}/{key}')
        controls.require(read_json(case_dir / 'mutation.json') == {**plan, 'assets': expected_assets},
                         'case mutation identity differs from planned inputs')
        controls.require(process['command'] == command, 'case command differs from pinned verifier and inputs')
        stdout = controls.bounded(case_dir / 'process/stdout.log', MAX_LOG_BYTES)
        stderr = controls.bounded(case_dir / 'process/stderr.log', MAX_LOG_BYTES)
        require_fields(process, {'stdout_sha256': controls.digest(stdout), 'stderr_sha256': controls.digest(stderr)},
                       'process output identity')
        controls.require(not controls.panic_or_abort(process, stdout + stderr), 'process output contains a panic or abort')
        layers = [name for name, marker in controls.LAYERS.items() if marker.encode() in stderr]
        controls.require(case['observed_rejection_layers'] == layers, 'recorded rejection layers differ from stderr')
        layer = plan.get('required_rejection_layer')
        controls.require(layer is None or layers == [layer], 'wrong rejection layer')
        if plan.get('required_error_text'):
            controls.require(plan['required_error_text'].encode() in stderr, 'required rejection text is absent')
        if plan['expect'] == 'accept':
            positive = controls.validate_positive(stdout, baseline, location)
            controls.require(positive == report['positive_report'], 'positive stdout differs from aggregate report')
    controls.validate_positive(json.dumps(report['positive_report']), baseline, location)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('out', type=Path)
    parser.add_argument('proof', type=Path)
    parser.add_argument('verifier', type=Path)
    args = parser.parse_args(argv)
    verifier = args.verifier.resolve(strict=True)
    validate(args.out, args.proof, verifier_path=verifier, verifier_sha256=controls.sha(verifier),
             stage_schema=CURRENT_STAGE_SCHEMA)
    print('All 58 original saved-v2 controls passed; no new proof or qualification is claimed.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

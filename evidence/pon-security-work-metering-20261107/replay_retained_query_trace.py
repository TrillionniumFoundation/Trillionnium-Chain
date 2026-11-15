#!/usr/bin/env python3
"""Reinspect the exact retained Python traces; do not reconstruct native queries.

This is a fixed-input evidence reproduction script, not a general authority
adapter. Ordering coordinates below are reader-assigned file ordinals. They do
not establish externally authenticated prequery task or target authorization.
The original native calls, controls and physical-cost gaps remain separately
identified; the selected Python trace is not a complete campaign denominator.
"""
import argparse
from collections import Counter
import gzip
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'formal/pon-nakamoto-v1'))
import grouped_work_profile_v1 as profile

REPORT_SHA = '3e18ebd0437320941f452e66088f49dedd1f71e3c747fb4d1965d85945285ac3'
TRACE_SHA = '16c761002daf687fa16086fe2966b89d0443bf2c7dafbd1fb8df55eaea082e3d'


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def read_pinned(path, expected):
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError('ORIGINAL_INPUT_SHA256:' + str(path))
    return raw


def write_json(path, value, compressed=False):
    raw = (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
    with path.open('xb') as stream:
        stream.write(gzip.compress(raw, mtime=0) if compressed else raw)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--trace', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    report = json.loads(read_pinned(args.report, REPORT_SHA))
    trace_raw = read_pinned(args.trace, TRACE_SHA)
    traces = [json.loads(line) for line in trace_raw.splitlines()]
    if report['profile'] != profile.PROFILE or len(traces) != 1088:
        raise ValueError('RETAINED_SOURCE_CONTRACT')
    original_candidates = {row['nonce']: row for row in report['freeze']['candidates']}
    attempts = {row['nonce']: row for row in report['attempts']}
    outsider = next(row for row in report['controls']
                    if row['control'] == 'valid_without_native_producer_journal')
    outsider_observation = outsider['response']['native_verification']['observation']
    bindings = {n: (row['challenge'], row['statement']) for n, row in attempts.items()}
    bindings[17] = (outsider_observation['challenge'], outsider_observation['statement'])
    task = report['material']['provenance']['selected_tasks']['content_root']
    material = report['legal_preparation']['product_sha256']
    target = report['freeze']['branch']['target']
    grouped = Counter((row['nonce'], row['owner']) for row in traces)
    allowed = {'independent_python_crosscheck': 'helper',
               'independent_untrusted_producer': 'producer'}
    policy = dict(schema=profile.POLICY_SCHEMA, campaign=REPORT_SHA,
        profile=profile.PROFILE, denomination=profile.DENOMINATION,
        actors=[dict(id=name, control_group='same-controlled-fixture') for name in
                ('historical-runner', 'historical-task-policy', 'historical-node-policy')],
        candidates=[], demands=[], operations=[])
    evidence = dict(schema=profile.EVIDENCE_SCHEMA, policy_sha256=None,
                    queries=[], terminals=[], uses=[], costs=[])
    operation_ids = {}
    deadline = len(traces) + 10
    for nonce, owner in sorted(grouped):
        if owner not in allowed or nonce not in bindings or grouped[nonce, owner] != 64:
            raise ValueError('UNEXPECTED_OR_INCOMPLETE_TRACE_GROUP')
        original = original_candidates[nonce]
        challenge, statement = bindings[nonce]
        if original['challenge'] != challenge:
            raise ValueError('CANDIDATE_CHALLENGE')
        candidate = original['work_id']
        operation = digest('retained-python-operation:' + TRACE_SHA + ':' + str(nonce) + ':' + owner)
        operation_ids[nonce, owner] = operation
        policy['candidates'].append(dict(id=candidate, task=task, material=material,
            challenge=challenge, statement=statement, target=target,
            task_authority='historical-task-policy', target_authority='historical-node-policy',
            authorized_at=0, expires_at=deadline))
        policy['operations'].append(dict(id=operation, actor='historical-runner',
            role=allowed[owner], candidates=[candidate], authorized_at=0, deadline=deadline,
            required_costs=[dict(stage='python_step_observation', unit=unit)
                            for unit in ('step_query', 'cpu_ns', 'wall_ns')]))
        evidence['terminals'].append(dict(id=operation, at=len(traces) + 1, outcome='completed',
            receipt_sha256=TRACE_SHA, carrier_sha256=TRACE_SHA))
        measured = attempts.get(nonce, {}).get('independent_python_seal_and_trace', {})
        # The outsider's reported CPU includes binding and encoding; it is not a
        # measured seal-only span, so no fabricated phase attribution is made.
        amounts = {'step_query': 64, 'cpu_ns': measured.get('thread_cpu_ns'),
                   'wall_ns': measured.get('wall_ns')}
        for unit, amount in amounts.items():
            evidence['costs'].append(dict(id=digest(operation + ':cost:' + unit),
                operation=operation, stage='python_step_observation', unit=unit,
                amount=amount, upper_bound=None, meter='historical-runner', payer=None,
                beneficiary=None, receipt_sha256=TRACE_SHA if unit == 'step_query' else REPORT_SHA,
                coverage=[digest(operation + ':coverage:' + unit)], included_in=None,
                carrier_sha256=REPORT_SHA))
    for ordinal, row in enumerate(traces, 1):
        nonce, owner = row['nonce'], row['owner']
        raw = bytes.fromhex(row['input_hex'])
        candidate_id = original_candidates[nonce]['work_id']
        candidate = next(c for c in policy['candidates'] if c['id'] == candidate_id)
        if raw != profile._step_input(candidate, row['index'], raw[-32:]):
            raise ValueError('RETAINED_NATIVE_PREIMAGE')
        evidence['queries'].append(dict(id=digest(TRACE_SHA + ':line:' + str(ordinal)),
            operation=operation_ids[nonce, owner], candidate=candidate_id, at=ordinal,
            index=row['index'], predecessor=raw[-32:].hex(), answer=row['output_hex'],
            carrier_sha256=TRACE_SHA))
    evidence['policy_sha256'] = profile.policy_digest(policy)
    assessment = profile.assess(evidence, expected_policy=policy,
                                expected_policy_sha256=evidence['policy_sha256'])
    provenance = dict(schema='pon-retained-python-query-reinspection-v1',
        original_report_sha256=REPORT_SHA, original_trace_sha256=TRACE_SHA,
        original_source_commit=report['expected_source_sha'],
        inspector_source_sha256=hashlib.sha256(Path(profile.__file__).read_bytes()).hexdigest(),
        original_planned_primary_attempts=report['planned_primary_attempts'],
        original_actual_primary_attempts=report['actual_primary_attempts'],
        original_control_rows=len(report['controls']),
        original_control_counts=dict(sorted(Counter(r['control'] for r in report['controls']).items())),
        all_retained_python_trace_rows=len(traces), omitted_retained_python_trace_rows=0,
        reader_assigned_order_coordinates=True, authenticated_original_clock=False,
        policy_source='declared original frozen report; not independent issuer authentication',
        scope='exact retained Python step observations only; not all native or campaign work',
        excluded_but_retained_scope=list(report['cost_scope']),
        native_and_control_queries_reconstructed_as_observations=False,
        physical_costs_of_this_inspection_in_original_measurement=False,
        genuinely_independent_demand=False, actual_chainwork=0)
    args.out.mkdir(parents=True, exist_ok=False)
    write_json(args.out / 'expected-policy.json', policy)
    write_json(args.out / 'observations.json.gz', evidence, compressed=True)
    write_json(args.out / 'assessment.json', assessment)
    write_json(args.out / 'provenance.json', provenance)
    print(json.dumps(dict(qualification=assessment['qualification'],
        observed_events=assessment['queries']['observed_execution_events'],
        distinct_inputs=assessment['queries']['distinct_native_inputs'],
        complete_seals=len(assessment['queries']['complete_seal_traces']),
        local_issues=len(assessment['local_issues']),
        external_obligations=len(assessment['unresolved_predicates'])), sort_keys=True))


if __name__ == '__main__':
    main()

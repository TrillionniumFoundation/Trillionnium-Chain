"""Bound operations acceptance sidecar over the existing target-model evaluator.

Checks supplied records, not their physical origin. There is deliberately no path
from self-reported identities/timestamps/results to independent acceptance.
"""
from __future__ import annotations
import hashlib
from fractions import Fraction
from contract_wire import H, canonical
from llm_adapter_contract import (closed, digest, integer, require, freeze, decode,
                                 evaluate_run_record, validate_run_plan, CONTROL_IDS)

DOMAIN = 'model-operations-preregistration-v1'
PROBES = ('poison', 'backdoor', 'forgetting')
EXTERNAL = ('preregistration-custody', 'future-task-custody', 'material-license-consent',
            'independent-operator-reviewer', 'authenticated-runtime-consumer',
            'retention-availability', 'evaluator-governance-appeal')
MAX = (1 << 63)-1


def count(value, lo=0):
    return integer(value, lo, MAX, 'ACCEPTANCE_INTEGER')


def identity(value):
    return H(DOMAIN, canonical(value)).hex()


def validate_preregistration(value):
    closed(value, 'schema run_plan registered_at release_after closes_at minimum_gain_ppm '
           'max_probe_regressions max_retention_byte_seconds min_consumer_operations '
           'training_groups future_groups probes material_roots material_bindings owner operator reviewer '
           'governance retention_until evidence scope', 'ACCEPTANCE_PLAN_FIELDS')
    require(value['schema'] == 'pon-model-operations-preregistration-v1' and
            value['scope'] == 'reported-record-gates-only-no-independent-acceptance', 'ACCEPTANCE_PLAN_SCOPE')
    for field in ('run_plan', 'owner', 'operator', 'reviewer', 'governance'):
        digest(value[field])
    require(len({value[k] for k in ('owner', 'operator', 'reviewer')}) == 3,
            'ACCEPTANCE_DECLARED_ROLE_ALIAS')
    for field in ('registered_at', 'release_after', 'closes_at', 'retention_until'):
        count(value[field], 1)
    require(value['registered_at'] < value['release_after'] < value['closes_at'] <= value['retention_until'],
            'ACCEPTANCE_CHRONOLOGY')
    integer(value['minimum_gain_ppm'], 1, 1000000, 'ACCEPTANCE_GAIN')
    count(value['max_probe_regressions']); count(value['max_retention_byte_seconds'], 1)
    integer(value['min_consumer_operations'], 1, 32768, 'ACCEPTANCE_CONSUMER_MIN')
    for field in ('training_groups', 'future_groups', 'material_roots'):
        rows = value[field]
        require(type(rows) is list and 1 <= len(rows) <= 32768, 'ACCEPTANCE_SET')
        for row in rows: digest(row)
        require(rows == sorted(set(rows)), 'ACCEPTANCE_SET_ORDER')
    require(type(value['material_bindings']) is dict and set(value['material_bindings']) ==
            {'candidate', *CONTROL_IDS, 'backbone', 'tokenizer', 'task-data'}, 'ACCEPTANCE_MATERIAL_ROLES')
    for root in value['material_bindings'].values(): digest(root)
    require(set(value['material_bindings'].values()) == set(value['material_roots']), 'ACCEPTANCE_MATERIAL_ROLES')
    require(not set(value['training_groups']) & set(value['future_groups']), 'ACCEPTANCE_GROUP_LEAKAGE')
    probes = value['probes']
    require(type(probes) is list and 3 <= len(probes) <= 32768, 'ACCEPTANCE_PROBES')
    seen = set(); kinds = set()
    for probe in probes:
        closed(probe, 'id kind prompt target', 'ACCEPTANCE_PROBE_FIELDS')
        for field in ('id', 'prompt', 'target'): digest(probe[field])
        require(type(probe['kind']) is str and probe['kind'] in PROBES, 'ACCEPTANCE_PROBE_KIND')
        require(probe['id'] not in seen, 'ACCEPTANCE_PROBE_REPLAY')
        seen.add(probe['id']); kinds.add(probe['kind'])
    require(kinds == set(PROBES), 'ACCEPTANCE_PROBE_COVERAGE')
    require(len({p['prompt'] for p in probes}) == len(probes), 'ACCEPTANCE_PROBE_CONTENT_ALIAS')
    evidence = value['evidence']
    require(type(evidence) is dict and set(evidence) == set(EXTERNAL), 'ACCEPTANCE_EVIDENCE_SET')
    for root in evidence.values(): digest(root)


def freeze_preregistration(value, plan, expected_plan):
    validate_run_plan(plan)
    require(freeze(plan, validate_run_plan, 'target-decoder-evaluation-run-plan-v1')[1] == expected_plan,
            'ACCEPTANCE_RUN_PLAN')
    validate_preregistration(value)
    require(value['run_plan'] == expected_plan, 'ACCEPTANCE_RUN_PLAN')
    groups = {t['source_group'] for t in plan['tasks'] if t['partition'] == 'evaluation'}
    calibration = {t['source_group'] for t in plan['tasks'] if t['partition'] == 'calibration'}
    require(groups == set(value['future_groups']) and not groups & calibration,
            'ACCEPTANCE_FUTURE_PARTITION_LEAKAGE')
    require(not {p['prompt'] for p in value['probes']} & {t['prompt_sha256'] for t in plan['tasks']},
            'ACCEPTANCE_PROBE_TASK_LEAKAGE')
    return freeze(value, validate_preregistration, DOMAIN)


def verify_acceptance(preregistration_raw, expected_preregistration, plan, expected_plan,
                      record, receipt, material):
    """Replay all supplied obligations and return explicit unresolved authority gates.

    material maps SHA256 to actual bounded bytes (including external owner evidence).
    Pin expected_preregistration outside the submitted receipt. Matching hashes alone
    do not prove preregistration time, source independence, licenses or physical use.
    """
    prereg = decode(preregistration_raw, expected_preregistration, validate_preregistration, DOMAIN)
    require(freeze_preregistration(prereg, plan, expected_plan)[0] == preregistration_raw,
            'ACCEPTANCE_PREREGISTRATION')
    assessment = evaluate_run_record(plan, record, expected_plan)
    closed(receipt, 'schema preregistration run_record observed_at task_released_at '
           'probes consumers retention evidence scope', 'ACCEPTANCE_RECEIPT_FIELDS')
    require(receipt['schema'] == 'pon-model-operations-reported-receipt-v1' and
            receipt['scope'] == prereg['scope'], 'ACCEPTANCE_RECEIPT_SCOPE')
    require(receipt['preregistration'] == expected_preregistration and
            receipt['run_record'] == assessment['record'], 'ACCEPTANCE_RECEIPT_BINDING')
    count(receipt['observed_at'], 1); count(receipt['task_released_at'], 1)
    require(prereg['release_after'] <= receipt['task_released_at'] <= receipt['observed_at'] <= prereg['closes_at'],
            'ACCEPTANCE_OBSERVATION_CHRONOLOGY')
    require(receipt['evidence'] == prereg['evidence'], 'ACCEPTANCE_EVIDENCE_SUBSTITUTION')
    require(type(material) is dict and 1 <= len(material) <= 65536, 'ACCEPTANCE_MATERIAL_SET')
    required = set(prereg['material_roots']) | set(prereg['evidence'].values())
    require(set(material) == required, 'ACCEPTANCE_MATERIAL_SET')
    require(sum(len(raw) for raw in material.values() if type(raw) is bytes) <= 16*1024*1024,
            'ACCEPTANCE_MATERIAL_LIMIT')
    for root, raw in material.items():
        digest(root)
        require(type(raw) is bytes and len(raw) > 0 and hashlib.sha256(raw).hexdigest() == root,
                'ACCEPTANCE_MATERIAL_BINDING')

    expected_models = {'candidate': plan['candidate'], **{c['id']: c['artifact'] for c in plan['controls']}}
    probes = receipt['probes']; require(type(probes) is list and len(probes) == len(prereg['probes']), 'ACCEPTANCE_PROBE_SET')
    regressions = dict.fromkeys(PROBES, 0)
    for row, probe in zip(probes, prereg['probes']):
        closed(row, 'id outputs', 'ACCEPTANCE_PROBE_RESULT_FIELDS')
        require(row['id'] == probe['id'] and type(row['outputs']) is dict and set(row['outputs']) == set(expected_models),
                'ACCEPTANCE_PROBE_CONTEXT')
        for output in row['outputs'].values(): digest(output)
        # Candidate must preserve any success achieved by any frozen strong control.
        if row['outputs']['candidate'] != probe['target'] and any(row['outputs'][c] == probe['target'] for c in CONTROL_IDS):
            regressions[probe['kind']] += 1

    consumers = receipt['consumers']
    require(type(consumers) is list and len(consumers) <= 32768, 'ACCEPTANCE_CONSUMERS')
    operations = set(); outputs = set()
    evaluation = {t['id']: t for t in plan['tasks'] if t['partition'] == 'evaluation'}
    runs = record['participants'][0]['runs']
    for row in consumers:
        closed(row, 'operation consumer task candidate seed output used_at', 'ACCEPTANCE_CONSUMER_FIELDS')
        for field in ('operation', 'consumer', 'task', 'candidate', 'output'): digest(row[field])
        require(row['operation'] not in operations, 'ACCEPTANCE_CONSUMER_REPLAY')
        operations.add(row['operation'])
        require(row['consumer'] not in {prereg[k] for k in ('owner', 'operator', 'reviewer')}, 'ACCEPTANCE_CONSUMER_ROLE_ALIAS')
        require(row['candidate'] == plan['candidate'] and row['task'] in evaluation,
                'ACCEPTANCE_CONSUMER_CONTEXT')
        count(row['seed']); count(row['used_at'], 1)
        require(row['seed'] in plan['seeds'] and receipt['task_released_at'] <= row['used_at'] <= receipt['observed_at'],
                'ACCEPTANCE_CONSUMER_CHRONOLOGY')
        output = runs[plan['seeds'].index(row['seed'])]['outputs'][row['task']]
        require(row['output'] == output == evaluation[row['task']]['target_output_sha256'], 'ACCEPTANCE_CONSUMER_OUTPUT')
        outputs.add((evaluation[row['task']]['prompt_sha256'], row['output']))

    retention = receipt['retention']
    require(type(retention) is list and len(retention) == len(prereg['material_roots']), 'ACCEPTANCE_RETENTION_SET')
    seen = set(); byte_seconds = 0; repair_bytes = 0
    for row in retention:
        closed(row, 'root bytes copies starts_at ends_at retrieved_sha256 retrieved_at repair_bytes', 'ACCEPTANCE_RETENTION_FIELDS')
        digest(row['root']); digest(row['retrieved_sha256'])
        require(row['root'] in prereg['material_roots'] and row['root'] not in seen, 'ACCEPTANCE_RETENTION_REPLAY')
        seen.add(row['root'])
        for field in ('bytes', 'copies', 'starts_at', 'ends_at', 'retrieved_at'): count(row[field], 1)
        count(row['repair_bytes'])
        require(row['bytes'] == len(material[row['root']]) and row['retrieved_sha256'] == row['root'], 'ACCEPTANCE_DA_BYTES')
        require(row['starts_at'] <= prereg['registered_at'] and row['ends_at'] >= prereg['retention_until'] and
                row['starts_at'] <= row['retrieved_at'] <= receipt['observed_at'], 'ACCEPTANCE_RETENTION_WINDOW')
        byte_seconds += row['bytes']*row['copies']*(row['ends_at']-row['starts_at'])
        repair_bytes += row['repair_bytes']
        require(max(byte_seconds, repair_bytes) <= MAX, 'ACCEPTANCE_RETENTION_OVERFLOW')

    gain = Fraction(*map(int, assessment['gain_vs_strongest_evaluation_control']))
    gates = {'reported_gain': gain >= Fraction(prereg['minimum_gain_ppm'], 1000000),
             'adversarial_nonregression': max(regressions.values()) <= prereg['max_probe_regressions'],
             'reported_consumer_use': len(outputs) >= prereg['min_consumer_operations'],
             'complete_gpu_cost': assessment['gpu_cost_complete'],
             'retention_budget': byte_seconds <= prereg['max_retention_byte_seconds']}
    return {'schema': 'pon-model-operations-assessment-v1', 'preregistration': expected_preregistration,
            'receipt': H('model-operations-reported-receipt-v1', canonical(receipt)).hex(),
            'run_assessment': assessment, 'reported_gates': gates, 'probe_regressions': regressions,
            'unique_reported_uses': len(outputs), 'reported_retention_byte_seconds': byte_seconds,
            'reported_repair_bytes': repair_bytes, 'material_relationship_verified': False,
            'full_model_retention_cost_complete': False, 'complete_model_retention_byte_seconds': None,
            'external_gates_unverified': list(EXTERNAL),
            'reported_gates_passed': all(gates.values()), 'prospective_accepted': False,
            'independent_accepted': False, 'public_reward_eligible': False, 'production_activation': False}

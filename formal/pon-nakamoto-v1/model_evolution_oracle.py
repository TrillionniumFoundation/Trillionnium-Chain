"""Independent ILF3/ILM3, context and bounded-graph oracle.

This does not call Rust, accept producer scores, authenticate a chain, or establish
future model benefit. Fixed public rows deliberately supply reproducible mechanics.
"""
from __future__ import annotations
import json
import struct
from pathlib import Path
from contract_wire import H, canonical, read_config

PROFILE = 'linear-model-evolution-dev-v5'
ROWS, COLUMNS, MATRICES = 3, 257, 5
COEFFICIENTS = ROWS * COLUMNS * MATRICES
EMPIRICAL = read_config('config/pon/model-evidence-v3.json')


def require(condition, error):
    if not condition:
        raise ValueError(error)


def coefficients(values):
    require(len(values) == COEFFICIENTS, 'FACTOR_MODEL_LENGTH')
    require(all(type(v) is int and -32767 <= v <= 32767 for v in values), 'FACTOR_MODEL_RANGE')
    return tuple(values)


def encode_model(family, values, mask):
    require(type(family) is bytes and len(family) == 32, 'FACTOR_MODEL_CONTEXT')
    require(type(mask) is int and 1 <= mask <= 7, 'EVOLUTION_GRAPH')
    values = coefficients(values)
    return (b'ILM3' + struct.pack('<H', 3) + family + struct.pack('<4HBB', 1024, 3, 257, 3, mask, 0)
            + struct.pack('<' + 'h' * COEFFICIENTS, *values))


def decode_model(raw, family):
    require(len(raw) == 7758, 'FACTOR_MODEL_LENGTH')
    require(raw[:6] == b'ILM3\x03\x00', 'FACTOR_MODEL_VERSION')
    require(raw[6:38] == family and raw[38:46] == struct.pack('<4H', 1024, 3, 257, 3)
            and raw[47] == 0, 'FACTOR_MODEL_CONTEXT')
    values = coefficients(struct.unpack('<' + 'h' * COEFFICIENTS, raw[48:]))
    require(encode_model(family, values, raw[46]) == raw, 'FACTOR_MODEL_CANONICAL')
    return values, raw[46]


def artifact(family, values, mask):
    return H('integer-linear-model-artifact-v3', encode_model(family, values, mask))


def checked_operations(operations):
    require(isinstance(operations, list) and len(operations) <= 3, 'EVOLUTION_ENCODING')
    targets = [operation['target'] for operation in operations]
    require(all(type(v) is int and 0 <= v < 5 for v in targets)
            and targets == sorted(set(targets)), 'EVOLUTION_ENCODING')
    require(sum(operation['rank'] for operation in operations) <= 3, 'EVOLUTION_ENCODING')
    for operation in operations:
        rank, values = operation['rank'], operation['factors']
        require(type(rank) is int and 1 <= rank <= 2 and len(values) == (ROWS + COLUMNS) * rank
                and all(type(v) is int and -32767 <= v <= 32767 for v in values), 'EVOLUTION_ENCODING')
    return operations


def derive(parent, parent_mask, mask, operations):
    require(type(mask) is int and 1 <= mask <= 7, 'EVOLUTION_GRAPH')
    result = list(coefficients(parent))
    for operation in checked_operations(operations):
        target, rank, factors = operation['target'], operation['rank'], operation['factors']
        b = [factors[row * rank:(row + 1) * rank] for row in range(ROWS)]
        a = [factors[ROWS * rank + k * COLUMNS:ROWS * rank + (k + 1) * COLUMNS] for k in range(rank)]
        normal = [sum(left * right for left, right in zip(b_row, column))
                  for b_row in b for column in zip(*a)]
        require(all(-32767 <= value <= 32767 for value in normal), 'EVOLUTION_DELTA_RANGE')
        require(any(normal), 'EVOLUTION_NOOP_OPERATION')
        offset = target * ROWS * COLUMNS
        updated = [value + delta for value, delta in zip(result[offset:offset + ROWS * COLUMNS], normal)]
        require(all(-32767 <= value <= 32767 for value in updated), 'EVOLUTION_MODEL_RANGE')
        result[offset:offset + ROWS * COLUMNS] = updated
    require(result != list(parent) or mask != parent_mask, 'EVOLUTION_NOOP')
    return tuple(result)


def predictions(values, mask, rows):
    values = coefficients(values)
    require(type(mask) is int and 1 <= mask <= 7, 'EVOLUTION_GRAPH')
    enabled = [slot for slot in range(3) if mask & (1 << slot)]
    matrices = [values[i * 771:(i + 1) * 771] for i in range(5)]
    result = []
    for features in rows:
        require(len(features) == COLUMNS and all(type(x) is int and -8 <= x <= 8 for x in features)
                and features[-1] == 8, 'MODEL_EVIDENCE_TASK')
        def logits(matrix):
            return [sum(w * x for w, x in zip(matrix[i * COLUMNS:(i + 1) * COLUMNS], features))
                    for i in range(ROWS)]
        router = logits(matrices[1])
        slot = max(enabled, key=router.__getitem__)
        output = [a + b for a, b in zip(logits(matrices[0]), logits(matrices[2 + slot]))]
        result.append(max(range(3), key=output.__getitem__))
    return result


def correct(values, mask):
    tasks = EMPIRICAL['tasks']
    return sum(prediction == task['label'] for prediction, task in zip(
        predictions(values, mask, [task['features'] for task in tasks]), tasks))


def context():
    params = read_config('config/pon/devnet-v1.json')
    quorum = read_config('config/pon/public-evaluation-model-evolution-v5.json')
    policy = read_config('config/pon/model-evolution-v5.json')
    family_registry = read_config('config/pon/model-family-evolution-v3.json')
    params.update(quorum['genesis_overrides'])
    params['evaluation_policy_hash'] = H('evaluation-policy', canonical(quorum)).hex()
    params['chain_label'] += '-evaluation-storage3-' + PROFILE
    params['model_profile'] = PROFILE
    params['model_evidence_policy_hash'] = H('native-model-evidence-policy-v3', canonical(EMPIRICAL)).hex()
    params['model_evidence_tasks_hash'] = H('native-model-evidence-tasks-v3', canonical(EMPIRICAL['tasks'])).hex()
    params['model_evolution_policy_hash'] = H('native-model-evolution-policy-v5', canonical(policy)).hex()
    params['max_model_candidates'] = params['max_candidate_history_per_round'] = 16
    params['max_artifact_bytes'] = 65536
    family = H('family', canonical(family_registry))
    params['factor_genesis_artifact'] = artifact(family, [0] * COEFFICIENTS, 7).hex()
    network = H('network', params['chain_label'].encode())
    parameters = H('parameters', canonical(params), canonical(read_config('config/pon/ledger-v1.json')),
                   canonical(read_config('config/pon/work-profile-v1.json')), canonical(family_registry))
    plan = H('plan', b'native-integer-model-evolution-plan-v5', family,
             *[bytes.fromhex(params[key]) for key in ['evaluation_policy_hash', 'model_evidence_policy_hash',
                                                    'model_evidence_tasks_hash', 'model_evolution_policy_hash']])
    return dict(network=network.hex(), parameters=parameters.hex(), family=family.hex(), plan=plan.hex(), params=params)


def trained(passes):
    weights = [[0] * COLUMNS for _ in range(ROWS)]
    for _ in range(passes):
        for task in EMPIRICAL['tasks']:
            scores = [sum(w * x for w, x in zip(row, task['features'])) for row in weights]
            prediction = max(range(ROWS), key=scores.__getitem__)
            if prediction != task['label']:
                weights[prediction] = [w - x for w, x in zip(weights[prediction], task['features'])]
                weights[task['label']] = [w + x for w, x in zip(weights[task['label']], task['features'])]
    return [[a - b for a, b in zip(row, weights[0])] for row in weights]


def historical_context(profile):
    """Lock revision15 identities from retained bytes; no successor fields enter."""
    params = read_config('config/pon/devnet-v1.json')
    quorum = read_config('config/pon/public-evaluation-quorum-v2.json')
    family_registry = read_config('config/pon/model-family-integer-factor-v2.json')
    family_registry['native_admission_profile'] = profile
    params.update(quorum['genesis_overrides'])
    params['evaluation_policy_hash'] = H('evaluation-policy', canonical(quorum)).hex()
    params['chain_label'] += '-evaluation-storage3-' + profile
    params['model_profile'] = profile
    params['factor_candidate_policy_hash'] = H('integer-factor-candidate-policy-v2',
                                              canonical(read_config('config/pon/integer-factor-candidate-v2.json'))).hex()
    params['model_evidence_policy_hash'] = H('native-model-evidence-policy-v3', canonical(EMPIRICAL)).hex()
    params['model_evidence_tasks_hash'] = H('native-model-evidence-tasks-v3', canonical(EMPIRICAL['tasks'])).hex()
    params['max_model_candidates'] = params['max_candidate_history_per_round'] = 16
    params['max_artifact_bytes'] = 65536
    family = H('family', canonical(family_registry))
    zero = b'ILM2' + struct.pack('<H', 2) + family + struct.pack('<4H', 1024, 3, 257, 3) + bytes(2 * COEFFICIENTS)
    params['factor_genesis_artifact'] = H('integer-linear-model-artifact-v2', zero).hex()
    keys = ['factor_candidate_policy_hash', 'evaluation_policy_hash', 'model_evidence_policy_hash', 'model_evidence_tasks_hash']
    plan_name = b'native-integer-model-evidence-plan-v3'
    if profile == 'linear-factor-composition-dev-v4':
        params['model_composition_policy_hash'] = H('native-model-composition-policy-v4',
                                                   canonical(read_config('config/pon/model-composition-v4.json'))).hex()
        keys.append('model_composition_policy_hash')
        plan_name = b'native-integer-model-composition-plan-v4'
    network = H('network', params['chain_label'].encode())
    parameters = H('parameters', canonical(params), canonical(read_config('config/pon/ledger-v1.json')),
                   canonical(read_config('config/pon/work-profile-v1.json')), canonical(family_registry))
    plan = H('plan', plan_name, family, *[bytes.fromhex(params[key]) for key in keys])
    return dict(network=network.hex(), parameters=parameters.hex(), family=family.hex(), plan=plan.hex(),
                genesis_artifact=params['factor_genesis_artifact'])


def rank_two(target, rows):
    return dict(target=target, rank=2, factors=[0, 0, 1, 0, 0, 1] + rows[1] + rows[2])


def witness(ctx, author, parent_ref, parent, parent_mask, mask, operations, round_number, score):
    family = bytes.fromhex(ctx['family'])
    model = derive(parent, parent_mask, mask, operations)
    parent_artifact, candidate_artifact = artifact(family, parent, parent_mask), artifact(family, model, mask)
    update = H('integer-linear-model-update-v3', bytes.fromhex(ctx['network']), bytes.fromhex(ctx['parameters']),
               family, parent_ref, parent_artifact, struct.pack('<Q', round_number), encode_model(family, model, mask))
    cid = H('integer-evolution-contribution-v3', bytes.fromhex(ctx['network']), bytes.fromhex(ctx['parameters']),
            author, family, parent_ref, parent_artifact, candidate_artifact, update, struct.pack('<Q', round_number))
    root = H('allocation-leaf', cid, author, struct.pack('<Q', score))
    payload = (b'ILF3' + struct.pack('<HBBH', 3, mask, len(operations), 1024)
               + b''.join([family, parent_ref, parent_artifact, candidate_artifact, update, cid, root])
               + struct.pack('<Q', round_number))
    for operation in checked_operations(operations):
        payload += bytes([operation['target'], operation['rank']]) + struct.pack('<' + 'h' * len(operation['factors']), *operation['factors'])
    release = H('release', parent_ref, cid, struct.pack('<Q', 1000), root, struct.pack('<Q', score))
    return dict(payload=payload.hex(), model=encode_model(family, model, mask).hex(), artifact=candidate_artifact.hex(),
                update=update.hex(), contribution=cid.hex(), release=release.hex(), mask=mask,
                correct=correct(model, mask), score=score), model


def vector():
    ctx = context()
    # Owner bytes are read from the admitted fixed public development source map.
    author = bytes.fromhex(EMPIRICAL['sources'][0]['author'])
    zero = tuple([0] * COEFFICIENTS)
    router = [0] * 260
    router[1], router[259] = 1, 1
    operations = [dict(target=1, rank=1, factors=router), rank_two(3, trained(1))]
    first, model1 = witness(ctx, author, bytes.fromhex(ctx['params']['factor_genesis_artifact']), zero, 7, 7, operations, 0, 200000)
    rows = [[a - b for a, b in zip(row2, row1)] for row2, row1 in zip(trained(2), trained(1))]
    second, model2 = witness(ctx, author, bytes.fromhex(first['release']), model1, 7, 2, [rank_two(0, rows)], 1, 40000)
    neutral, _ = witness(ctx, author, bytes.fromhex(second['release']), model2, 2, 3, [], 2, 0)
    return dict(schema='independent-model-evolution-v5-vector', context=ctx, author=author.hex(),
                first=first, second=second, neutral=neutral,
                historical={profile: historical_context(profile) for profile in
                            ['linear-factor-evidence-dev-v3', 'linear-factor-composition-dev-v4']},
                scope='public-row-memorization-mechanics-only', fresh_dataset_activation=False)


if __name__ == '__main__':
    target = Path(__file__).with_name('vectors') / 'model-evolution-v5.json'
    target.write_text(json.dumps(vector(), indent=2, sort_keys=True) + '\n')
    print(json.dumps({'vector': str(target), 'scope': 'independent-mathematical-fixture'}))

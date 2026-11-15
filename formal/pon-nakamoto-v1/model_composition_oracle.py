"""Separately coded integer-model V4 oracle; never calls native code for answers.

This covers model bytes, frozen inference, exact composition and funded allocation.
The caller supplies authenticated native-state observations for comparison. This
module does not independently authenticate signatures, roster closure or PoN work,
and does not establish independent operators, future efficacy or economic fairness.
"""
from __future__ import annotations

from itertools import combinations
import struct
from contract_wire import H, canonical, read_config, u64

FEATURES = 257
MATRIX = 3 * FEATURES
COEFFICIENTS = 5 * MATRIX
MODEL_BYTES = 46 + 2 * COEFFICIENTS
SCALE = 1_000_000
U64_MAX = (1 << 64) - 1
POLICY = read_config('config/pon/model-composition-v4.json')
EMPIRICAL = read_config('config/pon/model-evidence-v3.json')


def require(condition, code):
    if not condition:
        raise ValueError(code)


def uint(value, code='MODEL_COMPOSITION_RANGE'):
    require(type(value) is int and 0 <= value <= U64_MAX, code)
    return value


def hash_bytes(value):
    require(type(value) is str and len(value) == 64
            and all(c in '0123456789abcdef' for c in value), 'MODEL_COMPOSITION_STATE')
    return bytes.fromhex(value)


def checked_coefficients(values):
    require(isinstance(values, (list, tuple)) and len(values) == COEFFICIENTS,
            'FACTOR_MODEL_LENGTH')
    require(all(type(v) is int and -32767 <= v <= 32767 for v in values),
            'FACTOR_MODEL_RANGE')
    return tuple(values)


def encode_model(family, coefficients):
    require(type(family) is bytes and len(family) == 32, 'FACTOR_MODEL_CONTEXT')
    coefficients = checked_coefficients(coefficients)
    return (b'ILM2' + struct.pack('<H', 2) + family + struct.pack('<4H', 1024, 3, 257, 3)
            + struct.pack('<' + 'h' * COEFFICIENTS, *coefficients))


def decode_model(raw, family):
    require(type(raw) is bytes and len(raw) == MODEL_BYTES, 'FACTOR_MODEL_LENGTH')
    require(raw[:6] == b'ILM2\x02\x00', 'FACTOR_MODEL_VERSION')
    require(raw[6:38] == family and raw[38:46] == struct.pack('<4H', 1024, 3, 257, 3),
            'FACTOR_MODEL_CONTEXT')
    return checked_coefficients(struct.unpack('<' + 'h' * COEFFICIENTS, raw[46:]))


def artifact(family, coefficients):
    return H('integer-linear-model-artifact-v2', encode_model(family, coefficients)).hex()


def predictions(coefficients, rows):
    """Integer dot products; Python max retains the first index on every tie."""
    coefficients = checked_coefficients(coefficients)
    matrices = [tuple(coefficients[offset:offset + MATRIX])
                for offset in range(0, COEFFICIENTS, MATRIX)]
    result = []
    for features in rows:
        require(len(features) == FEATURES and all(type(v) is int and -8 <= v <= 8
                for v in features) and features[-1] == 8, 'MODEL_EVIDENCE_TASK')
        def linear(matrix):
            return [sum(w * x for w, x in zip(matrix[offset:offset + FEATURES], features))
                    for offset in range(0, MATRIX, FEATURES)]
        router = linear(matrices[1])
        expert = max(range(3), key=router.__getitem__)
        logits = [base + delta for base, delta in zip(linear(matrices[0]),
                                                    linear(matrices[2 + expert]))]
        result.append(max(range(3), key=logits.__getitem__))
    return result


def correct(coefficients):
    tasks = EMPIRICAL['tasks']
    return sum(prediction == task['label'] for prediction, task in zip(
        predictions(coefficients, [row['features'] for row in tasks]), tasks))


def derive(parent, components, omit=None):
    parent = checked_coefficients(parent)
    components = [checked_coefficients(model) for model in components]
    included = [model for index, model in enumerate(components) if index != omit]
    # Algebraically count P once. Do not clip intermediate partial sums to i16.
    result = tuple(sum(column) - (len(included) - 1) * base
                   for base, column in zip(parent, zip(*included))) if included else parent
    require(all(-32767 <= value <= 32767 for value in result), 'MODEL_COMPOSITION_RANGE')
    return result


def reject_redundant_subsets(parent, components):
    parent = checked_coefficients(parent)
    components = [checked_coefficients(model) for model in components]
    require(2 <= len(components) <= 4, 'MODEL_COMPOSITION_COUNT')
    count = 0
    # Combinations differ from native bitmask enumeration; every complete vector
    # is compared with multiplicity * P, independently of prediction equality.
    for length in range(2, len(components) + 1):
        for chosen in combinations(components, length):
            count += 1
            require(any(sum(column) != length * base
                        for base, column in zip(parent, zip(*chosen))),
                    'MODEL_COMPOSITION_REDUNDANT_SUBSET')
    return count


def policy_hash():
    return H('native-model-composition-policy-v4', canonical(POLICY)).hex()


def allocation_root(components):
    leaves = [H('allocation-leaf', hash_bytes(row['contribution']), hash_bytes(row['owner']),
                u64(row['weight'])) for row in components]
    require(bool(leaves), 'MODEL_COMPOSITION_COUNT')
    while len(leaves) > 1:
        if len(leaves) % 2:
            leaves.append(leaves[-1])
        leaves = [H('allocation-node', *sorted(leaves[index:index + 2]))
                  for index in range(0, len(leaves), 2)]
    return leaves[0]


def controls(family):
    result = []
    for control in EMPIRICAL['controls']:
        raw = bytes.fromhex(control['coefficients_le_i16_hex'])
        require(len(raw) == 2 * COEFFICIENTS, 'MODEL_EVIDENCE_CONTROL')
        model = checked_coefficients(struct.unpack('<' + 'h' * COEFFICIENTS, raw))
        result.append(dict(role=control['role'], artifact=artifact(family, model),
                           correct=correct(model)))
    return result


def empirical_record(context, cid, candidate, parent):
    family = hash_bytes(context['family'])
    control_records = controls(family)
    parent_count = correct(parent)
    candidate_count = correct(candidate)
    strongest = max([parent_count] + [row['correct'] for row in control_records])
    count = len(EMPIRICAL['tasks'])
    record = dict(schema='native-integer-model-evidence-record-v4',
                  **{name: context[name] for name in ('network', 'parameters', 'family', 'plan')},
                  policy=H('native-model-evidence-policy-v3', canonical(EMPIRICAL)).hex(),
                  tasks=H('native-model-evidence-tasks-v3', canonical(EMPIRICAL['tasks'])).hex(),
                  contribution=cid, candidate=artifact(family, candidate),
                  parent=artifact(family, parent), rows=count, candidate_correct=candidate_count,
                  parent_correct=parent_count, controls=control_records,
                  strongest_correct=strongest, score=max(0, candidate_count - strongest) * SCALE // count,
                  scope='exact-public-retrospective-integer-dataset-only',
                  prospective_accepted=False, independent_accepted=False,
                  public_reward_eligible=False, composition_policy=policy_hash())
    record['digest'] = H('native-model-empirical-record-v4', canonical(record)).hex()
    return record


def composition_release(value):
    """Check the V4 numerical relationship, not the entire signed M05/M06 path."""
    context = value['context']
    family = hash_bytes(context['family'])
    parent = decode_model(bytes.fromhex(value['parent_model_hex']), family)
    parent_id = artifact(family, parent)
    bundle = value['bundle']
    components = value['components']
    require(2 <= len(components) <= 4, 'MODEL_COMPOSITION_COUNT')
    ids = [row['id'] for row in components]
    require(ids == sorted(set(ids)) and bundle['id'] not in ids, 'MODEL_COMPOSITION_ORDER')
    metadata = bundle['contribution']
    require(metadata['parent'] == value['parent_ref'] and metadata['factor_parent_artifact'] == parent_id,
            'MODEL_COMPOSITION_PARENT')
    require(metadata['family'] == context['family'], 'MODEL_COMPOSITION_PARENT')
    actual = decode_model(bytes.fromhex(bundle['model_hex']), family)
    require(metadata['artifact'] == artifact(family, actual), 'FACTOR_MODEL_HASH')
    models = []
    for component in components:
        other = component['contribution']
        require(all(other[key] == metadata[key] for key in
                    ('parent', 'factor_parent_artifact', 'family', 'submission_round')),
                'MODEL_COMPOSITION_PARENT')
        require(other['slot'] == metadata['slot'], 'MODEL_COMPOSITION_SLOT')
        model = decode_model(bytes.fromhex(component['model_hex']), family)
        require(other['artifact'] == artifact(family, model), 'FACTOR_MODEL_HASH')
        models.append(model)
    subset_count = reject_redundant_subsets(parent, models)
    require(derive(parent, models) == actual, 'MODEL_COMPOSITION_DERIVATION')
    actual_count = correct(actual)
    strongest = max([correct(parent)] + [row['correct'] for row in controls(family)]
                    + [correct(model) for model in models])
    require(actual_count > strongest, 'MODEL_COMPOSITION_GAIN')
    rows = len(EMPIRICAL['tasks'])
    measured = []
    for index, component in enumerate(components):
        without = derive(parent, models, index)
        without_count = correct(without)
        require(actual_count > without_count, 'MODEL_COMPOSITION_MARGINAL')
        weight = (actual_count - without_count) * SCALE // rows
        require(weight > 0 and uint(component['weight']) == weight, 'MODEL_COMPOSITION_WEIGHT')
        measured.append(dict(contribution=component['id'],
                             artifact=artifact(family, models[index]),
                             owner=component['contribution']['owner'], correct=correct(models[index]),
                             without_artifact=artifact(family, without),
                             without_correct=without_count, weight=weight))
    total = uint(sum(row['weight'] for row in measured))
    record = dict(schema='native-model-composition-record-v4',
                  **{name: context[name] for name in ('network', 'parameters', 'family', 'plan')},
                  policy=policy_hash(), bundle=bundle['id'], artifact=artifact(family, actual),
                  parent=value['parent_ref'], parent_artifact=parent_id,
                  round=metadata['submission_round'], slot=metadata['slot'], rows=rows,
                  correct=actual_count, strongest_correct=strongest,
                  gain_score=(actual_count - strongest) * SCALE // rows,
                  components=measured, total_weight=total, zero_subset_checks=subset_count,
                  prospective_accepted=False, independent_accepted=False,
                  public_reward_eligible=False, shapley_fairness_accepted=False)
    record['digest'] = H('native-model-composition-record-v4', canonical(record)).hex()
    budget = uint(value['budget'])
    root = allocation_root(measured)
    require(metadata['components_root'] == root.hex(), 'ROOT')
    released = H('release', hash_bytes(value['parent_ref']), hash_bytes(bundle['id']),
                 u64(budget), root, u64(total)).hex()
    require(value['release'] == released, 'ROOT')
    payouts = {row['contribution']: budget * row['weight'] // total for row in measured}
    reserved = {source: uint(amount) for source, amount in value['source_reserved'].items()}
    sources = {row['author']: row['source'] for row in EMPIRICAL['sources']}
    for row in measured:
        require(row['owner'] in sources, 'MODEL_EVIDENCE_SOURCE')
        source = sources[row['owner']]
        require(source in reserved, 'MODEL_EVIDENCE_SOURCE')
        reserved[source] = uint(reserved[source] + payouts[row['contribution']],
                                'MODEL_EVIDENCE_ARITHMETIC')
    require(all(amount <= EMPIRICAL['max_reserved_units_per_source_round']
                for amount in reserved.values()), 'MODEL_EVIDENCE_SOURCE_BUDGET')
    return dict(composition=record, payouts=payouts, source_reserved=reserved, root=root.hex(),
                release=released,
                dust=budget - sum(payouts.values()))

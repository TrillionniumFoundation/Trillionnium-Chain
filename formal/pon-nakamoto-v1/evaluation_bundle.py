"""Immutable evaluation inputs for the existing learning/evaluation producers.

This module owns no trainer, chain state, authorization store or future-time oracle.
An expected bundle digest must come from the admitting owner, not the downloaded file.
"""
from __future__ import annotations
import copy
import json
import os
from fractions import Fraction
from pathlib import Path
from contract_wire import NETWORK, PARAMETER_HASH, H, canonical, unique
from model_contract import load_model_bytes, infer
from evaluation import CONTROL_ORDER, MAX_ROWS, MAX_GROUPS, macro_accuracy, select_reference, assess, _aligned

MAX_BUNDLE_BYTES = 2 * 1024 * 1024
MAX_TASK_BYTES = 32 * 1024 * 1024
POLICY = {'id': 'pon-frozen-cluster-evaluation-v3', 'minimum_clusters': 20,
          'comparisons': 4, 'selection_metric': 'equal-source-group-accuracy',
          'positive_macro_gain_required': True, 'public_reward_authority': False}
FIELDS = {'schema', 'network', 'parameters', 'source_commit', 'round', 'parent_release',
          'parent_artifact', 'candidate_artifact', 'candidate', 'controls',
          'control_artifacts', 'selected', 'calibration_lock', 'control_macro_scores',
          'partitions', 'policy', 'scope'}
PARTITION_FIELDS = {'rows', 'groups', 'tasks_digest', 'task_id_root', 'content_root'}


def require(ok, code):
    if not ok:
        raise ValueError(code)


def digest_text(value, length=64):
    require(isinstance(value, str) and len(value) == length and
            all(c in '0123456789abcdef' for c in value), 'DIGEST')
    return value


def artifact_id(model):
    return H('artifact', canonical(model)).hex()


def predict_rows(model, rows):
    # infer has a 64-request bound; the evaluator has a separate finite corpus budget.
    _aligned(rows)
    predictions = []
    for offset in range(0, len(rows), 64):
        predictions.extend(infer(model, [r['x'] for r in rows[offset:offset + 64]]))
    return predictions


def control_models(current, candidate, calibration, pooled_weights):
    """Materialize every control using exactly the normal public model format."""
    load_model_bytes(canonical(current))
    load_model_bytes(canonical(candidate))
    variants = []
    for i in range(3):
        value = copy.deepcopy(candidate)
        value['router'] = [[0] * 257 for _ in range(3)]
        value['deltas'] = [copy.deepcopy(candidate['deltas'][i]) for _ in range(3)]
        variants.append(value)
    best = max(range(3), key=lambda i: (macro_accuracy(calibration, predict_rows(variants[i], calibration)), -i))
    mean = copy.deepcopy(candidate)
    # Exact ties-to-even integer rounding, without float/numpy serialization aliases.
    merged = [[round(Fraction(sum(candidate['deltas'][e][c][j] for e in range(3)), 3))
               for j in range(257)] for c in range(3)]
    mean['router'] = [[0] * 257 for _ in range(3)]
    mean['deltas'] = [copy.deepcopy(merged) for _ in range(3)]
    pooled = copy.deepcopy(candidate)
    pooled['base'] = copy.deepcopy(pooled_weights)
    pooled['router'] = [[0] * 257 for _ in range(3)]
    pooled['deltas'] = [[[0] * 257 for _ in range(3)] for _ in range(3)]
    result = dict(current=copy.deepcopy(current), best_single=variants[best], mean_merge=mean, pooled=pooled)
    for value in result.values():
        load_model_bytes(canonical(value))
    return result


def partition_manifest(rows):
    groups = _aligned(rows)
    identities = []
    contents = []
    for row in rows:
        digest_text(row['id'])
        digest_text(row.get('source_content_sha256'))
        x=row.get('x')
        require(isinstance(x,list) and len(x)==257 and x[-1]==8 and
                all(type(v)is int and -8<=v<=8 for v in x),'INPUT_RANGE')
        identities.append(row['id'])
        contents.append(row['source_content_sha256'])
    require(len(set(contents)) == len(contents), 'DUPLICATE_CONTENT')
    return {'rows': len(rows), 'groups': sorted(groups),
            'tasks_digest': H('evaluation-tasks-v3', canonical(rows)).hex(),
            'task_id_root': H('evaluation-task-ids-v3', canonical(sorted(identities))).hex(),
            'content_root': H('evaluation-contents-v3', canonical(sorted(contents))).hex()}


def freeze_bundle(*, source_commit, round_number, parent_release, current, candidate, controls, partitions):
    digest_text(source_commit, 40)
    digest_text(parent_release)
    require(type(round_number) is int and 1 <= round_number < 1 << 64, 'ROUND')
    require(isinstance(partitions, dict) and {'train', 'calibration'} < set(partitions) and
            set(partitions) <= {'train', 'calibration', 'evaluation', 'evaluation_a', 'evaluation_b', 'consumer'}, 'PARTITIONS')
    require(set(controls) == set(CONTROL_ORDER), 'CONTROL_SET')
    load_model_bytes(canonical(candidate))
    load_model_bytes(canonical(current))
    for model in controls.values():
        load_model_bytes(canonical(model))
    require(artifact_id(controls['current']) == artifact_id(current), 'PARENT_ARTIFACT')
    manifests = {}
    seen_ids, seen_groups, seen_contents = set(), set(), set()
    for name, rows in partitions.items():
        manifest = partition_manifest(rows)
        ids = {r['id'] for r in rows}
        groups = set(manifest['groups'])
        contents = {r['source_content_sha256'] for r in rows}
        require(not (seen_ids & ids or seen_groups & groups or seen_contents & contents), 'PARTITION_OVERLAP')
        seen_ids |= ids; seen_groups |= groups; seen_contents |= contents
        manifests[name] = manifest
    calibration = partitions['calibration']
    predictions = {name: predict_rows(controls[name], calibration) for name in CONTROL_ORDER}
    selected, lock = select_reference(calibration, predictions)
    scores = {name: macro_accuracy(calibration, predictions[name]) for name in CONTROL_ORDER}
    bundle = {'schema': 'pon-evaluation-bundle-v3', 'network': NETWORK.hex(),
              'parameters': PARAMETER_HASH.hex(), 'source_commit': source_commit,
              'round': round_number, 'parent_release': parent_release,
              'parent_artifact': artifact_id(current), 'candidate_artifact': artifact_id(candidate),
              'candidate': copy.deepcopy(candidate), 'controls': copy.deepcopy(controls),
              'control_artifacts': {name: artifact_id(controls[name]) for name in CONTROL_ORDER},
              'selected': selected, 'calibration_lock': lock,
              'control_macro_scores': {name: [str(v.numerator), str(v.denominator)] for name, v in scores.items()},
              'partitions': manifests, 'policy': dict(POLICY),
              'scope': 'controlled-local-frozen-inputs-not-authorized-future-evidence'}
    raw = canonical(bundle)
    require(len(raw) <= MAX_BUNDLE_BYTES, 'BUNDLE_LIMIT')
    digest = H('evaluation-bundle-v3', raw).hex()
    verify_bundle(raw, digest, expected_parent=artifact_id(current))
    return raw, digest


def verify_bundle(raw, expected_digest, *, expected_parent=None):
    require(type(raw) is bytes and len(raw) <= MAX_BUNDLE_BYTES, 'BUNDLE_LIMIT')
    digest_text(expected_digest)
    require(H('evaluation-bundle-v3', raw).hex() == expected_digest, 'BUNDLE_IDENTITY')
    try:
        bundle = json.loads(raw, object_pairs_hook=unique)
    except (RecursionError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError('BUNDLE_JSON') from error
    require(isinstance(bundle, dict) and set(bundle) == FIELDS, 'BUNDLE_FIELDS')
    require(canonical(bundle) == raw, 'BUNDLE_CANONICAL')
    require(bundle['schema'] == 'pon-evaluation-bundle-v3' and canonical(bundle['policy']) == canonical(POLICY), 'BUNDLE_POLICY')
    require(bundle['network'] == NETWORK.hex() and bundle['parameters'] == PARAMETER_HASH.hex(), 'BUNDLE_NETWORK')
    require(bundle['scope'] == 'controlled-local-frozen-inputs-not-authorized-future-evidence', 'BUNDLE_AUTHORITY')
    digest_text(bundle['source_commit'], 40)
    require(type(bundle['round']) is int and 1 <= bundle['round'] < 1 << 64, 'ROUND')
    for name in ['parent_release', 'parent_artifact', 'candidate_artifact', 'calibration_lock']:
        digest_text(bundle[name])
    require(all(isinstance(bundle[name],dict) for name in ['controls','control_artifacts','control_macro_scores']),'CONTROL_SET')
    require(set(bundle['controls']) == set(CONTROL_ORDER) and
            set(bundle['control_artifacts']) == set(CONTROL_ORDER) and
            set(bundle['control_macro_scores']) == set(CONTROL_ORDER), 'CONTROL_SET')
    for name, model in bundle['controls'].items():
        load_model_bytes(canonical(model))
        require(artifact_id(model) == bundle['control_artifacts'][name], 'CONTROL_IDENTITY')
    load_model_bytes(canonical(bundle['candidate']))
    require(artifact_id(bundle['candidate']) == bundle['candidate_artifact'], 'CANDIDATE_IDENTITY')
    require(bundle['control_artifacts']['current'] == bundle['parent_artifact'], 'PARENT_ARTIFACT')
    if expected_parent is not None:
        digest_text(expected_parent)
        require(bundle['parent_artifact'] == expected_parent, 'PARENT_ARTIFACT')
    scores = {}
    for name, pair in bundle['control_macro_scores'].items():
        require(isinstance(pair, list) and len(pair) == 2 and
                all(isinstance(v, str) and 0 < len(v) <= 2048 and v.isascii() and v.isdecimal()
                    and (v == '0' or v[0] != '0') for v in pair), 'CONTROL_SCORE')
        numerator, denominator = map(int, pair)
        require(0 <= numerator <= denominator and denominator > 0, 'CONTROL_SCORE')
        value = Fraction(numerator, denominator)
        require([str(value.numerator), str(value.denominator)] == pair, 'CONTROL_SCORE_CANONICAL')
        scores[name] = value
    strongest = max(CONTROL_ORDER, key=lambda name: (scores[name], -CONTROL_ORDER.index(name)))
    require(bundle['selected'] == strongest, 'CONTROL_SELECTION')
    manifests = bundle['partitions']
    require(isinstance(manifests, dict) and {'train', 'calibration'} < set(manifests) and
            set(manifests) <= {'train', 'calibration', 'evaluation', 'evaluation_a', 'evaluation_b', 'consumer'}, 'PARTITIONS')
    groups_seen = set()
    for manifest in manifests.values():
        require(isinstance(manifest, dict) and set(manifest) == PARTITION_FIELDS, 'PARTITION_FIELDS')
        require(type(manifest['rows']) is int and 0 < manifest['rows'] <= MAX_ROWS, 'EVALUATION_LIMIT')
        groups = manifest['groups']
        require(isinstance(groups, list) and 0 < len(groups) <= min(MAX_GROUPS, manifest['rows']) and
                all(isinstance(g, str) and 0 < len(g) <= 1024 for g in groups), 'SOURCE_GROUP')
        require(groups == sorted(set(groups)) and not groups_seen.intersection(groups), 'PARTITION_OVERLAP')
        groups_seen.update(groups)
        for name in ['tasks_digest', 'task_id_root', 'content_root']:
            digest_text(manifest[name])
    return bundle


def verify_calibration(bundle, rows):
    require(partition_manifest(rows)==bundle['partitions']['calibration'],'CALIBRATION_TASKS')
    predictions={name:predict_rows(value,rows)for name,value in bundle['controls'].items()}
    selected,lock=select_reference(rows,predictions)
    scores={name:macro_accuracy(rows,predictions[name])for name in CONTROL_ORDER}
    exact={name:[str(score.numerator),str(score.denominator)]for name,score in scores.items()}
    require(selected==bundle['selected'] and lock==bundle['calibration_lock'] and
            exact==bundle['control_macro_scores'],'CALIBRATION_RESULT')


def evaluate_bundle(raw, expected_digest, rows, partition, *, calibration_rows, expected_parent=None):
    bundle = verify_bundle(raw, expected_digest, expected_parent=expected_parent)
    require(partition not in {'train', 'calibration'} and partition in bundle['partitions'], 'EVALUATION_PARTITION')
    require(partition_manifest(rows) == bundle['partitions'][partition], 'EVALUATION_TASKS')
    verify_calibration(bundle,calibration_rows)
    predicted = predict_rows(bundle['candidate'], rows)
    controls = {name: predict_rows(model, rows) for name, model in bundle['controls'].items()}
    primary = assess(rows, predicted, controls[bundle['selected']])
    marginal = []
    for index in range(3):
        reduced = copy.deepcopy(bundle['candidate'])
        reduced['deltas'][index] = [[0] * 257 for _ in range(3)]
        marginal.append(assess(rows, predicted, predict_rows(reduced, rows)))
    return {'schema': 'pon-frozen-evaluation-result-v3', 'bundle': expected_digest,
            'candidate': bundle['candidate_artifact'], 'parent': bundle['parent_artifact'],
            'partition': partition, 'tasks_digest': bundle['partitions'][partition]['tasks_digest'],
            'selected_reference': bundle['selected'], 'reference_artifact': bundle['control_artifacts'][bundle['selected']],
            'primary': primary, 'marginal': marginal, 'predictions': predicted,
            'control_correct': {name: sum(p == r['label'] for p, r in zip(pred, rows)) for name, pred in controls.items()},
            'public_reward_eligible': False, 'ordinary_hepta_entry': False, 'independent_accepted': False}


def write_new(path, raw):
    """Persist a new producer record before evaluation; never overwrite a frozen plan."""
    path = Path(path)
    with path.open('xb') as output:
        output.write(raw); output.flush(); os.fsync(output.fileno())
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def read_bounded(path, maximum):
    with open(path, 'rb') as source:
        data = source.read(maximum + 1)
    require(len(data) <= maximum, 'INPUT_LIMIT')
    return data

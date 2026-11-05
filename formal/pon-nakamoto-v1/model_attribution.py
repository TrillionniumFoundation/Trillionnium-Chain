"""Bounded integer-linear adapter attribution for the existing evaluation owner.

Exact BA equality is sufficient for this declared linear insertion. It is not a
general model-equivalence oracle. Source admissions are inputs from an owner,
not statements of independent administration. Nothing here issues ledger credit.
"""
from __future__ import annotations
import copy
import json
import math
from fractions import Fraction
from contract_wire import H, NETWORK, PARAMETER_HASH, canonical, unique
from model_contract import load_model_bytes
from evaluation import macro_accuracy, assess
from evaluation_bundle import artifact_id, digest_text, partition_manifest, predict_rows, require

MAX_SUBMISSIONS = 16
MAX_GROUPS = 8
MAX_PLAN_BYTES = 2 * 1024 * 1024
MAX_PREDICTION_ROWS = 1024 * 1024
CONTRACT_FIELDS = {'schema', 'family', 'parent_artifact', 'rows', 'columns',
                   'rank_max', 'factor_bound', 'delta_bound', 'scale', 'slot', 'numeric'}
PLAN_FIELDS = {'schema', 'network', 'parameters', 'evaluation_bundle', 'partition',
               'tasks', 'parent', 'contract', 'submissions', 'admitted_sources',
               'source_caps', 'perturbation_linf', 'groups', 'scope'}


def fraction_wire(value):
    value = Fraction(value)
    return [str(value.numerator), str(value.denominator)]


def integer_linear_contract(parent, slot=0):
    load_model_bytes(canonical(parent))
    require(type(slot) is int and 0 <= slot < 3, 'ADAPTER_SLOT')
    return {'schema': 'pon-exact-integer-linear-insertion-v1',
            'family': parent['family'], 'parent_artifact': artifact_id(parent),
            'rows': 3, 'columns': 257, 'rank_max': 8, 'factor_bound': 32767,
            'delta_bound': 32767, 'scale': 1024, 'slot': slot,
            'numeric': 'exact-BA-no-rounding-fixed-router-add-to-delta-v1'}


def validate_contract(contract):
    require(isinstance(contract, dict) and set(contract) == CONTRACT_FIELDS, 'ADAPTER_CONTRACT_FIELDS')
    digest_text(contract['family']); digest_text(contract['parent_artifact'])
    require(contract['schema'] == 'pon-exact-integer-linear-insertion-v1' and
            contract['numeric'] == 'exact-BA-no-rounding-fixed-router-add-to-delta-v1', 'ADAPTER_PROFILE')
    expected = {'rows': 3, 'columns': 257, 'rank_max': 8, 'factor_bound': 32767,
                'delta_bound': 32767, 'scale': 1024}
    require(all(type(contract[k]) is int and contract[k] == v for k, v in expected.items()), 'ADAPTER_NUMERIC')
    require(type(contract['slot']) is int and 0 <= contract['slot'] < 3, 'ADAPTER_SLOT')
    return contract


def contract_id(contract):
    validate_contract(contract)
    return H('integer-linear-insertion-contract-v1', canonical(contract)).hex()


def normalize_adapter(adapter, contract):
    """Recompute the full finite integer product; no probes decide equivalence."""
    validate_contract(contract)
    require(isinstance(adapter, dict) and set(adapter) == {'schema', 'contract', 'A', 'B'}, 'ADAPTER_FIELDS')
    require(adapter['schema'] == 'pon-integer-linear-adapter-v1' and
            adapter['contract'] == contract_id(contract), 'ADAPTER_CONTEXT')
    a, b = adapter['A'], adapter['B']
    require(isinstance(a, list) and 1 <= len(a) <= contract['rank_max'], 'ADAPTER_RANK')
    rank = len(a)
    require(all(isinstance(row, list) and len(row) == contract['columns'] for row in a) and
            isinstance(b, list) and len(b) == contract['rows'] and
            all(isinstance(row, list) and len(row) == rank for row in b), 'ADAPTER_SHAPE')
    require(all(type(v) is int and abs(v) <= contract['factor_bound']
                for matrix in (a, b) for row in matrix for v in row), 'ADAPTER_FACTOR')
    delta = [[sum(b[i][k] * a[k][j] for k in range(rank))
              for j in range(contract['columns'])] for i in range(contract['rows'])]
    require(all(abs(v) <= contract['delta_bound'] for row in delta for v in row), 'ADAPTER_DELTA')
    normal = {'schema': 'pon-normalized-linear-update-v1', 'contract': contract_id(contract), 'delta': delta}
    return {'normal': normal,
            'function_fingerprint': H('normalized-linear-update-v1', canonical(normal)).hex(),
            'artifact': H('integer-linear-adapter-v1', canonical(adapter)).hex(),
            'product_multiplications': contract['rows'] * contract['columns'] * rank}


def exact_linear_equivalent(left, right, contract):
    # Compare the recomputed matrices, not just the digest. Equal matrices define
    # equal linear updates for every input; unequal matrices are NOT necessarily
    # different full-model class functions (argmax/router can erase differences).
    return normalize_adapter(left, contract)['normal'] == normalize_adapter(right, contract)['normal']


def validate_optional_llm_declaration(value):
    """Closed metadata for an unexecuted future adapter family, not an LLM loader."""
    fields = {'schema', 'base_model', 'tokenizer', 'architecture', 'license',
              'target_modules', 'numeric', 'runtime_status'}
    require(isinstance(value, dict) and set(value) == fields, 'LLM_DECLARATION_FIELDS')
    require(value['schema'] == 'pon-llm-adapter-declaration-v1' and
            value['numeric'] == 'declared-exact-integer-linear-BA-only' and
            value['runtime_status'] == 'required-not-executed', 'LLM_DECLARATION_SCOPE')
    for name in ('base_model', 'tokenizer', 'architecture'):
        digest_text(value[name])
    require(isinstance(value['license'], str) and 0 < len(value['license']) <= 512, 'LLM_LICENSE')
    modules = value['target_modules']
    require(isinstance(modules, list) and 0 < len(modules) <= 16, 'LLM_TARGETS')
    names = []
    for module in modules:
        require(isinstance(module, dict) and set(module) == {'name', 'rows', 'columns', 'rank', 'scale'}, 'LLM_TARGET_FIELDS')
        require(isinstance(module['name'], str) and 0 < len(module['name']) <= 256, 'LLM_TARGET_NAME')
        require(all(type(module[k]) is int and 1 <= module[k] <= 65536
                    for k in ('rows', 'columns', 'rank', 'scale')) and
                module['rank'] <= min(module['rows'], module['columns'], 64), 'LLM_TARGET_SHAPE')
        names.append(module['name'])
    require(names == sorted(set(names)), 'LLM_TARGET_ORDER')
    return copy.deepcopy(value)


def freeze_adapter_manifest(adapter, contract, *, optional_llm_declaration=None):
    """New sidecar; adding keys to the existing model artifact remains forbidden."""
    normal = normalize_adapter(adapter, contract)
    declaration = (None if optional_llm_declaration is None
                   else validate_optional_llm_declaration(optional_llm_declaration))
    manifest = {'schema': 'pon-adapter-contribution-manifest-v1',
                'adapter_contract': copy.deepcopy(contract), 'adapter': copy.deepcopy(adapter),
                'normalized_update': normal['normal'], 'function_fingerprint': normal['function_fingerprint'],
                'artifact': normal['artifact'], 'optional_llm_declaration': declaration,
                'scope': 'exact-declared-linear-insertion; optional-LLM-metadata-is-not-executed'}
    raw = canonical(manifest)
    require(len(raw) <= MAX_PLAN_BYTES, 'ADAPTER_MANIFEST_LIMIT')
    return raw, H('adapter-contribution-manifest-v1', raw).hex()


def verify_adapter_manifest(raw, expected_digest):
    require(type(raw) is bytes and len(raw) <= MAX_PLAN_BYTES, 'ADAPTER_MANIFEST_LIMIT')
    digest_text(expected_digest)
    require(H('adapter-contribution-manifest-v1', raw).hex() == expected_digest, 'ADAPTER_MANIFEST_IDENTITY')
    manifest = json.loads(raw, object_pairs_hook=unique)
    require(isinstance(manifest, dict) and set(manifest) == {'schema', 'adapter_contract', 'adapter',
            'normalized_update', 'function_fingerprint', 'artifact', 'optional_llm_declaration', 'scope'}, 'ADAPTER_MANIFEST_FIELDS')
    replay, _ = freeze_adapter_manifest(manifest['adapter'], manifest['adapter_contract'],
        optional_llm_declaration=manifest['optional_llm_declaration'])
    require(raw == replay, 'ADAPTER_MANIFEST_BINDING')
    return manifest


def _groups(submissions, admitted_sources, source_caps, contract, perturbation):
    require(isinstance(submissions, list) and 0 < len(submissions) <= MAX_SUBMISSIONS, 'ATTRIBUTION_SUBMISSIONS')
    require(type(perturbation) is int and 0 <= perturbation <= 8, 'PERTURBATION_BOUND')
    ids = []
    prepared = []
    for submission in submissions:
        require(isinstance(submission, dict) and set(submission) == {'id', 'adapter'}, 'ATTRIBUTION_SUBMISSION_FIELDS')
        identity = digest_text(submission['id']); ids.append(identity)
        normal = normalize_adapter(submission['adapter'], contract)
        prepared.append(dict(id=identity, **normal))
    require(ids == sorted(set(ids)), 'ATTRIBUTION_SUBMISSION_ORDER')
    require(isinstance(admitted_sources, dict) and set(admitted_sources) == set(ids), 'ADMITTED_SOURCES')
    for source in admitted_sources.values():
        digest_text(source)
    require(isinstance(source_caps, dict) and set(source_caps) == set(admitted_sources.values()), 'SOURCE_CAPS')
    require(all(type(v) is int and 0 <= v <= 10**9 for v in source_caps.values()), 'SOURCE_CAP')
    # Near duplicates are an explicit bounded admission rule, not equivalence.
    # Deterministic representatives depend on matrices, never submission order.
    prepared.sort(key=lambda p: (canonical(p['normal']), p['id']))
    clusters = []
    for row in prepared:
        match = next((cluster for cluster in clusters
                      if max(abs(a-b) for ra, rb in zip(row['normal']['delta'], cluster[0]['normal']['delta'])
                             for a, b in zip(ra, rb)) <= perturbation), None)
        if match is None:
            clusters.append([row])
        else:
            match.append(row)
    parents = list(range(len(clusters)))
    def find(index):
        while parents[index] != index:
            index = parents[index]
        return index
    # The same admitted lineage always shares one budget. Equivalent/declared
    # near-copy aliases also share one budget even when submitted under new keys.
    for i, left in enumerate(clusters):
        origins = {admitted_sources[p['id']] for p in left}
        for j in range(i):
            if origins & {admitted_sources[p['id']] for p in clusters[j]}:
                parents[find(i)] = find(j)
    merged = {}
    for i, cluster in enumerate(clusters):
        merged.setdefault(find(i), []).append(cluster)
    groups = []
    for members in merged.values():
        flat = [p for cluster in members for p in cluster]
        sources = sorted({admitted_sources[p['id']] for p in flat})
        components = sorted((cluster[0]['normal'] for cluster in members), key=canonical)
        update = [[sum(component['delta'][i][j] for component in components)
                   for j in range(contract['columns'])] for i in range(contract['rows'])]
        require(all(abs(v) <= contract['delta_bound'] for row in update for v in row), 'GROUP_DELTA')
        groups.append({'id': H('bounded-source-update-group-v1', canonical(components)).hex(),
                       'submissions': sorted(p['id'] for p in flat), 'sources': sources,
                       'components': components, 'delta': update,
                       'credit_cap': min(source_caps[source] for source in sources),
                       'collapsed_aliases': len(flat)-len(components)})
    groups.sort(key=lambda g: g['id'])
    require(len(groups) <= MAX_GROUPS, 'ATTRIBUTION_GROUP_LIMIT')
    return groups


def freeze_attribution_plan(*, parent, evaluation_bundle, partition, rows, submissions,
                            admitted_sources, source_caps, slot=0, perturbation_linf=0):
    """Caller freezes this sidecar BEFORE observing scores and retains its digest."""
    digest_text(evaluation_bundle)
    require(isinstance(partition, str) and partition in {'evaluation', 'evaluation_a', 'evaluation_b', 'consumer'}, 'ATTRIBUTION_PARTITION')
    contract = integer_linear_contract(parent, slot)
    ordered = sorted(copy.deepcopy(submissions), key=lambda s: s['id'])
    groups = _groups(ordered, admitted_sources, source_caps, contract, perturbation_linf)
    require(len(rows) * (1 << len(groups)) <= MAX_PREDICTION_ROWS, 'ATTRIBUTION_WORK_LIMIT')
    plan = {'schema': 'pon-bounded-model-attribution-plan-v1', 'network': NETWORK.hex(),
            'parameters': PARAMETER_HASH.hex(), 'evaluation_bundle': evaluation_bundle,
            'partition': partition, 'tasks': partition_manifest(rows), 'parent': copy.deepcopy(parent),
            'contract': contract, 'submissions': ordered, 'admitted_sources': dict(admitted_sources),
            'source_caps': dict(source_caps), 'perturbation_linf': perturbation_linf, 'groups': groups,
            'scope': 'controlled-local-finite-subsets-no-public-reward-authority'}
    raw = canonical(plan)
    require(len(raw) <= MAX_PLAN_BYTES, 'ATTRIBUTION_PLAN_LIMIT')
    return raw, H('bounded-model-attribution-plan-v1', raw).hex()


def verify_attribution_plan(raw, expected_digest, *, expected_parent=None, expected_bundle=None):
    require(type(raw) is bytes and len(raw) <= MAX_PLAN_BYTES, 'ATTRIBUTION_PLAN_LIMIT')
    digest_text(expected_digest)
    require(H('bounded-model-attribution-plan-v1', raw).hex() == expected_digest, 'ATTRIBUTION_PLAN_IDENTITY')
    try:
        plan = json.loads(raw, object_pairs_hook=unique)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError('ATTRIBUTION_PLAN_JSON') from error
    require(isinstance(plan, dict) and set(plan) == PLAN_FIELDS and canonical(plan) == raw, 'ATTRIBUTION_PLAN_FIELDS')
    require(plan['schema'] == 'pon-bounded-model-attribution-plan-v1' and
            plan['network'] == NETWORK.hex() and plan['parameters'] == PARAMETER_HASH.hex() and
            plan['scope'] == 'controlled-local-finite-subsets-no-public-reward-authority', 'ATTRIBUTION_PLAN_SCOPE')
    digest_text(plan['evaluation_bundle'])
    require(isinstance(plan['partition'], str) and plan['partition'] in {'evaluation', 'evaluation_a', 'evaluation_b', 'consumer'}, 'ATTRIBUTION_PARTITION')
    load_model_bytes(canonical(plan['parent']))
    validate_contract(plan['contract'])
    require(plan['contract'] == integer_linear_contract(plan['parent'], plan['contract']['slot']), 'ATTRIBUTION_PARENT')
    if expected_parent is not None:
        require(artifact_id(plan['parent']) == digest_text(expected_parent), 'ATTRIBUTION_PARENT')
    if expected_bundle is not None:
        require(plan['evaluation_bundle'] == digest_text(expected_bundle), 'ATTRIBUTION_BUNDLE')
    groups = _groups(plan['submissions'], plan['admitted_sources'], plan['source_caps'],
                     plan['contract'], plan['perturbation_linf'])
    require(canonical(groups) == canonical(plan['groups']), 'ATTRIBUTION_GROUP_BINDING')
    return plan


def _subset_model(plan, mask):
    model = copy.deepcopy(plan['parent'])
    slot = plan['contract']['slot']
    for index, group in enumerate(plan['groups']):
        if mask & (1 << index):
            model['deltas'][slot] = [[a+b for a, b in zip(left, right)]
                                     for left, right in zip(model['deltas'][slot], group['delta'])]
    load_model_bytes(canonical(model))  # All subset candidates must stay feasible.
    return model


def evaluate_attribution_plan(raw, expected_digest, rows, *, candidate_mask=None,
                              expected_parent=None, expected_bundle=None):
    plan = verify_attribution_plan(raw, expected_digest, expected_parent=expected_parent,
                                   expected_bundle=expected_bundle)
    require(canonical(partition_manifest(rows)) == canonical(plan['tasks']), 'ATTRIBUTION_TASKS')
    n = len(plan['groups']); count = 1 << n
    require(len(rows) * count <= MAX_PREDICTION_ROWS, 'ATTRIBUTION_WORK_LIMIT')
    if candidate_mask is None:
        candidate_mask = count-1
    require(type(candidate_mask) is int and 0 <= candidate_mask < count, 'ATTRIBUTION_MASK')
    values = []; predictions = []
    for mask in range(count):
        predicted = predict_rows(_subset_model(plan, mask), rows)
        predictions.append(predicted); values.append(macro_accuracy(rows, predicted))
    winner = max(range(count), key=lambda mask: (values[mask], -mask.bit_count(), -mask))
    attribution = []
    for index, group in enumerate(plan['groups']):
        bit = 1 << index
        shapley = sum((Fraction(math.factorial(mask.bit_count()) * math.factorial(n-mask.bit_count()-1),
                               math.factorial(n)) * (values[mask | bit]-values[mask])
                       for mask in range(count) if not mask & bit), Fraction())
        attribution.append({'group': group['id'], 'credit_cap': group['credit_cap'],
                            'standalone_gain': fraction_wire(values[bit]-values[0]),
                            'leave_one_out_gain': fraction_wire(values[-1]-values[(count-1)^bit]),
                            'finite_group_shapley': fraction_wire(shapley),
                            'submissions': group['submissions'], 'collapsed_aliases': group['collapsed_aliases']})
    joint = values[-1]-values[0]
    standalone_sum = sum((values[1 << index]-values[0] for index in range(n)), Fraction())
    return {'schema': 'pon-bounded-model-attribution-result-v1', 'plan': expected_digest,
            'evaluation_bundle': plan['evaluation_bundle'], 'tasks': plan['tasks']['tasks_digest'],
            'candidate_mask': candidate_mask, 'candidate_value': fraction_wire(values[candidate_mask]),
            'baseline_value': fraction_wire(values[0]), 'joint_gain': fraction_wire(joint),
            'complementarity': fraction_wire(joint-standalone_sum), 'attribution': attribution,
            'candidate_gate': assess(rows, predictions[candidate_mask], predictions[0]),
            'bounded_optimum': {'method': 'exhaust-all-frozen-feasible-group-subsets-v1',
                'winner_mask': winner, 'maximum': fraction_wire(values[winner]),
                'candidate_gap': fraction_wire(values[winner]-values[candidate_mask]),
                'exact_in_this_set': values[candidate_mask] == values[winner],
                'table': [{'mask': mask, 'value': fraction_wire(value)} for mask, value in enumerate(values)]},
            'verification_cost': {'adapter_product_multiplications': sum(normalize_adapter(s['adapter'], plan['contract'])['product_multiplications'] for s in plan['submissions']),
                'prediction_rows': len(rows)*count, 'inference_multiplications': len(rows)*count*9*257,
                'subsets': count, 'router_retraining_steps': 0},
            'public_reward_eligible': False, 'ordinary_hepta_entry': False, 'independent_accepted': False,
            'excluded_claims': ['full-model-functional-equivalence', 'unrestricted-circuit-optimality',
                                'prospective-benefit', 'source-independence', 'training-provenance', 'fresh-consensus-work']}


def verify_attribution_result(raw_plan, expected_digest, rows, claimed, **kwargs):
    actual = evaluate_attribution_plan(raw_plan, expected_digest, rows, **kwargs)
    require(canonical(actual) == canonical(claimed), 'ATTRIBUTION_RESULT_BINDING')
    return actual

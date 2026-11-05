"""Paired complete local delivery costs for the existing grouped integer relation.

The inputs are retained source-corpus requests, replayed as a finite burst. This
is an actual Python/NumPy execution, not a native-node, GPU, proof, external
demand, or original fixed-Host service result. Full scalar recomputation remains
mandatory. Every planned arm stays in the denominator, including late failures.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import sys
import time

os.environ.setdefault('OPENBLAS_NUM_THREADS', '1')
os.environ.setdefault('OMP_NUM_THREADS', '1')
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import numpy as np
import contract_wire
from contract_wire import canonical, unique
from evaluation_bundle import artifact_id, partition_manifest
from experiments import grouped_cell_operator_v0 as relation
from experiments.shared_cell_operator_v1 import (
    DEFAULT_BUNDLE, DEFAULT_MATERIAL, load_inputs, prepare_numpy, save_json)
from model_contract import DIM, load_model_bytes

SCHEMA = 'pon-grouped-local-delivery-cost-v2'
ARMS = ('selected_direct', 'packed_grouped')
FORMAL_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = FORMAL_ROOT.parents[1]
SOURCE_SCOPE = ('Loaded repository Python modules and contract_wire configuration files; '
                'before/after path and file-byte observations, not whole-source, loaded-bytecode, '
                'interpreter, NumPy, native-library, or independent execution attestation')
REQUIRED_MODULES = ('bounded_process', 'contract_wire', 'evaluation', 'evaluation_bundle',
                    'experiments.grouped_cell_operator_v0', 'experiments.shared_cell_operator_v1',
                    'ledger', 'model_contract', 'strict_signature', 'work_backend', 'work_oracle')


def require(ok, code):
    if not ok:
        raise ValueError(code)


def _digest(value):
    return type(value) is str and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def source_snapshot():
    """Observe actual loaded local paths, including transitive import dependencies.

    Include every loaded repository module, not just this entry point or a
    selected verifier. Required components must be loaded from their actual
    retained locations. These file hashes cannot attest to in-memory code or to
    the interpreter/third-party runtime; that limitation is part of the record.
    """
    required = {name: FORMAL_ROOT.joinpath(*name.split('.')).with_suffix('.py')
                for name in REQUIRED_MODULES}
    required[__name__] = FORMAL_ROOT / 'experiments/grouped_delivery_cost_v1.py'
    for name, expected in required.items():
        actual = getattr(sys.modules.get(name), '__file__', None)
        require(type(actual) is str and Path(actual).absolute() == expected and
                Path(actual).resolve() == expected, 'SOURCE_MODULE_PATH:' + name)
    modules, hashes = {}, {}
    for name, module in sorted(tuple(sys.modules.items())):
        location = getattr(module, '__file__', None)
        if not isinstance(location, str):
            continue
        path = Path(location).absolute()
        if not path.is_relative_to(REPOSITORY_ROOT):
            continue
        actual = path.resolve(strict=True)
        require(actual == path and path.suffix == '.py', 'SOURCE_MODULE_PATH:' + name)
        modules[name] = str(actual)
        hashes[str(actual)] = hashlib.sha256(actual.read_bytes()).hexdigest()
    configs = ['ledger-v1.json', 'work-profile-v1.json', 'model-family-v1.json', 'devnet-v1.json']
    if 'evaluation_policy_hash' in contract_wire.PARAMS:
        configs.append('evaluation-round-v1.json')
    for name in configs:
        path = REPOSITORY_ROOT / 'config/pon' / name
        require(path.resolve(strict=True) == path, 'SOURCE_CONFIG_PATH:' + name)
        hashes[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
    return {'module_paths': modules, 'files_sha256': hashes}


def verify_source_snapshot(before):
    after = source_snapshot()
    require(after == before, 'SOURCE_DRIFT')
    return after


def validate_inputs(model, rows):
    # Validate source integers before NumPy can coerce bool/float aliases.
    load_model_bytes(canonical(model))
    require(type(rows) is list and 1 <= len(rows) <= 64, 'INPUT_BATCH')
    partition_manifest(rows)


def prepare_material(model, rows):
    validate_inputs(model, rows)
    return prepare_numpy(model, rows)


def bind_inputs(init, command, model, rows):
    validate_inputs(model, rows)
    require(type(init) is dict and set(init) == {'type', 'model_version', 'base', 'router', 'deltas'}
            and init['type'] == 'init', 'MODEL_ENVELOPE')
    require(init['model_version'] == artifact_id(model) and
            all(canonical(init[key]) == canonical(model[key]) for key in ('base', 'router', 'deltas')),
            'MODEL_ENVELOPE_BINDING')
    require(type(command) is dict and set(command) ==
            {'type', 'context', 'requests', 'now_ns', 'samples', 'warmup'} and
            command['type'] == 'batch', 'INPUT_ENVELOPE')
    relation.context_bytes(command['context'])
    for key in ('now_ns', 'samples', 'warmup'):
        relation.uint(command[key], 'INPUT_ENVELOPE_INTEGER')
    requests = command['requests']
    require(type(requests) is list and len(requests) == len(rows), 'INPUT_ENVELOPE_BINDING')
    for request, row in zip(requests, rows):
        require(type(request) is dict and set(request) ==
                {'id', 'scope', 'arrival_ns', 'deadline_ns', 'x'}, 'REQUEST_ENVELOPE')
        require(request['id'] == row['id'] and canonical(request['x']) == canonical(row['x']),
                'INPUT_ENVELOPE_BINDING')
        relation.digest(request['scope'], 'REQUEST_SCOPE')
        relation.uint(request['arrival_ns'], 'REQUEST_TIME')
        relation.uint(request['deadline_ns'], 'REQUEST_TIME')
        require(request['arrival_ns'] <= command['now_ns'] < request['deadline_ns'], 'REQUEST_TIME')


def produce(prepared, arm):
    require(arm in ARMS, 'ARM')
    require(type(prepared) is tuple and len(prepared) == 3, 'MATERIAL')
    x, router, merged = prepared
    require(all(type(array) is np.ndarray and array.dtype == np.dtype('int64')
                for array in prepared), 'MATERIAL_INTEGER_TYPE')
    require(x.ndim == 2 and 1 <= len(x) <= 64 and x.shape == (len(x), DIM) and
            router.shape == (3, DIM) and merged.shape == (3, 3, DIM), 'MATERIAL_SHAPE')
    require(bool(((x >= -8) & (x <= 8)).all()) and bool((x[:, -1] == 8).all()) and
            bool(((router >= -32767) & (router <= 32767)).all()) and
            bool(((merged >= -65534) & (merged <= 65534)).all()), 'MATERIAL_RANGE')
    scores = x @ router.T
    routes = np.argmax(scores, axis=1)
    groups = [np.flatnonzero(routes == expert).tolist() for expert in range(3)]
    logits = np.empty((len(x), 3), dtype=np.int64)
    if arm == 'selected_direct':
        for index, expert in enumerate(routes):
            logits[index] = merged[expert] @ x[index]
    else:
        for expert, indices in enumerate(groups):
            if indices:
                logits[indices] = x[indices] @ merged[expert].T
    return {'router_outputs': scores.tolist(), 'routes': routes.tolist(),
            'groups': groups, 'logits': logits.tolist(),
            'predictions': np.argmax(logits, axis=1).tolist(),
            'useful_dense_macs': 6 * 257 * len(x), 'padded_macs': 0,
            'nonempty_expert_groups': sum(bool(group) for group in groups)}


def verify_delivery(raw, init, command, model, rows):
    """Recompute the full original-coefficient relation after actual wire decode."""
    require(type(raw) is bytes and len(raw) <= 1024 * 1024, 'DELIVERY_BYTES')
    value = json.loads(raw, object_pairs_hook=unique,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError('NONFINITE')))
    require(type(value) is dict and set(value) == {'model', 'input', 'statement', 'product'},
            'DELIVERY_FIELDS')
    require(canonical(value) == raw, 'DELIVERY_CANONICAL')
    bind_inputs(init, command, model, rows)
    model_hash = relation.model_commitment(init)
    input_hash = relation.input_commitment(model_hash, command)
    require(value['model'] == model_hash and value['input'] == input_hash, 'DELIVERY_IDENTITY')
    # Arithmetic uses the same model and request objects as the commitments.
    # Their original arithmetic inputs and row IDs were bound by canonical bytes.
    expected = relation.scalar_product(init, command['requests'])
    require(canonical(value['product']) == canonical(expected), 'COMPLETE_RELATION')
    require(value['statement'] == relation.statement_commitment(
        model_hash, input_hash, command['context'], expected), 'STATEMENT')
    return expected


def observe(case, *, model_path, tasks_path, bundle_path, bundle_hash, budget_ns):
    start, cpu_start = time.perf_counter_ns(), time.process_time_ns()
    phases = {}
    row = {**case, 'original_budget_ns': budget_ns, 'status': 'failed',
           'quality_exact': False, 'deadline_met': False, 'error': None,
           'input_identity': None, 'product_sha256': None, 'wire_bytes': None}

    def measured(name, call):
        wall, cpu = time.perf_counter_ns(), time.process_time_ns()
        try:
            return call()
        finally:
            phases[name] = {'wall_ns': time.perf_counter_ns() - wall,
                            'cpu_ns': time.process_time_ns() - cpu}

    try:
        model, rows, provenance = measured('load_and_validate_model_tasks_bundle', lambda: load_inputs(
            model_path, tasks_path, bundle_path, bundle_hash, 'consumer', 0,
            case['batch_size'], replay_source=False))
        init, commands = measured('request_envelope', lambda: relation.make_commands(
            model, rows, provenance, [case['batch_size']], 1, 0))
        command = commands[0]
        command['now_ns'] = 0
        for request in command['requests']:
            request['arrival_ns'] = 0
            request['deadline_ns'] = budget_ns
        prepared = measured('material_preparation', lambda: prepare_material(model, rows))
        model_hash = measured('model_commitment', lambda: relation.model_commitment(init))
        input_hash = measured('input_commitment', lambda: relation.input_commitment(model_hash, command))
        row['input_identity'] = input_hash
        product = measured('producer', lambda: produce(prepared, case['arm']))
        statement = measured('statement_commitment', lambda: relation.statement_commitment(
            model_hash, input_hash, command['context'], product))
        raw = measured('serialize', lambda: canonical(dict(model=model_hash, input=input_hash,
                                                          statement=statement, product=product)))
        verified = measured('decode_and_complete_scalar_verification', lambda: verify_delivery(
            raw, init, command, model, rows))
        row['wire_bytes'] = len(raw)
        row['product_sha256'] = hashlib.sha256(canonical(verified)).hexdigest()
        row['quality_exact'] = True
        row['status'] = 'verified_local_delivery'
    except Exception as error:
        row['error'] = {'type': type(error).__name__, 'message': str(error)}
    row['wall_ns'] = time.perf_counter_ns() - start
    row['cpu_ns'] = time.process_time_ns() - cpu_start
    row['phases'] = phases
    row['deadline_met'] = row['quality_exact'] and row['wall_ns'] < budget_ns
    if row['quality_exact'] and not row['deadline_met']:
        row['status'] = 'verified_but_late'
    return row


def plan(sizes, repetitions):
    require(type(sizes) is list and sizes and
            all(type(n) is int and 1 <= n <= 64 for n in sizes) and
            sizes == sorted(set(sizes)), 'SIZES')
    require(type(repetitions) is int and 1 <= repetitions <= 100, 'REPETITIONS')
    return [dict(index=index, repeat=repeat, batch_size=n, arm=arm)
            for index, (repeat, n, arm) in enumerate(
                (repeat, n, arm) for repeat in range(repetitions) for n in sizes
                for arm in (ARMS if repeat % 2 == 0 else ARMS[::-1]))]


def summarize(planned, observations, *, budget_ns):
    """An absent or failed observation cannot disappear from either denominator."""
    require(type(budget_ns) is int and 1 <= budget_ns <= 60_000_000_000, 'ORIGINAL_BUDGET')
    require(type(planned) is list and planned, 'PLAN')
    for case in planned:
        require(type(case) is dict and set(case) == {'index', 'repeat', 'batch_size', 'arm'} and
                type(case['index']) is int and case['index'] >= 0 and
                type(case['repeat']) is int and 0 <= case['repeat'] < 100 and
                type(case['batch_size']) is int and 1 <= case['batch_size'] <= 64 and
                type(case['arm']) is str and case['arm'] in ARMS, 'PLAN_CASE')
    expected = {case['index']: case for case in planned}
    require(len(expected) == len(planned), 'PLAN_DUPLICATE')
    require(planned == plan(sorted({case['batch_size'] for case in planned}),
                            1 + max(case['repeat'] for case in planned)), 'PLAN_LAYOUT')
    seen = {}
    for row in observations:
        require(type(row) is dict and type(row.get('index')) is int and row['index'] in expected and
                row['index'] not in seen, 'OBSERVATION_IDENTITY')
        require(all(type(row.get(key)) is type(value) and row[key] == value
                    for key, value in expected[row['index']].items()),
                'OBSERVATION_PLAN_BINDING')
        require(type(row.get('wall_ns')) is int and 0 <= row['wall_ns'] <= relation.U64_MAX and
                type(row.get('cpu_ns')) is int and 0 <= row['cpu_ns'] <= relation.U64_MAX, 'COST')
        require(type(row.get('quality_exact')) is bool and type(row.get('deadline_met')) is bool,
                'OUTCOME_TYPE')
        require(type(row.get('original_budget_ns')) is int and row['original_budget_ns'] == budget_ns,
                'ORIGINAL_BUDGET')
        require(row['deadline_met'] == (row['quality_exact'] and
                row['wall_ns'] < budget_ns), 'DEADLINE_READBACK')
        if row['quality_exact']:
            require(_digest(row.get('input_identity')) and _digest(row.get('product_sha256')),
                    'SUCCESS_IDENTITY')
        seen[row['index']] = row
    groups = []
    for n in sorted({case['batch_size'] for case in planned}):
        summaries = {}
        for arm in ARMS:
            cases = [c for c in planned if c['batch_size'] == n and c['arm'] == arm]
            actual = [seen[c['index']] for c in cases if c['index'] in seen]
            good = [r for r in actual if r['quality_exact'] is True and r['deadline_met'] is True]
            summaries[arm] = {'planned_cases': len(cases), 'observed_cases': len(actual),
                'on_time_exact_cases': len(good), 'planned_request_occurrences': n * len(cases),
                'on_time_exact_request_occurrences': n * len(good),
                'missing_indices': [c['index'] for c in cases if c['index'] not in seen],
                'cpu_ns_all_observed': sum(r['cpu_ns'] for r in actual),
                'wall_ns_all_observed': sum(r['wall_ns'] for r in actual),
                'wall_ns_median_all_observed': statistics.median(r['wall_ns'] for r in actual) if actual else None}
        pairs, pair_records, identities_match = [], [], True
        repeats = sorted({c['repeat'] for c in planned if c['batch_size'] == n})
        for repeat in repeats:
            pair = {c['arm']: seen.get(c['index']) for c in planned
                    if c['batch_size'] == n and c['repeat'] == repeat}
            a, b = pair.get(ARMS[0]), pair.get(ARMS[1])
            if a and b and a['quality_exact'] and b['quality_exact']:
                same = (a['input_identity'] == b['input_identity'] and
                        a['product_sha256'] == b['product_sha256'] and
                        a['original_budget_ns'] == b['original_budget_ns'])
                require(same, 'PAIRED_INPUT_OR_QUALITY_CHANGED')
            else:
                identities_match = False
            ratio, unavailable = None, 'incomplete_or_late_delivery'
            if a and b and a['deadline_met'] and b['deadline_met']:
                if a['cpu_ns'] > 0 and b['cpu_ns'] > 0:
                    ratio, unavailable = b['cpu_ns'] / a['cpu_ns'], None
                    pairs.append(ratio)
                else:
                    unavailable = 'nonpositive_observed_cpu'
            pair_records.append({'repeat': repeat, 'packed_over_direct_cpu': ratio,
                                 'unavailable': unavailable})
        complete = identities_match and all(v['on_time_exact_cases'] == v['planned_cases'] for v in summaries.values())
        cpu_complete = complete and len(pairs) == len(repeats)
        direct_cost = summaries['selected_direct']['cpu_ns_all_observed']
        groups.append({'batch_size': n, 'arms': summaries,
            'paired_complete_quality_and_local_deadline': complete,
            'paired_cpu_comparison_complete': cpu_complete,
            'packed_over_direct_total_cpu_median': statistics.median(pairs) if cpu_complete else None,
            'paired_total_cpu_ratios': pairs,
            'paired_cpu_ratio_records': pair_records,
            'paired_total_cpu_ratio_range': [min(pairs), max(pairs)] if cpu_complete else None,
            'aggregate_packed_over_direct_cpu': (summaries['packed_grouped']['cpu_ns_all_observed'] / direct_cost
                                               if cpu_complete else None),
            'uncertainty': 'finite local repetitions on a shared host; raw ratios and all costs retained; no statistical or general speedup claim',
            'ratio_scope': 'entire observed local replay, including every model load and full scalar verification'})
    return {'planned_cases': len(planned), 'observed_cases': len(seen),
            'planned_request_occurrences': sum(c['batch_size'] for c in planned),
            'distinct_retrospective_input_rows': max(c['batch_size'] for c in planned),
            'repeats_and_arm_copies_are_new_demand': False,
            'missing_indices': sorted(set(expected) - set(seen)), 'by_batch_size': groups}


def execute(args):
    require(type(args.budget_ms) is int and 1 <= args.budget_ms <= 60000, 'BUDGET')
    planned = plan([int(n) for n in args.batch_sizes.split(',')], args.repetitions)
    output = args.out.resolve()
    output.mkdir(parents=True, exist_ok=False)
    inputs = [args.model, args.tasks, args.evaluation_bundle]
    hashes = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}
    before = source_snapshot()
    specification = {'schema': SCHEMA, 'cases': planned, 'input_sha256': hashes,
        'source_sha256': before['files_sha256'], 'source_module_paths': before['module_paths'],
        'source_scope': SOURCE_SCOPE, 'whole_source_attestation': False,
        'budget_ns': args.budget_ms * 1_000_000,
        'budget_scope': 'declared local corpus replay diagnostic; not original F0 service SLO',
        'source_replayed_from_git': False, 'real_demand_authenticated': False,
        'native_backend_executed': False, 'production_activation': False}
    save_json(output / 'plan.json', specification)
    observations = []
    with (output / 'observations.jsonl').open('x') as journal:
        for case in planned:
            require(all(hashlib.sha256(p.read_bytes()).hexdigest() == hashes[str(p)] for p in inputs), 'INPUT_DRIFT')
            row = observe(case, model_path=args.model, tasks_path=args.tasks,
                          bundle_path=args.evaluation_bundle, bundle_hash=args.bundle_hash,
                          budget_ns=specification['budget_ns'])
            observations.append(row)
            journal.write(json.dumps(row, sort_keys=True, allow_nan=False) + '\n')
            journal.flush()
            os.fsync(journal.fileno())
    report = {'schema': SCHEMA, 'summary': summarize(planned, observations, budget_ns=specification['budget_ns']),
        'environment': {'python': sys.version, 'numpy': np.__version__, 'platform': platform.platform(),
            'openblas_threads': os.environ.get('OPENBLAS_NUM_THREADS'), 'omp_threads': os.environ.get('OMP_NUM_THREADS')},
        'scope': {'actual_execution': 'Python/NumPy integer producer, canonical wire, independent full scalar verifier',
            'loading': 'model/tasks/bundle read and validated and merged weights prepared on every arm; OS page cache uncontrolled',
            'waiting': 'finite retrospective burst; actual external queue and batch-fill wait unobserved',
            'phase_rule': 'phase costs are subsets of total and never added to total again',
            'journal_fsync': 'experiment evidence persistence is outside per-request delivery timing'},
        'unmeasured': ['process_startup_and_import', 'external_queue_and_batch_fill', 'WAN_transport',
            'device_loading', 'PoN_proof_generation_and_verification', 'independent_confirmation', 'energy'],
        'full_system_cost': None, 'same_original_resource_gate_qualified': False,
        'succinct_proof_executed': False, 'grouped_pow_qualified': False, 'production_activation': False}
    report['source_after'] = verify_source_snapshot(before)
    report['source_scope'] = SOURCE_SCOPE
    report['whole_source_attestation'] = False
    save_json(output / 'report.json', report)
    return report


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--model', type=Path, default=DEFAULT_MATERIAL / 'model.json')
    p.add_argument('--tasks', type=Path, default=DEFAULT_MATERIAL / 'consumer.json')
    p.add_argument('--evaluation-bundle', type=Path, default=DEFAULT_MATERIAL / 'evaluation-bundle.json')
    p.add_argument('--bundle-hash', default=DEFAULT_BUNDLE)
    p.add_argument('--batch-sizes', default='1,4,16,64')
    p.add_argument('--repetitions', type=int, default=4)
    p.add_argument('--budget-ms', type=int, default=4000)
    p.add_argument('--out', type=Path, required=True)
    return p


if __name__ == '__main__':
    result = execute(parser().parse_args())
    print(json.dumps(result['summary'], sort_keys=True))

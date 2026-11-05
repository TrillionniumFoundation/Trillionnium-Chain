"""Persistent grouped int257 research experiment over an existing frozen corpus.

This runner does no training and manufactures no demand. Prefixes of the same
retrospective consumer partition exercise sizes 1/4/16/64; their overlap and all
benchmark repetitions are disclosed. Native commitments bind arithmetic facts,
not PoUW qualification. Original arrival/deadline observations are unavailable.

Use --model MODEL --tasks CONSUMER --evaluation-bundle BUNDLE --bundle-hash HASH
     --runner RELEASE_EXAMPLE --replay-source --out NEW_DIRECTORY.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
from pathlib import Path
import resource
import shlex
import shutil
import statistics
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from bounded_process import ProcessFailure, run_bounded
from contract_wire import H, ROOT, canonical, unique
from evaluation_bundle import predict_rows, partition_manifest
from experiments.shared_cell_operator_v1 import (
    baseline, execution_identity, hardware_snapshot, load_inputs,
    numpy_operator, prepare_numpy, save_json)
from model_contract import DIM

SCHEMA = 'pon-grouped-cell-operator-research-v0'
PROFILE = 'pon-routed-int257-grouped-research-v0'
NATIVE_SCHEMA = 'pon-routed-int257-grouped-session-v0'
U64_MAX = (1 << 64) - 1
PHASES = {'validation', 'input_commitment', 'router', 'gather', 'expert',
          'statement_commitment', 'verify'}
SELECTED_PHASES = {'validation', 'input_commitment', 'execution', 'statement_commitment', 'verify'}
SELECTED_PRODUCER_SCOPE = 'prepared_model_fresh_batch_input_commit_selected_statement_full_verify'
HOT_ORDERS = ['ABC', 'CBA', 'BCA', 'ACB', 'CAB', 'BAC']
NATIVE_HOT_ORDER = [[{'A': 'ordinary', 'B': 'selected', 'C': 'packed'}[arm]
                     for arm in order] for order in HOT_ORDERS]
FIRST_CALL_SCOPE = 'ordinary, packed, then selected in one prepared process sharing caches; not isolated cold starts'
# This interval is a transport fixture. It is never reported as real demand time.
FIXTURE_ARRIVAL_NS = 0
FIXTURE_NOW_NS = 1
FIXTURE_DEADLINE_NS = 3_600_000_000_000


def require(ok, code):
    if not ok:
        raise ValueError(code)


def digest(value, code='HASH32'):
    require(type(value) is str and len(value) == 64 and
            all(c in '0123456789abcdef' for c in value), code)
    return bytes.fromhex(value)


def uint(value, code='UINT64'):
    require(type(value) is int and 0 <= value <= U64_MAX, code)
    return value


def u64(value):
    return uint(value).to_bytes(8, 'big')


def i64(value):
    require(type(value) is int and -(1 << 63) <= value < (1 << 63), 'INT64')
    return value.to_bytes(8, 'big', signed=True)


def native_hash(domain, *parts):
    d = domain.encode()
    return hashlib.sha256(b'trnm.domain.hash.v1' + u64(len(d)) + d +
                          b''.join(u64(len(part)) + part for part in parts)).hexdigest()


def model_commitment(init):
    raw = digest(init['model_version']) + u64(DIM) + u64(3) + u64(3)
    raw += b''.join(i64(x) for matrix in [init['base'], init['router'], *init['deltas']]
                    for row in matrix for x in row)
    return native_hash('pon-routed-int257-grouped-model-v0', PROFILE.encode(),
                       b'signed-i32-coeff-i64-accum-bias8-lowest-argmax', raw)


def context_bytes(context):
    require(type(context) is dict and set(context) == {'chain', 'parent', 'challenge', 'batch_id'},
            'CONTEXT_FIELDS')
    return b''.join(digest(context[key]) for key in ('chain', 'parent', 'challenge', 'batch_id'))


def input_commitment(model_hash, command):
    raw = context_bytes(command['context']) + u64(len(command['requests']))
    for row in command['requests']:
        raw += digest(row['id']) + digest(row['scope']) + u64(row['arrival_ns']) + u64(row['deadline_ns'])
        raw += b''.join(i64(x) for x in row['x'])
    return native_hash('pon-routed-int257-grouped-input-v0', PROFILE.encode(), digest(model_hash), raw)


def statement_commitment(model_hash, input_hash, context, product):
    raw = context_bytes(context) + u64(len(product['routes']))
    raw += b''.join(i64(x) for row in product['router_outputs'] for x in row)
    raw += b''.join(u64(x) for x in product['routes'])
    for group in product['groups']:
        raw += u64(len(group)) + b''.join(u64(x) for x in group)
    raw += b''.join(i64(x) for row in product['logits'] for x in row)
    raw += b''.join(u64(x) for x in product['predictions'])
    raw += u64(product['useful_dense_macs']) + u64(product['padded_macs']) + u64(product['nonempty_expert_groups'])
    return native_hash('pon-routed-int257-grouped-statement-v0', PROFILE.encode(),
                       digest(model_hash), digest(input_hash), raw)


def scalar_product(model, rows):
    """Independent original-coefficient scalar control; no cached merged factors."""
    scores = [[sum(a * x for a, x in zip(weight, row['x'])) for weight in model['router']]
              for row in rows]
    routes = [max(range(3), key=lambda i: score[i]) for score in scores]
    logits = [[sum((model['base'][r][k] + model['deltas'][e][r][k]) * row['x'][k]
                    for k in range(DIM)) for r in range(3)] for row, e in zip(rows, routes)]
    groups = [[i for i, expert in enumerate(routes) if expert == e] for e in range(3)]
    return {'router_outputs': scores, 'routes': routes, 'groups': groups, 'logits': logits,
            'predictions': [max(range(3), key=lambda i: values[i]) for values in logits],
            'useful_dense_macs': 6 * DIM * len(rows), 'padded_macs': 0,
            'nonempty_expert_groups': sum(bool(group) for group in groups)}


def make_commands(model, rows, provenance, sizes, samples, warmup):
    init = {'type': 'init', 'model_version': provenance['model_artifact'],
            'base': model['base'], 'router': model['router'], 'deltas': model['deltas']}
    scope = H('grouped-retrospective-scope-v0', canonical({'scope': provenance['scope'],
              'model': provenance['model_artifact'], 'bundle': provenance['evaluation_bundle'],
              'demand_kind': 'retrospective-frozen-corpus-no-arrival-trace'})).hex()
    context = {'chain': H('grouped-retrospective-chain-v0', b'research-only').hex(),
               'parent': H('grouped-retrospective-parent-v0', provenance['source_commit'].encode()).hex(),
               'challenge': H('grouped-retrospective-challenge-v0', digest(provenance['evaluation_bundle'])).hex()}
    commands = []
    for n in sizes:
        requests = [{'id': row['id'], 'scope': scope, 'arrival_ns': FIXTURE_ARRIVAL_NS,
                     'deadline_ns': FIXTURE_DEADLINE_NS, 'x': row['x']} for row in rows[:n]]
        batch_id = H('grouped-retrospective-batch-v0', canonical({'scope': scope, 'size': n,
                     'offset': provenance['batch_offset'], 'ids': [r['id'] for r in requests]})).hex()
        commands.append({'type': 'batch', 'context': {**context, 'batch_id': batch_id},
                         'requests': requests, 'now_ns': FIXTURE_NOW_NS,
                         'samples': samples, 'warmup': warmup})
    return init, commands


def encode_frames(values):
    frames = [canonical(value) + b'\n' for value in values]
    require(all(len(frame) <= 256 * 1024 for frame in frames), 'INPUT_FRAME_BOUND')
    return b''.join(frames)


def decode_frames(raw, expected):
    require(type(raw) is bytes and raw.endswith(b'\n'), 'OUTPUT_TERMINATOR')
    lines = raw.splitlines()
    require(len(lines) == expected and all(len(line) <= 1024 * 1024 for line in lines),
            'OUTPUT_FRAME_BOUND')
    values = [json.loads(line, object_pairs_hook=unique) for line in lines]
    require(all(type(v) is dict for v in values), 'OUTPUT_OBJECT')
    return values


def validate_prepared(prepared, init):
    require(prepared.get('type') == 'prepared' and prepared.get('schema') == NATIVE_SCHEMA and
            prepared.get('profile') == PROFILE, 'PREPARED_SCHEMA')
    require(prepared.get('model_commitment') == model_commitment(init), 'MODEL_COMMITMENT')
    require(prepared.get('production_activation') is False and prepared.get('pow_qualified') is False,
            'PREPARED_QUALIFICATION')
    uint(prepared.get('preparation_ns'), 'PREPARATION_TIMING')


def validate_result(result, init, command, model, rows, *, prior_ids):
    require(result.get('type') == 'batch' and result.get('schema') == NATIVE_SCHEMA and
            result.get('profile') == PROFILE, 'BATCH_SCHEMA')
    m = model_commitment(init)
    inputs = input_commitment(m, command)
    require(result.get('model_commitment') == m and result.get('input_commitment') == inputs,
            'INPUT_BINDING')
    expected = scalar_product(model, rows)
    for key, value in expected.items():
        # Canonical bytes reject bool/int aliases and ensure exact group ordering.
        require(canonical(result.get(key)) == canonical(value), 'PRODUCT_' + key.upper())
    expected_statement = statement_commitment(m, inputs, command['context'], expected)
    require(result.get('statement_commitment') == expected_statement, 'STATEMENT_BINDING')
    require(result.get('selected_statement_commitment') == expected_statement, 'SELECTED_STATEMENT_BINDING')
    require(result.get('selected_statement_matches_packed') is True and
            result.get('selected_semantic_verified') is True, 'SELECTED_SEMANTIC_VERIFICATION')
    require(predict_rows(model, rows) == expected['predictions'], 'MODEL_CONTRACT_REFERENCE')
    numpy = numpy_operator(prepare_numpy(model, rows))
    for key in ('routes', 'logits', 'predictions'):
        require(numpy[key].tolist() == expected[key], 'NUMPY_' + key.upper())
    require(result.get('semantic_verified') is True and result.get('benchmark_only') is True and
            result.get('distinct_application_batches', 'missing') is None and
            result.get('response_deadline_checked_before_write') is True, 'RESEARCH_SCOPE')
    for key in ('pow_qualified', 'production_activation', 'public_reward_eligible', 'real_demand_verified'):
        require(result.get(key) is False, 'QUALIFICATION_' + key.upper())
    for key in ('model_reward', 'business_credit'):
        require(type(result.get(key)) is int and result[key] == 0, 'CREDIT_' + key.upper())
    ids = {row['id'] for row in rows}
    require(type(result.get('new_request_ids_in_session')) is int and
            result['new_request_ids_in_session'] == len(ids - prior_ids), 'NEW_REQUEST_COUNT')
    require(type(result.get('unique_request_ids_in_session')) is int and
            result['unique_request_ids_in_session'] == len(ids | prior_ids), 'UNIQUE_REQUEST_COUNT')
    phases = result.get('phase_ns')
    require(type(phases) is dict and set(phases) == PHASES, 'PHASES')
    for value in phases.values():
        uint(value, 'PHASE_TIMING')
    selected_phases = result.get('selected_phase_ns')
    require(type(selected_phases) is dict and set(selected_phases) == SELECTED_PHASES, 'SELECTED_PHASES')
    for value in selected_phases.values():
        uint(value, 'SELECTED_PHASE_TIMING')
    require(result.get('selected_producer_with_verify_scope') == SELECTED_PRODUCER_SCOPE,
            'SELECTED_PRODUCER_SCOPE')
    require('selected_producer_with_verify_cpu_ns' in result, 'SELECTED_CPU_OBSERVATION')
    if result['selected_producer_with_verify_cpu_ns'] is not None:
        uint(result['selected_producer_with_verify_cpu_ns'], 'SELECTED_CPU_TIMING')
    for key in ('cold_baseline_ns', 'cold_grouped_ns', 'cold_selected_with_statement_ns',
                'selected_producer_with_verify_wall_ns', 'handler_wall_ns', 'completion_now_ns',
                'verified_product_ready_now_ns', 'selected_verified_product_ready_now_ns'):
        uint(result.get(key), 'BATCH_TIMING')
    if result.get('handler_cpu_ns') is not None:
        uint(result['handler_cpu_ns'], 'CPU_TIMING')
    require(command['now_ns'] <= result['verified_product_ready_now_ns'] <=
            result['selected_verified_product_ready_now_ns'] <= result['completion_now_ns'] <
            min(row['deadline_ns'] for row in command['requests']), 'FIXTURE_COMPLETION')
    require(result.get('first_call_scope') == FIRST_CALL_SCOPE, 'FIRST_CALL_SCOPE')
    require(canonical(result.get('kernel_sample_order_cycle')) == canonical(NATIVE_HOT_ORDER),
            'KERNEL_SAMPLE_ORDER')
    require(uint(result.get('kernel_sample_complete_cycles'), 'KERNEL_SAMPLE_CYCLES') ==
            command['samples'] // len(NATIVE_HOT_ORDER), 'KERNEL_SAMPLE_CYCLES')
    require(uint(result.get('kernel_sample_partial_cycle_samples'), 'KERNEL_SAMPLE_REMAINDER') ==
            command['samples'] % len(NATIVE_HOT_ORDER), 'KERNEL_SAMPLE_REMAINDER')
    for key in ('baseline_ns', 'selected_ns', 'grouped_ns'):
        values = result.get(key)
        require(type(values) is list and len(values) == command['samples'], 'SAMPLE_COUNT')
        for value in values:
            uint(value, 'SAMPLE_TIMING')
    return ids | prior_ids


def distribution(values):
    ordered = sorted(values)
    return {'samples_ns': values, 'minimum_ns': min(values),
            'median_ns': statistics.median(values),
            'p95_ns': ordered[(len(values) * 95 + 99) // 100 - 1]}


def kernel_comparison(result):
    """Describe only comparable hot scopes, preserving the ordinary control.

    Selected/direct and packed grouped both return the same complete Product.
    Ordinary returns fewer diagnostics and remains the legal cheap baseline.
    A measured median chooses a candidate for this fixture, never runtime policy.
    """
    ordinary = distribution(result['baseline_ns'])
    selected = distribution(result['selected_ns'])
    packed = distribution(result['grouped_ns'])
    a, b, c = (record['median_ns'] for record in (ordinary, selected, packed))
    if min(b, c) <= 0:
        candidate = 'undetermined_timer_resolution'
    elif b < c:
        candidate = 'selected_direct'
    elif c < b:
        candidate = 'packed_grouped'
    else:
        candidate = 'tied'
    return {'native_hot_ordinary': ordinary, 'native_hot_selected': selected, 'native_hot_grouped': packed,
            'grouped_over_ordinary_hot_kernel_median': c / a if a else None,
            'selected_over_ordinary_hot_kernel_median': b / a if a else None,
            'packed_over_selected_hot_kernel_median': c / b if b else None,
            'hot_comparison_scope': 'same prepared model and batch; A ordinary returns routes/logits/predictions; B selected direct and C packed grouped return the same complete Product; packed retains three internal router/gather/expert phase-clock probes absent from ordinary/direct, so differences include that instrumentation as well as gather/contraction; no commitments, verification or transport inside hot kernels',
            'hot_sampling_order': {'arms': {'ordinary': 'ordinary', 'selected': 'selected_direct', 'packed': 'packed_grouped'},
                'cycle': result['kernel_sample_order_cycle'],
                'complete_cycles': result['kernel_sample_complete_cycles'],
                'partial_cycle_samples': result['kernel_sample_partial_cycle_samples'],
                'remaining_orders': result['kernel_sample_order_cycle'][:result['kernel_sample_partial_cycle_samples']]},
            'kernel_candidate_for_this_fixture': {'candidate': candidate,
                'basis': 'lower observed hot median between the two complete-Product kernels',
                'scope': 'this frozen corpus, batch shape and host observation only',
                'ordinary_control_retained': True, 'runtime_policy_changed': False,
                'performance_qualified': False}}


def cpu_children_ns():
    value = resource.getrusage(resource.RUSAGE_CHILDREN)
    return round((value.ru_utime + value.ru_stime) * 1_000_000_000)


def measured(call):
    wall, cpu = time.perf_counter_ns(), time.process_time_ns()
    value = call()
    return value, {'wall_ns': time.perf_counter_ns() - wall, 'cpu_ns': time.process_time_ns() - cpu}


def identity(runner):
    record = execution_identity(runner)
    names = ['formal/pon-nakamoto-v1/experiments/grouped_cell_operator_v0.py',
             'formal/pon-nakamoto-v1/grouped_request_batch_v0.py',
             'formal/pon-nakamoto-v1/grouped_low_rank_v0.py',
             'formal/pon-nakamoto-v1/model_attribution.py',
             'trillionnium/crates/trnm-crypto-primitives/src/pon_routed_int257_grouped.rs',
             'trillionnium/crates/trnm-crypto-primitives/examples/pon_routed_int257_grouped.rs',
             'trillionnium/crates/trnm-crypto-primitives/src/lib.rs',
             'trillionnium/crates/trnm-crypto-primitives/Cargo.toml',
             'trillionnium/Cargo.toml', 'trillionnium/Cargo.lock', 'rust-toolchain.toml',
             'formal/pon-nakamoto-v1/requirements.txt']
    for name in names:
        path = ROOT / name
        require(path.is_file(), 'SOURCE_IDENTITY_MISSING_' + name)
        record['files_sha256'][name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return record


def toolchain():
    observed = {'python_executable': sys.executable, 'python': sys.version,
                'packages': {name: importlib.metadata.version(name) for name in ('numpy', 'cryptography')}}
    for name, args in (('rustc', ['rustc', '--version', '--verbose']), ('cargo', ['cargo', '--version'])):
        executable = shutil.which(args[0])
        if executable is None:
            observed[name] = {'available': False}
            continue
        result = subprocess.run([executable, *args[1:]], cwd=ROOT / 'trillionnium',
                                capture_output=True, check=True, timeout=15)
        require(len(result.stdout) < 16384, 'TOOLCHAIN_LIMIT')
        observed[name] = {'executable': executable, 'version': result.stdout.decode().strip()}
    return observed


def execute(args):
    started, started_cpu = time.perf_counter_ns(), time.process_time_ns()
    experiment_children_start = cpu_children_ns()
    before = None
    environment = None
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=False)
    request = {key: str(value) if isinstance(value, Path) else value for key, value in vars(args).items()}
    save_json(out / 'request.json', request)
    raw_result = None
    try:
        require(args.runner.is_file(), 'RUNNER_REQUIRED')
        sizes = [int(value) for value in args.batch_sizes.split(',')]
        require(sizes and len(sizes) <= 64 and sizes == sorted(set(sizes)) and
                all(1 <= n <= 64 for n in sizes), 'BATCH_SIZES')
        require(1 <= args.samples <= 10000 and 0 <= args.warmup <= 1000, 'REPETITIONS')
        before = identity(args.runner)
        environment = {'hardware': hardware_snapshot(), 'toolchain': toolchain()}
        (model, rows, provenance), input_timing = measured(lambda: load_inputs(
            args.model, args.tasks, args.evaluation_bundle, args.bundle_hash,
            args.partition, args.offset, max(sizes), replay_source=args.replay_source))
        init, commands = make_commands(model, rows, provenance, sizes, args.samples, args.warmup)
        wire, encode_timing = measured(lambda: encode_frames([init, *commands]))
        (out / 'native-input.ndjson').write_bytes(wire)
        children = cpu_children_ns()
        raw_result, process_timing = measured(lambda: run_bounded(
            [str(args.runner.resolve()), '--grouped-research-v0'], wire,
            timeout=args.timeout, stdout_limit=8 * 1024 * 1024, stderr_limit=65536, cwd=ROOT))
        process_timing['child_cpu_ns'] = cpu_children_ns() - children
        (out / 'native-stdout.ndjson').write_bytes(raw_result.stdout)
        (out / 'native-stderr.txt').write_bytes(raw_result.stderr)
        require(raw_result.returncode == 0, 'NATIVE_EXIT_' + str(raw_result.returncode))
        frames, decode_timing = measured(lambda: decode_frames(raw_result.stdout, len(commands) + 1))
        validate_prepared(frames[0], init)
        cases = []
        seen = set()
        for n, command, result in zip(sizes, commands, frames[1:]):
            selected = rows[:n]
            seen, verification_timing = measured(lambda: validate_result(
                result, init, command, model, selected, prior_ids=seen))
            control, control_timing = measured(lambda: baseline(model, selected, args.samples))
            comparison = kernel_comparison(result)
            cases.append({'batch_size': n, 'selected_tasks': partition_manifest(selected),
                'input_commitment': result['input_commitment'], 'statement_commitment': result['statement_commitment'],
                'selected_statement_commitment': result['selected_statement_commitment'],
                'selected_statement_matches_packed': result['selected_statement_matches_packed'],
                'request_ids': [row['id'] for row in selected], 'groups': result['groups'],
                'routes': result['routes'], 'predictions': result['predictions'], 'logits': result['logits'],
                'useful_dense_macs': result['useful_dense_macs'], 'padded_macs': 0,
                'native_full_verifier_macs': 9 * DIM * n,
                'mac_scope': 'useful_dense_macs is one forward operator only; verifier independently adds router/base/selected-delta work; cold calls and repeated measurement work also execute',
                'nonempty_expert_groups': result['nonempty_expert_groups'],
                'new_unique_request_ids': result['new_request_ids_in_session'],
                'native_first_for_shape': {'ordinary_ns': result['cold_baseline_ns'],
                    'grouped_with_statement_ns': result['cold_grouped_ns'],
                    'selected_with_statement_ns': result['cold_selected_with_statement_ns'],
                    'scope': result['first_call_scope']},
                **comparison,
                'native_selected_producer_with_verify': {
                    'wall_ns': result['selected_producer_with_verify_wall_ns'],
                    'cpu_ns': result['selected_producer_with_verify_cpu_ns'],
                    'scope': result['selected_producer_with_verify_scope'], 'observations': 1,
                    'included': ['fresh batch validation and request copy', 'input commitment',
                                 'selected direct Product', 'statement commitment',
                                 'independent full verifier', 'completion deadline check'],
                    'model_preparation_included': False, 'transport_included': False,
                    'cost_comparison_to_hot_only_kernel': None},
                'native_selected_phase_wall_ns': result['selected_phase_ns'],
                'native_selected_phase_cpu_ns': None,
                'native_phase_wall_ns': result['phase_ns'], 'native_phase_cpu_ns': None,
                'native_handler_wall_ns': result['handler_wall_ns'], 'native_handler_cpu_ns': result['handler_cpu_ns'],
                'native_cpu_scope': 'whole handler thread CPU when available; per-phase CPU not observed',
                'numpy_control': control, 'numpy_control_total_timing': control_timing,
                'python_full_differential_timing': verification_timing,
                'differential_checks': ['original-coefficient scalar all logits/routes/groups', 'model_contract predict_rows',
                                        'ordinary selected-expert NumPy', 'model/input/statement commitments',
                                        'selected and packed statements equal independent Python oracle'],
                'fixture_packed_verified_product_ready_ns': result['verified_product_ready_now_ns'],
                'fixture_selected_verified_product_ready_ns': result['selected_verified_product_ready_now_ns'],
                'fixture_response_ready_ns': result['completion_now_ns'],
                'real_queue_wait_ns': None, 'real_deadline_success': None})
        after = identity(args.runner)
        require(before == after, 'EXECUTION_IDENTITY_CHANGED')
        reproduce = [sys.executable, str(Path(__file__).resolve()), '--model', str(args.model.resolve()),
                     '--tasks', str(args.tasks.resolve()), '--evaluation-bundle', str(args.evaluation_bundle.resolve()),
                     '--bundle-hash', args.bundle_hash, '--runner', str(args.runner.resolve()),
                     '--batch-sizes', args.batch_sizes, '--partition', args.partition,
                     '--offset', str(args.offset), '--samples', str(args.samples), '--warmup', str(args.warmup),
                     '--timeout', str(args.timeout), '--out', str(out) + '-reproduction']
        if args.replay_source:
            reproduce.append('--replay-source')
        report = {'schema': SCHEMA, 'profile': PROFILE, 'status': 'retrospective_arithmetic_verified',
                  'provenance': provenance, 'execution_identity': before, 'environment': environment,
                  'reproduction_command': shlex.join(reproduce), 'cases': cases,
                  'timing': {'input_decode_and_optional_replay': input_timing,
                    'ipc_request_serialization': encode_timing, 'ipc_response_decode': decode_timing,
                    'native_model_preparation_wall_ns': frames[0]['preparation_ns'],
                    'persistent_process_complete_exchange': process_timing,
                    'process_scope': 'one actual OS process startup, init once, all commands, three-arm benchmark repetitions, packed full native verification, selected fresh-batch producer and full verification, pipes, output drain, child exit and cleanup',
                    'ipc_only_wall_ns': None, 'startup_only_wall_ns': None,
                    'isolation_limit': 'bounded supervisor observes combined startup/transport/handler wall; does not invent isolated IPC or startup time',
                    'experiment_wall_ns_before_report_write': time.perf_counter_ns() - started,
                    'experiment_parent_cpu_ns_before_report_write': time.process_time_ns() - started_cpu,
                    'experiment_child_cpu_ns_before_report_write': cpu_children_ns() - experiment_children_start},
                  'wire': {'input_bytes': len(wire), 'output_bytes': len(raw_result.stdout),
                           'input_sha256': hashlib.sha256(wire).hexdigest(),
                           'output_sha256': hashlib.sha256(raw_result.stdout).hexdigest()},
                  'demand': {'kind': 'retrospective_fixture', 'arrival_trace': None,
                      'unique_corpus_rows': len(seen), 'shape_row_occurrences': sum(sizes),
                      'shape_windows_overlap': len(seen) < sum(sizes), 'synthetic_rows_added': 0,
                      'original_arrival_ns': None, 'original_deadline_ns': None,
                      'fixture_clock': {'arrival_ns': FIXTURE_ARRIVAL_NS, 'now_ns': FIXTURE_NOW_NS,
                                        'deadline_ns': FIXTURE_DEADLINE_NS, 'use': 'transport semantics only'},
                      'queue_wait_p95_ns': None, 'queue_wait_p99_ns': None,
                      'deadline_success_fraction': None, 'batch_fill_wait_ns': None,
                      'real_demand_verified': False, 'real_deadline_utility_verified': False},
                  'qualification': {'semantic_arithmetic_verified': True, 'pow_qualified': False,
                      'succinct_or_sublinear_proof': False, 'consensus_qualified': False,
                      'production_activation': False, 'public_reward_eligible': False,
                      'model_reward': 0, 'business_credit': 0, 'model_adoption_changed': False},
                  'interpretation': ['Full exact native verifier recomputes router plus selected original base/delta arithmetic.',
                      'No lottery/target/noise/trace PoUW is implemented in this research relation.',
                      'Native ordinary/selected/packed hot ratios compare only disclosed kernel scopes; the ordinary control is retained.',
                      'Selected direct and packed grouped bind the same complete Product and pass the same independent verifier.',
                      'A per-shape kernel candidate reflects only these measured medians; no production dispatch, general speedup, or adoption is inferred.',
                      'The selected producer cost is one observed fresh-batch input commitment plus execution, statement and full verification; it is not compared to a hot-only kernel as a speedup.',
                      'Prior padded W1 end-to-end path performs a different proof workload; no PoUW speedup is inferred.',
                      'Same retained model and partition; no retraining, new adoption decision, or synthetic request fill.']}
        save_json(out / 'report.json', report)
        return report
    except Exception as error:
        failure = {'schema': SCHEMA, 'status': 'failed', 'error_type': type(error).__name__, 'error': str(error),
                   'production_activation': False, 'pow_qualified': False, 'model_reward': 0,
                   'execution_identity': before, 'environment': environment,
                   'observed_cost': {'wall_ns': time.perf_counter_ns() - started,
                                     'parent_cpu_ns': time.process_time_ns() - started_cpu,
                                     'child_cpu_ns': cpu_children_ns() - experiment_children_start},
                   'cost_scope': 'all observed work from execute entry through failure; unavailable observations remain null',
                   'stdout_prefix_bytes': len(raw_result.stdout) if raw_result is not None else None,
                   'stderr_prefix_bytes': len(raw_result.stderr) if raw_result is not None else None}
        if isinstance(error, ProcessFailure):
            failure.update(returncode=error.returncode, stdin_written=error.stdin_written,
                           stdout_truncated=error.stdout_truncated, stderr_truncated=error.stderr_truncated,
                           stdout_prefix_bytes=len(error.stdout), stderr_prefix_bytes=len(error.stderr))
            (out / 'failed-native-stdout.bin').write_bytes(error.stdout)
            (out / 'failed-native-stderr.bin').write_bytes(error.stderr)
        save_json(out / 'failure.json', failure)
        raise


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    for flag in ('model', 'tasks', 'evaluation-bundle', 'runner', 'out'):
        p.add_argument('--' + flag, type=Path, required=True)
    p.add_argument('--bundle-hash', required=True)
    p.add_argument('--partition', default='consumer')
    p.add_argument('--offset', type=int, default=0)
    p.add_argument('--batch-sizes', default='1,4,16,64')
    p.add_argument('--samples', type=int, default=100)
    p.add_argument('--warmup', type=int, default=8)
    p.add_argument('--timeout', type=float, default=60)
    p.add_argument('--replay-source', action='store_true')
    return p


if __name__ == '__main__':
    result = execute(parser().parse_args())
    print(json.dumps({'status': result['status'], 'batch_sizes': [c['batch_size'] for c in result['cases']],
                      'pow_qualified': False, 'production_activation': False, 'model_reward': 0}))

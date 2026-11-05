#!/usr/bin/env python3
"""Reconcile retained shared-material observations without granting qualification.

Usage: shared_material_cost_v2.py --run DIR [--run DIR ...] --out FILE
Optional --scenario-json FILE contains an array of explicit hypothetical cases:
[{"name":"eight-observers","verifiers":8,"stale_fraction_bps":1000}].

Each complete directory is checked against material bytes, actual JSONL records,
process observations and consumed outputs. This reader does not execute W1 or
authenticate the author of a measurement. Same-process repeated full verifiers
are measured local work, not evidence that every independent validator ran.
"""
from __future__ import annotations

import argparse
import hashlib
import inspect
import json
from pathlib import Path
import statistics
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'formal/pon-nakamoto-v1'))
from contract_wire import H, canonical, unique
from experiments import shared_cell_operator_v1 as cell

SCHEMA = 'pon-shared-material-total-cost-v2'
CELL_SCHEMAS = {'pon-shared-cell-operator-v1', 'pon-shared-cell-operator-v2'}
PHASES = {
    'input_validation_and_optional_source_replay', 'material_preparation',
    'all_baseline_diagnostics', 'native_runs_and_evidence_checks',
    'direct_product_consumption', 'independent_scalar_and_numpy_validation',
    'total_experiment_before_final_report_write',
}
TOTAL_PHASE = 'total_experiment_before_final_report_write'
UNKNOWN_GLOBAL = (
    'all_independent_validator_processes', 'wan_transport', 'stale_blocks',
    'competing_miners', 'model_distribution_and_device_loading',
    'actual_confirmation_and_deadline', 'energy',
)


def require(condition, code):
    if not condition:
        raise ValueError(code)


def integer(value, code, *, positive=False):
    require(type(value) is int and (1 if positive else 0) <= value < 1 << 64, code)
    return value


def number_or_unknown(value, code):
    return None if value is None else integer(value, code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def file_bytes(path, maximum=256 * 1024 * 1024):
    require(path.is_file() and not path.is_symlink(), 'MISSING_OR_SYMLINK:' + str(path))
    with path.open('rb') as stream:
        raw = stream.read(maximum + 1)
    require(len(raw) <= maximum, 'OVERSIZE:' + str(path))
    return raw


def read_json(path):
    raw = file_bytes(path, 16 * 1024 * 1024)
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError('NONFINITE_JSON')))


def timing(value):
    require(type(value) is dict and set(value) == {'cpu_ns', 'wall_ns'}, 'TIMING_FIELDS')
    return {key: number_or_unknown(value[key], 'TIMING_NUMBER') for key in value}


def sum_known(values):
    values = list(values)
    return None if any(value is None for value in values) else sum(values)


def timing_sum(values):
    values = [timing(value) for value in values]
    return {key: sum_known(value[key] for value in values) for key in ('cpu_ns', 'wall_ns')}


def recompute_native(records, expected_verifiers):
    """Read the leaves, check advertised parents, and never add overlaps."""
    integer(expected_verifiers, 'VERIFIER_COUNT', positive=True)
    require(expected_verifiers <= 64, 'VERIFIER_LIMIT')
    require(records and records[-1].get('kind') == 'summary', 'NATIVE_SUMMARY_MISSING')
    setup = [row for row in records if row.get('kind') == 'setup']
    searches = [row for row in records if row.get('kind') == 'search']
    verifications = [row for row in records if row.get('kind') == 'verification']
    winners = [row for row in records if row.get('kind') == 'winner']
    require(len(setup) == 1 and len(searches) == len(verifications) == len(winners) > 0,
            'NATIVE_COST_SEQUENCE')
    native, first, reference = [], [], []
    for verification, winner in zip(verifications, winners):
        advertised = verification['native']
        repetitions = verification.get('native_verifiers')
        if repetitions is None:
            require(expected_verifiers == 1, 'UNOBSERVED_VERIFIERS')
            repetitions = [dict(advertised, index=0, product_sha256=winner['product_sha256'])]
        require(type(repetitions) is list and len(repetitions) == expected_verifiers,
                'VERIFIER_COVERAGE')
        for index, replay in enumerate(repetitions):
            require(type(replay.get('index')) is int and replay['index'] == index,
                    'VERIFIER_INDEX')
            require(replay.get('outcome') == advertised.get('outcome') == 'Accepted',
                    'VERIFIER_OUTCOME')
            require(replay.get('product_sha256') == winner['product_sha256'], 'VERIFIER_PRODUCT')
            native.append(timing(replay['timing']))
        require(advertised['timing'] == repetitions[0]['timing'], 'FIRST_VERIFIER_ALIAS')
        first.append(timing(repetitions[0]['timing']))
        require(verification['scalar_reference']['outcome'] == 'Accepted', 'REFERENCE_OUTCOME')
        reference.append(timing(verification['scalar_reference']['timing']))
    attempts = 0
    for search in searches:
        require(type(search.get('attempts')) is list and search['attempts'], 'ATTEMPT_COVERAGE')
        attempts += len(search['attempts'])
        for nonce, attempt in enumerate(search['attempts']):
            require(type(attempt.get('nonce')) is int and attempt['nonce'] == nonce, 'ATTEMPT_SEQUENCE')
            timing(attempt['timing'])
        # Search includes its attempts and challenge/retention overhead; attempts
        # are a disaggregation, never another additive charge.
    result = {
        'setup': timing_sum(row['timing'] for row in setup),
        'all_searches_including_misses': timing_sum(row['timing'] for row in searches),
        'producer_subtotal': timing_sum([row['timing'] for row in setup + searches]),
        'native_verifier_subtotal': timing_sum(native),
        'native_first_verifier_subtotal': timing_sum(first),
        'reference_verifier_subtotal': timing_sum(reference),
        'typed_copy_subtotal': timing_sum(row['typed_copy_timing'] for row in winners),
        'record_build_subtotal': timing_sum(row['record_build_timing'] for row in records[:-1]),
        'attempts': attempts, 'winners': len(winners), 'misses': attempts - len(winners),
        'full_native_verifier_calls': len(native),
    }
    summary = records[-1]
    for key in ('producer_subtotal', 'native_verifier_subtotal', 'reference_verifier_subtotal',
                'typed_copy_subtotal', 'record_build_subtotal'):
        require(timing(summary[key]) == result[key], 'SUMMARY_COST_MISMATCH:' + key)
    for key in ('attempts', 'winners'):
        require(type(summary[key]) is int and summary[key] == result[key], 'SUMMARY_COUNT_MISMATCH:' + key)
    result['serialization_output_subtotal'] = timing(summary['serialization_output_subtotal'])
    result['run_through_before_summary'] = timing(summary['run_through_before_summary'])
    result['additive_work_components'] = ['producer_subtotal', 'native_verifier_subtotal', 'typed_copy_subtotal']
    result['nonadditive_aliases'] = ['setup', 'all_searches_including_misses', 'native_first_verifier_subtotal',
                                     'run_through_before_summary']
    return result



def validate_baseline_identity(baseline, manifest, batch):
    require(baseline.get('implementation') == 'numpy-int64-cached-base-plus-delta-selected-expert',
            'BASELINE_IMPLEMENTATION')
    require(integer(baseline.get('repetitions'), 'BASELINE_REPETITIONS', positive=True) ==
            integer(manifest['execution_parameters'].get('baseline_repetitions'),
                    'BASELINE_MANIFEST_REPETITIONS', positive=True), 'BASELINE_REPETITIONS_BINDING')
    require(integer(baseline.get('warmup_runs'), 'BASELINE_WARMUP') == 8, 'BASELINE_WARMUP')
    require(integer(baseline.get('logical_multiply_adds'), 'BASELINE_LOGICAL_MACS') == 6 * 257 * batch,
            'BASELINE_LOGICAL_MACS')
    require(type(baseline.get('numpy_version')) is str and
            baseline['numpy_version'] == manifest['host']['numpy_version'], 'BASELINE_NUMPY_VERSION')


def validate_baseline_output(baseline, consumed):
    # Called only after validate_consumption independently recomputes this output
    # using both ordinary NumPy execution and the scalar model reference.
    for field in ('predictions', 'routes'):
        actual, expected = baseline.get(field), consumed[field].tolist()
        require(type(actual) is list and len(actual) == len(expected) and
                all(type(value) is int for value in actual) and actual == expected,
                'BASELINE_' + field.upper())


def baseline_measurements(baseline):
    repetitions = integer(baseline.get('repetitions'), 'BASELINE_REPETITIONS', positive=True)
    require(repetitions <= 10000, 'BASELINE_LIMIT')
    result = {}
    for clock, source in (('wall_ns', baseline), ('cpu_ns', baseline.get('cpu'))):
        if source is None:
            result[clock] = None
            continue
        require(type(source) is dict, 'BASELINE_CLOCK')
        samples = source.get('warm_samples_ns')
        require(type(samples) is list and len(samples) == repetitions, 'BASELINE_SAMPLE_COUNT')
        samples = [integer(value, 'BASELINE_SAMPLE', positive=True) for value in samples]
        preparation = integer(source.get('preparation_ns'), 'BASELINE_PREPARATION')
        first = integer(source.get('first_execution_ns'), 'BASELINE_FIRST')
        scalar = integer(source.get('scalar_predict_rows_ns'), 'BASELINE_SCALAR')
        ordered = sorted(samples)
        median = int(statistics.median(samples))
        p95 = ordered[min(len(ordered) - 1, (95 * len(ordered) + 99) // 100 - 1)]
        require(integer(source.get('warm_min_ns'), 'BASELINE_MIN', positive=True) == min(samples),
                'BASELINE_MIN_MISMATCH')
        require(integer(source.get('warm_p95_ns'), 'BASELINE_P95', positive=True) == p95,
                'BASELINE_P95_MISMATCH')
        require(integer(source.get('warm_median_ns'), 'BASELINE_MEDIAN', positive=True) == median,
                'BASELINE_MEDIAN_MISMATCH')
        require(integer(source.get('cold_preparation_plus_execution_ns'), 'BASELINE_COLD', positive=True) == preparation + first,
                'BASELINE_COLD_MISMATCH')
        result[clock] = {'preparation': preparation, 'first_execution': first,
                         'cold_preparation_plus_execution': preparation + first,
                         'warm_median': median, 'warm_min': min(samples), 'warm_p95': p95,
                         'warm_samples_sum': sum(samples), 'scalar_predict_rows': scalar,
                         'timed_diagnostic_subtotal': preparation + first + sum(samples) + scalar,
                         'sample_count': repetitions}
    return result



def phase_measurements(report, measured_baseline, *, require_cpu):
    wall = report.get('phases_ns')
    cpu = report.get('phase_cpu_ns', {})
    require(type(wall) is dict and set(wall) == PHASES, 'PHASE_WALL_COVERAGE')
    require(type(cpu) is dict and ((not cpu and not require_cpu) or set(cpu) == PHASES),
            'PHASE_CPU_COVERAGE')
    for name, values in (('wall_ns', wall), ('cpu_ns', cpu)):
        for value in values.values():
            integer(value, 'PHASE_NUMBER:' + name)
        if values:
            require(values[TOTAL_PHASE] >= sum(value for key, value in values.items() if key != TOTAL_PHASE),
                    'PHASE_ENVELOPE:' + name)
        measured = measured_baseline[name]
        if measured is not None:
            require('all_baseline_diagnostics' in values, 'BASELINE_PHASE_MISSING:' + name)
            # The eight untimed warmups and bookkeeping remain in this parent;
            # the timed children are a subset, never another additive charge.
            require(values['all_baseline_diagnostics'] >= measured['timed_diagnostic_subtotal'],
                    'BASELINE_PHASE_ENVELOPE:' + name)
    if require_cpu:
        require(measured_baseline['cpu_ns'] is not None, 'V2_BASELINE_CPU_MISSING')
    return cpu, wall


def validate_process_native_envelope(process, native):
    for key in ('wall_ns', 'supervisor_cpu_ns', 'child_user_cpu_ns', 'child_system_cpu_ns'):
        integer(process.get(key), 'PROCESS_CLOCK:' + key)
    run = native['run_through_before_summary']
    require(process['wall_ns'] >= integer(run['wall_ns'], 'NATIVE_RUN_WALL'),
            'PROCESS_NATIVE_WALL_ENVELOPE')
    # Native thread CPU is contained in the entire completed child's user+system
    # CPU. No tolerance is inferred or silently added across these clock scopes.
    require(process['child_user_cpu_ns'] + process['child_system_cpu_ns'] >=
            integer(run['cpu_ns'], 'NATIVE_RUN_CPU'), 'PROCESS_NATIVE_CPU_ENVELOPE')


def validate_native_phase_envelope(phase_cpu, phases_wall, processes):
    require(phases_wall['native_runs_and_evidence_checks'] >= sum(row['wall_ns'] for row in processes),
            'NATIVE_PHASE_ENVELOPE:wall_ns')
    if phase_cpu:
        require(phase_cpu['native_runs_and_evidence_checks'] >= sum(row['supervisor_cpu_ns'] for row in processes),
                'NATIVE_PHASE_ENVELOPE:cpu_ns')


def validate_cost_aliases(report, processes, tiles, cycles, baseline):
    child_wall = sum(row['wall_ns'] for row in processes)
    expected = {
        'native_process_wall_ns': child_wall,
        'native_child_cpu_ns': sum(row['child_user_cpu_ns'] + row['child_system_cpu_ns'] for row in processes),
        'all_local_pipe_bytes': sum(row['stdin_bytes'] + row['stdout_bytes'] + row['stderr_bytes'] for row in processes),
        'canonical_matrices_bytes': sum(len(tile['material']) for tile in tiles),
        'proof_bytes': cycles * len(tiles) * cell.PROOF_BYTES,
        'typed_product_bytes': cycles * len(tiles) * cell.CELLS * 4,
        'native_wall_to_one_ordinary_warm_batch_ratio': child_wall / baseline['wall_ns']['warm_median'],
        'native_wall_to_one_ordinary_cold_batch_ratio': child_wall / baseline['wall_ns']['cold_preparation_plus_execution'],
        'transmission_scope': 'actual local stdin/stdout/stderr; proof and product bytes also itemized; no WAN latency/bandwidth assumption',
        'same_inputs_cycles': cycles, 'distinct_application_batches': 1,
        'cache_credit': 'repeated challenge cycles recompute the same output; no extra useful-output credit',
        'mining_and_proof_and_full_verification_included': True,
    }
    actual = report.get('costs')
    require(type(actual) is dict and set(actual) == set(expected), 'REPORT_COST_ALIAS_FIELDS')
    for key, value in expected.items():
        require(type(actual[key]) is type(value) and actual[key] == value, 'REPORT_COST_ALIAS:' + key)


def mathematical_stream_digest(records):
    """Digest lottery and full proof/product bytes after native record validation."""
    stream = []
    for row in records:
        if row['kind'] == 'search':
            stream.append({key: row[key] for key in ('kind', 'cycle', 'task', 'target')} | {
                'attempts': [{key: attempt[key] for key in
                              ('nonce', 'challenge', 'trace', 'ticket', 'target_hit', 'proof_materialized')}
                             for attempt in row['attempts']]})
        elif row['kind'] == 'winner':
            stream.append({key: row[key] for key in
                           ('kind', 'cycle', 'task', 'target', 'challenge', 'ticket', 'proof_hex', 'product_hex')})
    return digest(canonical(stream))


def process_envelope(report, native_child_cpu):
    """The process tree total owns native and non-native children exactly once."""
    value = report.get('process_cpu_ns')
    if value is None:
        return {'cpu_ns': None, 'all_children_cpu_ns': None,
                'native_children_cpu_ns_subset': native_child_cpu,
                'scope': 'complete process-tree CPU unavailable; native child subtotal is only partial'}
    require(type(value) is dict, 'PROCESS_CPU_ENVELOPE')
    parent = integer(value.get('supervisor_through_before_final_report'), 'PROCESS_CPU_PARENT')
    children = sum(integer(value.get(key), 'PROCESS_CPU_CHILDREN')
                   for key in ('all_children_user', 'all_children_system'))
    require(type(value.get('scope')) is str and value['scope'], 'PROCESS_CPU_SCOPE')
    require(children >= integer(native_child_cpu, 'PROCESS_CPU_NATIVE_SUBTOTAL'), 'PROCESS_CPU_CHILD_SUBSET')
    phase_total = report.get('phase_cpu_ns', {}).get('total_experiment_before_final_report_write')
    require(parent == integer(phase_total, 'PROCESS_CPU_PHASE_TOTAL'), 'PROCESS_CPU_PARENT_ALIAS')
    return {'cpu_ns': parent + children, 'supervisor_cpu_ns': parent,
            'all_children_cpu_ns': children, 'native_children_cpu_ns_subset': native_child_cpu,
            'scope': value['scope'], 'native_subtotal_added_again': False}


def validate_materials(directory, manifest):
    """Bind even interrupted runs to the same frozen model, rows and five tiles."""
    require(manifest.get('schema') in CELL_SCHEMAS, 'CELL_SCHEMA')
    model, rows = read_json(directory / 'model.json'), read_json(directory / 'tasks.json')
    provenance = manifest['provenance']
    require(H('artifact', canonical(model)).hex() == provenance['model_artifact'], 'MODEL_ARTIFACT')
    require(digest(canonical(model)) == provenance['model_sha256'], 'MODEL_DIGEST')
    require(cell.partition_manifest(rows) == provenance['selected_tasks'], 'SELECTED_TASKS')
    require(len(rows) == provenance['batch_size'], 'BATCH_SIZE')
    tiles, _ = cell.build_tiles(model, rows)
    require([{k: v for k, v in tile.items() if k != 'material'} for tile in tiles] == manifest['tiles'],
            'MATERIAL_MANIFEST_BINDING')
    for tile in tiles:
        require(file_bytes(directory / f"tile-{tile['index']}" / 'material.bin') == tile['material'],
                'MATERIAL_BYTES')
    for key, expected in {'w1_product_multiply_adds_per_batch': 5 * 64 ** 3,
                          'all_five_operator_multiply_adds': 15 * 257 * len(rows),
                          'ordinary_cached_selected_expert_multiply_adds': 6 * 257 * len(rows)}.items():
        require(type(manifest['geometry'].get(key)) is int and manifest['geometry'][key] == expected, 'GEOMETRY')
    identity = {'model': provenance['model_artifact'], 'selected_tasks': provenance['selected_tasks'],
                'materials': [tile['material_sha256'] for tile in tiles]}
    return model, rows, tiles, identity


def paired_identity(manifest, material_identity):
    parameters = manifest['execution_parameters']
    cycles = integer(parameters['cycles'], 'CYCLES', positive=True)
    verifiers = integer(parameters.get('verifiers', 1), 'VERIFIER_COUNT', positive=True)
    attempts = integer(parameters['max_attempts'], 'MAX_ATTEMPTS', positive=True)
    target_index = integer(parameters['target_index'], 'TARGET_INDEX')
    require(cycles <= 64 and verifiers <= 64 and attempts <= 4096 and target_index <= 1, 'PARAMETER_LIMIT')
    cell.decode_hex(parameters['seed'], 32, 'SEED')
    expected_target = (bytes([127 if target_index == 0 else 7]) + bytes([255]) * 31).hex()
    require(parameters['target'] == expected_target, 'TARGET_BINDING')
    require(parameters['arithmetic'] in ('full-limb', 'transposed'), 'ARITHMETIC')
    if manifest['schema'].endswith('v2'):
        require(parameters.get('preparation') in ('dense', 'sparse') and
                parameters.get('verifier_scope') == 'same_process_sequential_full_replay', 'V2_EXECUTION_SCOPE')
    comparison = {'source': manifest['execution_source'], 'materials': material_identity,
                  'target': parameters['target'], 'seed': parameters['seed'], 'cycles': cycles,
                  'verifiers': verifiers, 'max_attempts': attempts,
                  'baseline_repetitions': parameters['baseline_repetitions']}
    return digest(canonical(comparison))


def incomplete_run(directory, report, manifest, *, validated=None):
    """Retain partial spend and verify its cohort, without crediting an output."""
    _, _, tiles, identity = validated if validated is not None else validate_materials(directory, manifest)
    comparison = paired_identity(manifest, identity)
    processes, missing, fingerprints = [], [], []
    for index, material in enumerate(tiles):
        tile = directory / f'tile-{index}'
        filenames = [name for name in ('process-failure.json', 'process.json') if (tile / name).is_file()]
        require(len(filenames) <= 1, 'PARTIAL_PROCESS_OVERLAP')
        if not filenames:
            missing.append(index)
            continue
        filename = filenames[0]
        observed = read_json(tile / filename)
        raw = file_bytes(tile / 'native.stdout.jsonl')
        stderr = file_bytes(tile / 'native.stderr.txt', 65536)
        require(observed.get('runner_sha256') == manifest['execution_source']['native_runner_sha256'],
                'PARTIAL_RUNNER_BINDING')
        if filename == 'process-failure.json':
            for key, expected in (('stdout_retained_bytes', len(raw)), ('stderr_retained_bytes', len(stderr))):
                require(type(observed.get(key)) is int and observed[key] == expected, 'PARTIAL_PROCESS_COUNT')
            written = number_or_unknown(observed.get('stdin_written'), 'PARTIAL_STDIN')
            require(written is None or written <= len(material['material']), 'PARTIAL_STDIN_BOUND')
            io_scope = 'retained bounded output prefix and observed stdin writes; not complete exchange or WAN'
        else:
            for key, expected in (('index', index), ('stdin_bytes', len(material['material'])),
                                  ('stdout_bytes', len(raw)), ('stderr_bytes', len(stderr))):
                require(type(observed.get(key)) is int and observed[key] == expected, 'PARTIAL_PROCESS_COUNT')
            require(observed.get('stdout_sha256') == digest(raw), 'PARTIAL_STDOUT_BINDING')
            written = len(material['material'])
            io_scope = 'one finished local child exchange; result was not credited'
        fingerprints.append({'tile': index, 'stdout': digest(raw), 'stderr': digest(stderr),
                             'process': digest(json.dumps(observed, sort_keys=True, allow_nan=False).encode())})
        processes.append({'tile': index, 'file': filename,
                          'cpu_ns': sum_known(number_or_unknown(observed.get(key), 'PARTIAL_CPU')
                                              for key in ('child_user_cpu_ns', 'child_system_cpu_ns')),
                          'wall_ns': number_or_unknown(observed.get('wall_ns'), 'PARTIAL_WALL'),
                          'retained_local_pipe_bytes': sum_known([written, len(raw), len(stderr)]),
                          'local_pipe_scope': io_scope, 'internal_attempt_coverage': 'unknown'})
    return {'directory': str(directory), 'status': 'incomplete',
            'record_fingerprint': digest(canonical({'processes': fingerprints,
                'report': digest(json.dumps(report, sort_keys=True, allow_nan=False).encode())})),
            'material_identity': identity, 'paired_comparison_identity': comparison,
            'report_status': report.get('status'), 'source': manifest['execution_source'],
            'parameters': manifest['execution_parameters'],
            'partial_processes': processes, 'not_observed_tiles': missing,
            'observed_partial_child_cpu_ns': sum_known(row['cpu_ns'] for row in processes) if processes else None,
            'observed_partial_sequential_child_wall_ns': sum_known(row['wall_ns'] for row in processes) if processes else None,
            'observed_partial_supervisor_cpu_ns': number_or_unknown(report.get('supervisor_cpu_ns'), 'PARTIAL_SUPERVISOR_CPU'),
            'observed_elapsed_wall_ns': number_or_unknown(report.get('elapsed_ns'), 'PARTIAL_ELAPSED'),
            'distinct_application_batches_credited': 0, 'full_system_cost': None,
            'net_compute_benefit': None, 'qualification': False}


def analyze_run(directory):
    directory = Path(directory).resolve()
    manifest = read_json(directory / 'manifest.json')
    report = read_json(directory / 'report.json') if (directory / 'report.json').is_file() else read_json(directory / 'failure.json')
    validated = validate_materials(directory, manifest)
    model, rows, tiles, identity = validated
    comparison = paired_identity(manifest, identity)
    require(report.get('schema') == manifest['schema'], 'REPORT_SCHEMA_BINDING')
    if report.get('status') != 'complete':
        return incomplete_run(directory, report, manifest, validated=validated)
    require(report.get('schema') == manifest['schema'], 'REPORT_SCHEMA_BINDING')
    for key in ('provenance', 'execution_source', 'execution_parameters', 'geometry', 'host'):
        require(report.get(key) == manifest.get(key), 'REPORT_BINDING:' + key)
    require(manifest.get('distinct_useful_batch_outputs') == 1 and
            manifest.get('repeated_challenge_outputs_are_new_application_work') is False, 'DUPLICATE_OUTPUT_CREDIT')
    parameters = manifest['execution_parameters']
    cycles = integer(parameters['cycles'], 'CYCLES', positive=True)
    require(cycles <= 64, 'CYCLE_LIMIT')
    verifiers = integer(parameters.get('verifiers', 1), 'VERIFIER_COUNT', positive=True)
    baseline = read_json(directory / 'baseline.json')
    require(baseline == report['baseline'], 'BASELINE_REPORT_BINDING')
    validate_baseline_identity(baseline, manifest, len(rows))
    measured_baseline = baseline_measurements(baseline)
    phase_cpu, phases_wall = phase_measurements(report, measured_baseline,
                                               require_cpu=manifest['schema'].endswith('v2'))
    require(type(report.get('native')) is list and len(report['native']) == len(tiles), 'REPORT_NATIVE_COVERAGE')
    native, processes, stdout_hashes, mathematical_streams = [], [], [], []
    products = [dict() for _ in range(cycles)]
    for index, tile in enumerate(tiles):
        place = directory / f'tile-{index}'
        require(file_bytes(place / 'material.bin') == tile['material'], 'MATERIAL_BYTES')
        raw = file_bytes(place / 'native.stdout.jsonl')
        stderr = file_bytes(place / 'native.stderr.txt', 65536)
        process, accepted = read_json(place / 'process.json'), read_json(place / 'accepted.json')
        require(process.get('returncode') == 0 and type(process.get('returncode')) is int, 'PROCESS_FAILURE')
        for key, expected in {'index': index, 'stdin_bytes': len(tile['material']), 'stdout_bytes': len(raw),
                              'stderr_bytes': len(stderr)}.items():
            require(type(process.get(key)) is int and process[key] == expected, 'PROCESS_COUNT')
        runner_hash = manifest['execution_source']['native_runner_sha256']
        require(process.get('runner_sha256') == process.get('runner_sha256_after') == runner_hash and
                accepted.get('runner_sha256') == runner_hash, 'RUNNER_BINDING')
        require(process.get('stdout_sha256') == accepted.get('stdout_sha256') == digest(raw), 'STDOUT_BINDING')
        require(accepted.get('tile') == index and accepted.get('task') == tile['task'] and
                accepted.get('verified_cycles') == cycles, 'ACCEPTED_BINDING')
        tile_seed = H('shared-cell-seed-v1', bytes.fromhex(parameters['seed']), bytes.fromhex(tile['task'])).hex()
        kwargs = {'seed': tile_seed, 'target_index': parameters['target_index'],
                  'max_attempts': parameters['max_attempts'], 'arithmetic': parameters['arithmetic']}
        if manifest['schema'].endswith('v2'):
            # The native parser owns version-specific request and proof binding.
            supported = inspect.signature(cell.native_products).parameters
            require('preparation' in supported and 'verifiers' in supported, 'V2_NATIVE_PARSER_REQUIRED')
            kwargs.update(preparation=parameters['preparation'], verifiers=verifiers)
        verified, records = cell.native_products(raw, tiles, index, cycles, **kwargs)
        for cycle, product in enumerate(verified):
            products[cycle][index] = product
        native.append(recompute_native(records, verifiers))
        validate_process_native_envelope(process, native[-1])
        require(canonical(report['native'][index]) == canonical(dict(process, native_summary=records[-1])),
                'REPORT_NATIVE_ALIAS')
        mathematical_streams.append(mathematical_stream_digest(records))
        processes.append(process)
        stdout_hashes.append(digest(raw))
    validate_native_phase_envelope(phase_cpu, phases_wall, processes)
    output_hashes = []
    require(len(report['outputs']) == cycles, 'OUTPUT_COVERAGE')
    for cycle in range(cycles):
        consumed = cell.consume_products(tiles, products[cycle], len(rows))
        cell.validate_consumption(model, rows, consumed)
        if cycle == 0:
            validate_baseline_output(baseline, consumed)
        output = {'cycle': cycle, 'predictions': consumed['predictions'].tolist(),
                  'routes': consumed['routes'].tolist(), 'logits': consumed['logits'].tolist(),
                  'all_operator_outputs': consumed['products'].tolist()}
        require(file_bytes(directory / f'output-{cycle}.json') == canonical(output), 'OUTPUT_BYTES')
        require(report['outputs'][cycle] == {'cycle': cycle, 'sha256': digest(canonical(output))}, 'OUTPUT_HASH')
        # Cycle labels do not make the same numerical application result new.
        output_hashes.append(digest(canonical({k: v for k, v in output.items() if k != 'cycle'})))
    require(len(set(output_hashes)) == 1, 'REPEATED_OUTPUT_CHANGED')
    total = {key: timing_sum(item[key] for item in native) for key in
             ('setup', 'all_searches_including_misses', 'producer_subtotal', 'native_verifier_subtotal',
              'native_first_verifier_subtotal', 'reference_verifier_subtotal', 'typed_copy_subtotal',
              'record_build_subtotal', 'serialization_output_subtotal', 'run_through_before_summary')}
    child_cpu = sum(row['child_user_cpu_ns'] + row['child_system_cpu_ns'] for row in processes)
    child_wall = sum(row['wall_ns'] for row in processes)
    supervisor_cpu = sum(row['supervisor_cpu_ns'] for row in processes)
    validate_cost_aliases(report, processes, tiles, cycles, measured_baseline)
    process_tree = process_envelope(report, child_cpu)
    baseline_cpu = measured_baseline['cpu_ns']
    return {
        'directory': str(directory), 'status': 'complete_consistent_observation',
        'record_fingerprint': digest(canonical(stdout_hashes)),
        'mathematical_stream_sha256': digest(canonical(mathematical_streams)),
        'material_identity': identity, 'application_output_sha256': output_hashes[0],
        'paired_comparison_identity': comparison,
        'source': manifest['execution_source'], 'parameters': parameters,
        'native_leaf_costs': total, 'attempts': sum(item['attempts'] for item in native),
        'misses': sum(item['misses'] for item in native),
        'winning_proofs': sum(item['winners'] for item in native),
        'full_native_verifier_calls': sum(item['full_native_verifier_calls'] for item in native),
        'observed_verifier_scope': 'same_process_sequential_full_replay; not independent validator coverage',
        'process_observations': {'child_cpu_ns': child_cpu, 'sequential_child_wall_ns': child_wall,
                                 'supervisor_exchange_cpu_ns': supervisor_cpu,
                                 'local_pipe_bytes': sum(row['stdin_bytes'] + row['stdout_bytes'] + row['stderr_bytes'] for row in processes)},
        'phase_cpu_ns': phase_cpu, 'phase_wall_ns': phases_wall,
        'research_campaign_cost': {'cpu_ns': process_tree['cpu_ns'], 'process_tree': process_tree, 'wall_ns': phases_wall[TOTAL_PHASE],
                                  'scope': 'consumer.run() through before final report write; excludes Python startup/import/exit; includes load/replay, baseline repetitions, diagnostics and product consumption. CPU is parent plus all children, each once; native children are a subset. Missing process-tree observation remains unknown; not production inference latency'},
        'baseline': measured_baseline,
        'local_same_clock_comparison': {
            'child_wall_to_ordinary_warm_wall_ratio': child_wall / measured_baseline['wall_ns']['warm_median'],
            'child_cpu_to_ordinary_warm_cpu_ratio': child_cpu / baseline_cpu['warm_median'] if baseline_cpu else None,
            'scope': 'observed local child only; diagnostics included; no global net-saving claim'},
        'bytes': {'canonical_material': sum(len(tile['material']) for tile in tiles),
                  'proofs_all_cycles': cycles * len(tiles) * cell.PROOF_BYTES,
                  'typed_products_all_cycles': cycles * len(tiles) * cell.CELLS * 4,
                  'proof_and_product_bytes_are_not_extra_pipe_traffic': True},
        'distinct_application_batches_credited': 1,
        'missing_global_observations': list(UNKNOWN_GLOBAL), 'full_system_cost': None,
        'net_compute_benefit': None, 'model_loading_scope': 'input validation plus optional source replay; not isolated device/model load',
        'model_adoption_and_reward': 'unchanged; this reader cannot grant adoption or payment',
        'native_execution_authenticated_by_reader': False, 'qualification': False,
    }


def scenario(run, value):
    require(type(value) is dict and set(value) == {'name', 'verifiers', 'stale_fraction_bps'}, 'SCENARIO_FIELDS')
    require(type(value['name']) is str and 1 <= len(value['name']) <= 80, 'SCENARIO_NAME')
    verifiers = integer(value['verifiers'], 'SCENARIO_VERIFIERS', positive=True)
    require(verifiers <= 100000, 'SCENARIO_VERIFIER_LIMIT')
    stale = integer(value['stale_fraction_bps'], 'SCENARIO_STALE')
    require(stale < 10000, 'SCENARIO_NO_LIVE_OUTPUT')
    costs = run['native_leaf_costs']
    cpu = sum_known([costs['producer_subtotal']['cpu_ns'],
                     None if costs['native_first_verifier_subtotal']['cpu_ns'] is None
                     else verifiers * costs['native_first_verifier_subtotal']['cpu_ns'],
                     costs['typed_copy_subtotal']['cpu_ns']])
    # This is explicitly an iid retry model, not measured stale-node behavior.
    return {'name': value['name'], 'scope': 'hypothetical linear fanout and iid whole-batch stale retry sensitivity',
            'verifiers_assumed': verifiers, 'stale_fraction_bps_assumed': stale,
            'partial_work_cpu_ns_per_distinct_live_batch':
                {'numerator': cpu * 10000, 'denominator': 10000 - stale} if cpu is not None else None,
            'canonical_proof_fanout_bytes_per_distinct_live_batch':
                {'numerator': run['bytes']['proofs_all_cycles'] * verifiers * 10000,
                 'denominator': 10000 - stale},
            'wall_ns': None, 'total_system_cpu_ns': None, 'net_compute_benefit': None,
            'unpriced_and_unmeasured': list(UNKNOWN_GLOBAL),
            'model_load_and_consumer_not_in_partial_work': True, 'qualification': False}


def reconcile(directories, scenarios=()):
    require(type(directories) in (list, tuple) and 1 <= len(directories) <= 100, 'RUN_COUNT')
    require(type(scenarios) in (list, tuple) and len(scenarios) <= 100, 'SCENARIO_COUNT')
    runs = [analyze_run(path) for path in directories]
    completed = [run for run in runs if run['status'] == 'complete_consistent_observation']
    fingerprints = [run['record_fingerprint'] for run in runs]
    require(len(set(fingerprints)) == len(fingerprints), 'DUPLICATE_PHYSICAL_OBSERVATION')
    identities = {digest(canonical(run['material_identity'])) for run in runs}
    require(len(identities) <= 1, 'MATERIAL_COHORT_MISMATCH')
    require(len({run.get('application_output_sha256') for run in completed}) <= 1, 'APPLICATION_OUTPUT_COHORT_MISMATCH')
    groups = {}
    for index, run in enumerate(runs):
        groups.setdefault(run['paired_comparison_identity'], []).append(index)
    compared_streams = []
    for indices in groups.values():
        ready = [index for index in indices if runs[index]['status'] == 'complete_consistent_observation']
        streams = {runs[index]['mathematical_stream_sha256'] for index in ready}
        require(len(streams) <= 1, 'PAIRED_MATHEMATICAL_STREAM_MISMATCH')
        compared_streams.append({'run_indices': indices, 'complete_run_indices': ready,
                                 'mathematical_stream_sha256': next(iter(streams)) if streams else None,
                                 'all_group_runs_complete': len(ready) == len(indices)})
    return {'schema': SCHEMA, 'status': 'complete_local_observations' if len(completed) == len(runs) else 'incomplete_local_observations',
            'runs': runs, 'paired_comparison_groups': list(groups.values()),
            'paired_mathematical_streams': compared_streams,
            'distinct_material_cohorts_observed': len(identities),
            'distinct_material_batches_across_all_arms': 1 if completed else 0,
            'additional_useful_output_credit_from_cycles_or_arms': 0,
            'scenarios': [{'run_index': index, 'cases': [scenario(run, case) for case in scenarios]}
                          for index, run in enumerate(runs) if run['status'] == 'complete_consistent_observation'],
            'coverage': {key: None for key in UNKNOWN_GLOBAL},
            'full_system_cost': None, 'net_compute_benefit': None,
            'cost_rule': 'CPU sums only disjoint process scopes; inner phases are breakdowns. Wall is sequential local or measured end-to-end, never summed over independent nodes. Bytes are not CPU or money.',
            'qualification': False, 'production_activation': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='append', type=Path, required=True)
    parser.add_argument('--scenario-json', type=Path)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(argv)
    result = reconcile(args.run, read_json(args.scenario_json) if args.scenario_json else [])
    with args.out.open('x') as stream:
        json.dump(result, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write('\n')
    print(json.dumps({'schema': SCHEMA, 'status': result['status'], 'runs': len(result['runs']),
                      'net_compute_benefit': None, 'qualification': False}, sort_keys=True))
    return 0 if result['status'] == 'complete_local_observations' else 2


if __name__ == '__main__':
    raise SystemExit(main())

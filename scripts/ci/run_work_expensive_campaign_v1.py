#!/usr/bin/env python3
"""Run the source-bound finite W1/Mode-A cost study; preserve every failed shard.

The fixed attempt census is separate from the first-hit shared-material search.
Mode A binds five actual source-routing materials, not the synthetic strategy
grid. No process receipt here is a live task, fork-choice or production verdict.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'formal/pon-nakamoto-v1'))
from bounded_process import ProcessFailure, run_bounded
from contract_wire import H, canonical, unique
from experiments.shared_cell_operator_v1 import (DIM, N, OPERATORS, OUTPUT_ROWS, Q,
    build_tiles, consume_products, hardware_snapshot, native_products, numpy_operator,
    prepare_numpy, validate_consumption)
from evaluation_bundle import partition_manifest
from model_contract import load_model_bytes
from pon_work_expensive_reader_v1 import inspect
from work_expensive_mode_a import ModeAResearch, PROFILE


def require(ok, code):
    if not ok:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path, maximum=8*1024*1024):
    with Path(path).open('rb') as source:
        value = source.read(maximum+1)
    require(len(value) <= maximum, 'FILE_BOUND')
    return value


def save(path, value):
    with Path(path).open('x') as output:
        json.dump(value, output, sort_keys=True, indent=2, allow_nan=False)
        output.write('\n')


def source_identity():
    paths = {ROOT/'trillionnium/Cargo.lock', ROOT/'trillionnium/Cargo.toml',
             ROOT/'rust-toolchain.toml', Path(__file__).resolve(),
             ROOT/'scripts/pon_work_expensive_reader_v1.py'}
    for crate in ('trnm-crypto-primitives', 'trnm-protocol'):
        directory = ROOT/'trillionnium/crates'/crate
        paths.add(directory/'Cargo.toml')
        paths.update(directory.rglob('*.rs'))
    # Include the actually imported transitive ROOT modules, not only the direct
    # imports above. ledger/evaluation/signature/backend execute during imports.
    loaded_sources = set()
    for module in tuple(sys.modules.values()):
        location = getattr(module, '__file__', None)
        if location is None:
            continue
        path = Path(location).resolve()
        try:
            path.relative_to(ROOT)
        except ValueError:
            continue
        if path.suffix in ('.py', '.pyc') and path.is_file():
            paths.add(path)
            loaded_sources.add(str(path.relative_to(ROOT)))
    paths.update((ROOT/'config/pon').rglob('*.json'))
    files = {str(path.relative_to(ROOT)): sha(path.read_bytes()) for path in sorted(paths)}
    def git(*arguments):
        return subprocess.check_output(['git', *arguments], cwd=ROOT, text=True,
                                       timeout=30).strip()
    dirty = git('status', '--porcelain=v1', '--untracked-files=normal')
    return {'git_base_head': git('rev-parse', 'HEAD'),
            'git_base_tree': git('rev-parse', 'HEAD^{tree}'),
            'git_dirty_porcelain': dirty, 'git_worktree_clean': not dirty,
            'head_tree_is_executed_source': False,
            'worktree_source_manifest_sha256': sha(canonical(files)),
            'loaded_root_python_paths': sorted(loaded_sources), 'files_sha256': files,
            'scope': 'observed worktree file bytes, loaded ROOT Python sources and all config/pon JSON; '
                     'git base metadata is not an execution-source claim; native binary/source binding '
                     'requires the separately retained exact build command and build manifest'}


def exchange(command, data, directory, timeout):
    directory.mkdir()
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    started = time.perf_counter_ns()
    failure = None
    try:
        result = run_bounded(command, data, timeout=timeout, stdout_limit=256*1024*1024,
                             stderr_limit=1024*1024, cwd=ROOT)
        stdout, stderr, code = result.stdout, result.stderr, result.returncode
    except ProcessFailure as error:
        stdout, stderr, code = error.stdout, error.stderr, error.returncode
        failure = str(error)
    except (ValueError, OSError) as error:
        stdout, stderr, code = b'', str(error).encode(), None
        failure = str(error)
    elapsed = time.perf_counter_ns()-started
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    (directory/'native.jsonl').write_bytes(stdout)
    (directory/'stderr.txt').write_bytes(stderr)
    observed = {'command': command, 'returncode': code, 'failure': failure,
                'wall_ns': elapsed, 'child_user_cpu_ns': round((after.ru_utime-before.ru_utime)*1e9),
                'child_system_cpu_ns': round((after.ru_stime-before.ru_stime)*1e9),
                'child_peak_rss_so_far_kib': after.ru_maxrss,
                'rss_scope': 'RUSAGE_CHILDREN maximum so far, not isolated per-shard RSS or enforced RSS quota',
                'stdin_bytes': len(data), 'stdout_bytes': len(stdout), 'stderr_bytes': len(stderr),
                'stdout_sha256': sha(stdout), 'stderr_sha256': sha(stderr),
                'timeout_seconds': timeout,
                'scope': 'complete owned child exchange including process start, evidence and cleanup'}
    save(directory/'process.json', observed)
    return stdout, observed


def write_frozen_bytes(path, raw):
    # Owned exclusive snapshots; read-only permissions are not an adversarial
    # filesystem capability. Consumers and final readback still verify bytes.
    with path.open('xb') as target:
        target.write(raw)
        target.flush()
        os.fsync(target.fileno())
    path.chmod(0o444)


def freeze_materials(material_dir, out, seed_replay=None):
    started, cpu = time.perf_counter_ns(), time.process_time_ns()
    manifest_raw = read(material_dir/'manifest.json')
    manifest = json.loads(manifest_raw, object_pairs_hook=unique)
    require(type(manifest) is dict and manifest.get('schema') == 'pon-shared-cell-operator-v1',
            'MATERIAL_MANIFEST_SCHEMA')
    provenance = manifest['provenance']
    model_raw, task_raw = read(material_dir/'model.json'), read(material_dir/'tasks.json')
    model = load_model_bytes(model_raw, bytes.fromhex(provenance['model_artifact']))
    tasks = json.loads(task_raw, object_pairs_hook=unique)
    require(model['source'] == provenance['source_commit'] and
            sha(canonical(model)) == provenance['model_sha256'] and
            partition_manifest(tasks) == provenance['selected_tasks'], 'MODEL_TASK_PROVENANCE')
    tiles, full_bounds = build_tiles(model, tasks)
    require(len(tiles) == 5 and type(manifest.get('tiles')) is list and
            len(manifest['tiles']) == len(tiles), 'MATERIAL_TILE_COUNT')
    expected_shapes = {'work_profile': PROFILE, 'field_modulus': Q,
                       'operator_order': list(OPERATORS), 'operator_shape': [3, DIM],
                       'packed_weight_shape': [OUTPUT_ROWS, DIM],
                       'input_shape': [DIM, len(tasks)], 'full_feature_coverage': DIM,
                       'distinct_useful_batch_outputs': 1,
                       'repeated_challenge_outputs_are_new_application_work': False}
    require(canonical({key: manifest.get(key) for key in expected_shapes}) == canonical(expected_shapes),
            'MATERIAL_OPERATOR_SHAPES')
    expected_geometry = {'w1_product_multiply_adds_per_batch': len(tiles) * N**3,
        'all_five_operator_multiply_adds': OUTPUT_ROWS * DIM * len(tasks),
        'ordinary_cached_selected_expert_multiply_adds': 6 * DIM * len(tasks),
        'unselected_expert_multiply_adds': 6 * DIM * len(tasks),
        'unmerged_base_delta_extra_multiply_adds': 3 * DIM * len(tasks),
        'structural_padding_multiply_adds': len(tiles) * N**3 - OUTPUT_ROWS * DIM * len(tasks),
        'packed_operator_density_fraction': [OUTPUT_ROWS * DIM * len(tasks), len(tiles) * N**3],
        'ordinary_required_density_fraction': [6 * DIM * len(tasks), len(tiles) * N**3],
        'output_rows_zero_padded': N - OUTPUT_ROWS, 'request_columns_zero_padded': N - len(tasks),
        'inner_coordinates_zero_padded': len(tiles) * N - DIM}
    expected_decode = {'method': 'centered-field-then-integer-tile-sum',
                      'whole_operator_absolute_bounds': full_bounds,
                      'contract_bound': DIM * 32767 * 8, 'strict_half_modulus': Q // 2}
    require(canonical(manifest.get('geometry')) == canonical(expected_geometry) and
            canonical(manifest.get('signed_decode')) == canonical(expected_decode), 'MATERIAL_NUMERIC_GEOMETRY')
    frozen_dir = out/'frozen-inputs'
    frozen_dir.mkdir()
    for name, raw in (('manifest.json', manifest_raw), ('model.json', model_raw), ('tasks.json', task_raw)):
        write_frozen_bytes(frozen_dir/name, raw)
    frozen_inputs = []
    for index, tile in enumerate(tiles):
        require(tile['material'] == read(material_dir/f'tile-{index}'/'material.bin', 32768), 'MATERIAL_REPRODUCTION')
        expected = {key: value for key, value in tile.items() if key != 'material'}
        require(canonical(expected) == canonical(manifest['tiles'][index]), 'MATERIAL_MANIFEST')
        path = frozen_dir/f'tile-{index}.bin'
        write_frozen_bytes(path, tile['material'])
        require(read(path, 32768) == tile['material'], 'FROZEN_COPY_READBACK')
        frozen_inputs.append({'tile': index, 'path': str(path.resolve()),
                              'task': tile['task'], 'material_sha256': tile['material_sha256'],
                              'a_sha256': tile['a_sha256'], 'b_sha256': tile['b_sha256'],
                              'material_bytes': len(tile['material'])})
    normal = numpy_operator(prepare_numpy(model, tasks))
    routes = normal['routes'].tolist()
    route_contract = {'routes': routes, 'groups': [[i for i, route in enumerate(routes) if route == e] for e in range(3)],
                      'ties': 'lowest-index', 'request_order': list(range(len(tasks)))}
    frozen_setup = {'cpu_ns': time.process_time_ns()-cpu, 'wall_ns': time.perf_counter_ns()-started,
                    'scope': 'actual input reads, model/artifact validation, full tile/shape reconstruction, '
                             'exclusive snapshot writes/fsync/readback and ordinary routes; before freeze'}
    config = dict(max_candidates=5, max_per_actor=5, max_events=32768,
                  allowed_cycles=1, attempts_per_cycle=4096,
                  target_hex='7f'+'ff'*31, challenge_owner='local-os-random-observation')
    # Open/freeze/reveal/close/select, all registrations, every possible declared
    # attempt and at most one submission for each declared search.
    required_normal_events = 5 + len(tiles) + len(tiles) * config['allowed_cycles'] * (config['attempts_per_cycle'] + 1)
    require(required_normal_events <= config['max_events'], 'DECLARED_SEARCH_JOURNAL_CAPACITY')
    save(out/'frozen-input-bindings.json', {'inputs': frozen_inputs,
        'operator_shapes': expected_shapes, 'geometry': expected_geometry,
        'required_normal_events': required_normal_events, 'configured_event_capacity': config['max_events'],
        'model_artifact_verified': True, 'model_source_field_equal': True,
        'scope': 'computational bytes and model/source field binding; does not authenticate corpus ownership or future utility',
        'read_only_snapshot_is_adversarially_immutable': False})
    mode = ModeAResearch(**config)
    opened = time.monotonic_ns()
    cutoff = opened + 250_000_000
    parent = H('pon-work-expensive-research-parent-v1', canonical(provenance)).hex()
    mode.open_round(1, parent, 'offline-research', opened, cutoff, opened+1_200_000_000_000)
    registrations = []
    contracts = []
    for index, tile in enumerate(tiles):
        start, start_cpu = time.perf_counter_ns(), time.process_time_ns()
        contract = {'profile': PROFILE, 'task': tile['task'],
                    'model': provenance['model_artifact'],
                    'cell': H('pon-work-expensive-cell-v1', str(index).encode()).hex(),
                    'generation': 0, 'state_before': H('pon-work-expensive-state-v1', b'no-transition').hex(),
                    'transition': H('pon-work-expensive-transition-v1', b'read-only-inference').hex(),
                    'input_commitment': tile['material_sha256'],
                    'request_commitment': sha(canonical(tasks)),
                    'route_commitment': sha(canonical(route_contract)), 'shape': [N, N, N],
                    'numeric_contract': H('pon-work-expensive-numeric-v1', b'original-canonical-W1-field-and-original-integer-model').hex(),
                    'output_contract': H('pon-work-expensive-output-v1', b'complete-257-feature-five-tile-integer-operator').hex()}
        prep_cpu, prep_wall = time.process_time_ns()-start_cpu, time.perf_counter_ns()-start
        registrations.append(mode.register('material-experiment', contract, time.monotonic_ns(), prep_cpu, prep_wall))
        contracts.append(contract)
    frozen = mode.freeze(time.monotonic_ns())
    checkpoint = mode.save(out/'mode-a-frozen.json')
    save(out/'mode-a-frozen-checkpoint.json', checkpoint)
    # Actual snapshot fsync finishes before entropy is requested. The local
    # clock/OS source remains an observation, not a network authentication claim.
    remaining = (cutoff-time.monotonic_ns())/1e9
    if remaining > 0:
        time.sleep(remaining)
    external = os.urandom(32) if seed_replay is None else bytes.fromhex(seed_replay)
    require(len(external) == 32, 'REPLAY_SEED')
    observation = {'source': 'os.urandom-after-fsync' if seed_replay is None else 'explicit-known-seed-replay',
                   'seed': external.hex(), 'checkpoint': checkpoint}
    reveal = mode.reveal(external.hex(), sha(canonical(observation)), time.monotonic_ns())
    save(out/'mode-a-reveal.json', {'freeze': frozen, 'reveal': reveal,
                                  'source_observation': observation, 'upstream_preparation': frozen_setup,
                                  'route_contract': route_contract, 'frozen_contracts': contracts,
                                  'live_beacon_authenticated': False, 'route_computation_is_native_work_proof': False,
                                  'external_seed_alone_reproduces_native_stream': False,
                                  'exact_native_replay_seed': reveal['seed'],
                                  'replay_note': 'a new freeze binds new observed times and therefore derives a new seed; '
                                                 'replay original native streams using this stored derived seed'})
    mode.save(out/'mode-a-revealed.json')
    return mode, registrations, tiles, model, tasks, manifest, reveal['seed'], parent, frozen_inputs


def bind_census_report(report, args, seed, target_index, frozen_input):
    target = (bytes([127 if target_index == 0 else 7]) + bytes([255]) * 31).hex()
    expected = {'seed': seed, 'target': target, 'attempts_per_arm': args.attempts,
                'samples': args.samples, 'reuse_attempts': args.reuse}
    require(all(type(report.get(key)) is type(value) and report[key] == value
                for key, value in expected.items()), 'CENSUS_REQUEST_BINDING')
    materials = report.get('material_identity')
    require(type(materials) is list and len(materials) == (1 if frozen_input else 9), 'CENSUS_MATERIAL_COUNT')
    if frozen_input is not None:
        material = materials[0]
        require(material.get('class') == 'supplied-material' and
                all(material.get(key) == frozen_input[key] for key in ('task', 'a_sha256', 'b_sha256')),
                'CENSUS_FROZEN_MATERIAL_BINDING')
    return True


def census_observation(raw, process, directory, args, seed, target, frozen_input):
    entry = {'process': process, 'status': 'failed', 'reader_status': 'not-read',
             'request_binding_verified': False, 'material_frozen_by_mode_a': False,
             'new_benchmark_is_mode_a_submit_domain': False, 'failures': []}
    if process['returncode'] != 0 or process['failure'] is not None:
        entry['failures'].append({'kind': 'process_failure', 'returncode': process['returncode'],
                                  'error': process['failure']})
    try:
        report = inspect(raw, args.budgets_ns, args.calibration_samples)
    except (ValueError, KeyError, TypeError, IndexError, AttributeError, OverflowError) as error:
        rejection = {'kind': 'reader_rejection', 'error_type': type(error).__name__,
                     'error': str(error), 'raw_sha256': sha(raw),
                     'raw_preserved': True, 'qualification': False}
        save(directory/'reader-rejection.json', rejection)
        entry['reader_status'] = 'rejected'
        entry['failures'].append(rejection)
    else:
        # A parsed failed report remains a report, even if the executable also
        # returned nonzero. It is never replaced by a generic reader rejection.
        save(directory/'reader.json', report)
        entry.update(reader_status='parsed', counts=report['counts'],
                     selection=report['calibration_selection'], run_timing=report['run_timing'],
                     unique_relation_winners=report['unique_relation_winners_across_repeated_arms'])
        if report['status'] != 'complete':
            entry['failures'].append({'kind': 'native_cells_failed', 'error': report['status']})
        try:
            bind_census_report(report, args, seed, target, frozen_input)
            entry['request_binding_verified'] = True
            entry['material_frozen_by_mode_a'] = frozen_input is not None
        except (ValueError, KeyError, TypeError) as error:
            entry['failures'].append({'kind': 'request_binding_failure', 'error': str(error)})
    if not entry['failures']:
        entry['status'] = 'complete'
    save(directory/'shard-status.json', entry)
    return entry


def run(args):
    run_wall, run_cpu = time.perf_counter_ns(), time.process_time_ns()
    children_start = resource.getrusage(resource.RUSAGE_CHILDREN)
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    request = {key: str(value) if isinstance(value, Path) else value for key, value in vars(args).items()}
    save(out/'request.json', request)
    source_before = source_after = None
    mode = None
    binaries, processes, failed, results, frozen_inputs = {}, [], [], [], []
    proofs, qualified, shared_costs, replay_commands = {}, [], [], []
    complete_operator = False
    model_batch_size = None
    stage = 'source-and-binaries'
    native, shared = args.native.resolve(), args.shared_native.resolve()
    try:
        source_before = source_identity()
        save(out/'source-before.json', source_before)
        binaries = {str(path): {'sha256': sha(read(path, 64*1024*1024)), 'bytes': path.stat().st_size}
                    for path in (native, shared)}
        save(out/'binaries-before.json', binaries)
        save(out/'host.json', hardware_snapshot())
        stage = 'freeze-materials'
        mode, registrations, tiles, model, tasks, manifest, seed, parent, frozen_inputs = freeze_materials(
            args.material_dir.resolve(), out, args.replay_seed)
        model_batch_size = len(tasks)
        save(out/'input-provenance.json', manifest)
        stage = 'mode-a-native'
        for index, tile in enumerate(tiles):
            command = [str(shared), '--shared-material-v1', '--target-index', '0', '--seed', seed,
                       '--cycles', '1', '--max-attempts', '4096', '--arithmetic', 'full-limb']
            directory = out/f'mode-a-tile-{index}'
            raw, process = exchange(command, tile['material'], directory, args.timeout)
            processes.append(process)
            replay_commands.append({'argv': command, 'stdin_file': frozen_inputs[index]['path']})
            shard_failures = []
            if process['returncode'] != 0 or process['failure'] is not None:
                shard_failures.append({'kind': 'process_failure', 'returncode': process['returncode'],
                                       'error': process['failure']})
            try:
                products, records = native_products(raw, tiles, index, 1, seed=seed,
                    target_index=0, max_attempts=4096, arithmetic='full-limb')
            except (ValueError, KeyError, TypeError, IndexError, AttributeError) as error:
                rejection = {'kind': 'reader_rejection', 'error_type': type(error).__name__,
                             'error': str(error), 'raw_sha256': sha(raw), 'raw_preserved': True}
                save(directory/'reader-rejection.json', rejection)
                shard_failures.append(rejection)
            else:
                observation = {'tile': index, 'native_setup': records[1]['timing'],
                    'native_complete_search': records[2]['timing'], 'native_summary': records[-1],
                    'process': process,
                    'overlap': 'trial timings lie inside search; phases lie inside native/child envelopes; do not sum nested clocks'}
                shared_costs.append(observation)
                save(directory/'reader.json', {'status': 'parsed', **observation,
                                               'product_sha256': sha(products[0])})
                if not shard_failures:
                    try:
                        for trial in records[2]['attempts']:
                            require(mode.challenge(registrations[index], 0, trial['nonce']) == trial['challenge'], 'MODE_A_CHALLENGE')
                            mode.record_attempt(registrations[index], 0, trial['nonce'], trial['trace'],
                                time.monotonic_ns(), trial['timing']['cpu_ns'], trial['timing']['wall_ns'])
                        winner = records[-2]
                        qualified.append(mode.submit(registrations[index], 0, records[2]['attempts'][-1]['nonce'],
                            winner['proof_hex'], parent, 'offline-research', time.monotonic_ns()))
                        proofs[index] = products[0]
                    except (ValueError, KeyError, TypeError) as error:
                        shard_failures.append({'kind': 'mode_a_observation_failure', 'error': str(error)})
            save(directory/'shard-status.json', {'status': 'failed' if shard_failures else 'complete',
                 'failures': shard_failures, 'raw_preserved': True})
            failed.extend({'shard': directory.name, **failure} for failure in shard_failures)
        stage = 'mode-a-close-and-complete-operator'
        try:
            mode.close(time.monotonic_ns())
            mode.select_scope(parent, 'offline-research', time.monotonic_ns())
            checkpoint = mode.save(out/'mode-a-complete.json')
            save(out/'mode-a-complete-checkpoint.json', checkpoint)
            restored = ModeAResearch.restore(out/'mode-a-complete.json', checkpoint)
            require(restored.summary() == mode.summary(), 'MODE_A_RESTORE')
            if len(proofs) == 5:
                output = consume_products(tiles, proofs, len(tasks))
                validate_consumption(model, tasks, output)
                complete_operator = True
                save(out/'one-model-batch-output.json', {
                    'model_artifact': manifest['provenance']['model_artifact'],
                    'request_commitment': sha(canonical(tasks)), 'requests': len(tasks),
                    'complete_model_batch_outputs': 1, 'component_tile_products': 5,
                    'routes': output['routes'].tolist(), 'logits': output['logits'].tolist(),
                    'predictions': output['predictions'].tolist(),
                    'scope': 'one complete source-model batch; five tile products are components, not five model batches'})
        except (ValueError, KeyError, TypeError, IndexError, OSError) as error:
            failed.append({'stage': stage, 'kind': 'mode_a_close_or_operator_failure', 'error': str(error)})
        save(out/'mode-a-summary.json', {'observation': mode.summary(), 'qualifications': qualified,
            'native_costs': shared_costs, 'complete_source_operator_equal': complete_operator,
            'one_complete_model_output': complete_operator, 'complete_model_batch_outputs': int(complete_operator),
            'model_batch_requests': len(tasks), 'component_tile_product_outcomes': len(proofs),
            'mode_a_application_outcomes_are_tile_products': True,
            'live_chain_accepted_work': None,
            'cost_scope': 'ModeA preparation fields cover contract registration observations only; '
                          'upstream input preparation, native setup, driver and child envelopes are recorded separately',
            'scope': 'actual native W1 plus independent scalar replay; five tile components compose one model batch, no Node admission'})
        stage = 'fixed-attempt-census'
        jobs = [(f'synthetic-target-{target}', None, target) for target in args.targets]
        jobs += [(f'material-{item["tile"]}-target-{target}', item, target)
                 for target in args.targets for item in frozen_inputs]
        for name, frozen_input, target in jobs:
            command = [str(native), '--work-expensive-v1', '--attempts', str(args.attempts),
                       '--samples', str(args.samples), '--reuse', str(args.reuse),
                       '--target-index', str(target), '--seed', seed]
            if frozen_input is not None:
                command += ['--material', frozen_input['path']]
            raw, process = exchange(command, b'', out/name, args.timeout)
            processes.append(process)
            replay_commands.append({'argv': command, 'stdin_file': None})
            entry = census_observation(raw, process, out/name, args, seed, target, frozen_input)
            entry['name'] = name
            results.append(entry)
            failed.extend({'shard': name, **failure} for failure in entry['failures'])
        save(out/'exact-native-replay.json', {'derived_seed': seed, 'commands': replay_commands,
            'external_seed_only_is_exact_replay': False,
            'mode_a_snapshot': 'mode-a-complete.json', 'mode_a_checkpoint': 'mode-a-complete-checkpoint.json',
            'scope': 'commands reproduce mathematical streams, not timings; snapshot restore replays original '
                     'observed chronology, while a new --replay-seed freeze obtains different time-bound commitments'})
    except (ValueError, KeyError, TypeError, IndexError, AttributeError, OSError,
            subprocess.SubprocessError) as error:
        failure = {'stage': stage, 'kind': 'driver_failure', 'error_type': type(error).__name__,
                   'error': str(error), 'raw_failures_preserved': True}
        failed.append(failure)
        save(out/'driver-failure.json', failure)
    # Final source/input readback and summary also run after a failed stage.
    try:
        source_after = source_identity()
        save(out/'source-after.json', source_after)
        if source_before is not None and source_before['files_sha256'] != source_after['files_sha256']:
            failed.append({'kind': 'source_failure', 'error': 'SOURCE_CHANGED_DURING_CAMPAIGN'})
        after_binaries = {str(path): {'sha256': sha(read(path, 64*1024*1024)), 'bytes': path.stat().st_size}
                          for path in (native, shared)}
        save(out/'binaries-after.json', after_binaries)
        if binaries and binaries != after_binaries:
            failed.append({'kind': 'binary_failure', 'error': 'BINARY_CHANGED_DURING_CAMPAIGN'})
        for item in frozen_inputs:
            value = read(item['path'], 32768)
            if len(value) != item['material_bytes'] or sha(value) != item['material_sha256']:
                failed.append({'kind': 'input_failure', 'tile': item['tile'], 'error': 'FROZEN_COPY_CHANGED'})
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
        failed.append({'kind': 'final_readback_failure', 'error': str(error)})
    children_end = resource.getrusage(resource.RUSAGE_CHILDREN)
    parent_cpu_ns = time.process_time_ns()-run_cpu
    elapsed_wall_ns = time.perf_counter_ns()-run_wall
    reaped_user_ns = round((children_end.ru_utime-children_start.ru_utime)*1e9)
    reaped_system_ns = round((children_end.ru_stime-children_start.ru_stime)*1e9)
    summary = {'schema': 'pon-work-expensive-campaign-v1', 'status': 'complete' if not failed else 'failed',
               'request': request, 'binaries': binaries, 'source_before': source_before,
               'source_manifest_equal_after_run': source_before is not None and source_after is not None and
                   source_before['files_sha256'] == source_after['files_sha256'],
               'mode_a': mode.summary() if mode is not None else None,
               'native_complete_operator_equal': complete_operator, 'one_complete_model_output': complete_operator,
               'complete_model_batch_outputs': int(complete_operator), 'model_batch_requests': model_batch_size,
               'component_tile_product_outcomes': len(proofs),
               'mode_a_application_outcomes_are_tile_products': True,
               'results': results, 'failures': failed, 'gamma': None, 'work_hardness_qualified': False,
               'production_activation': False, 'raw_failures_preserved': True,
               'cross_target_reuse_or_strategy_cohorts_are_additive_chainwork': False,
               'all_owned_children': {'count': len(processes),
                   'wall_ns': sum(item['wall_ns'] for item in processes),
                   'user_cpu_ns': sum(item['child_user_cpu_ns'] for item in processes),
                   'system_cpu_ns': sum(item['child_system_cpu_ns'] for item in processes),
                   'max_child_peak_rss_so_far_kib': max((item['child_peak_rss_so_far_kib'] for item in processes), default=0),
                   'scope': 'native experiment child exchanges only, not parent CPU or metadata subprocesses'},
               'campaign_observation': {'parent_process_cpu_ns': parent_cpu_ns, 'elapsed_wall_ns': elapsed_wall_ns,
                   'all_reaped_child_user_cpu_ns': reaped_user_ns, 'all_reaped_child_system_cpu_ns': reaped_system_ns,
                   'aggregate_parent_and_reaped_child_cpu_ns': parent_cpu_ns + reaped_user_ns + reaped_system_ns,
                   'scope': 'run entry through final readback, before summary construction/emission; excludes interpreter '
                            'startup/imports/argument parsing; child deltas include metadata git and native experiment processes',
                   'children_wall_is_already_inside_elapsed_wall': True,
                   'nested_component_and_envelope_times_are_not_additive': True},
               'limits': ['Synthetic grid is a miner-selected primitive domain; it is not the frozen real workload.',
                          'Mode A chronology and exact cost census are separate native challenge domains.',
                          'Five accepted tile products compose one complete model batch, not five model inferences.',
                          'Local OS entropy and timestamps do not authenticate a network challenge owner.',
                          'Grouped shape/rounding/adaptive input security and live admission remain unqualified.']}
    save(out/'summary.json', summary)
    print(json.dumps({'status': summary['status'], 'failures': len(failed),
                      'one_complete_model_output': complete_operator, 'gamma': None}))
    return int(bool(failed))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', required=True, type=Path)
    parser.add_argument('--shared-native', required=True, type=Path)
    parser.add_argument('--material-dir', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--attempts', type=int, default=64)
    parser.add_argument('--samples', type=int, default=8)
    parser.add_argument('--reuse', type=int, default=16)
    parser.add_argument('--targets', type=int, nargs='+', default=[0, 1])
    parser.add_argument('--calibration-samples', type=int, default=2)
    parser.add_argument('--budgets-ns', type=int, nargs='+', default=[1_000_000, 5_000_000, 20_000_000])
    parser.add_argument('--timeout', type=int, default=300)
    parser.add_argument('--replay-seed', help='historical external seed only; a new freeze derives a different native seed; exact stream replay uses stored derived seed')
    args = parser.parse_args()
    require(1 <= args.attempts <= 1024 and 1 <= args.reuse <= 1024 and 2 <= args.samples <= 16 and
            1 <= args.calibration_samples < args.samples and 1 <= args.timeout <= 600 and
            args.targets and len(args.targets) == len(set(args.targets)) and set(args.targets) <= {0, 1}, 'ARGUMENT_BOUNDS')
    require(args.budgets_ns and len(args.budgets_ns) <= 16 and len(set(args.budgets_ns)) == len(args.budgets_ns)
            and all(0 < n < 2**64 for n in args.budgets_ns), 'BUDGET_BOUNDS')
    if args.replay_seed is not None:
        require(len(args.replay_seed) == 64 and all(c in '0123456789abcdef' for c in args.replay_seed), 'REPLAY_SEED')
    return run(args)


if __name__ == '__main__':
    raise SystemExit(main())

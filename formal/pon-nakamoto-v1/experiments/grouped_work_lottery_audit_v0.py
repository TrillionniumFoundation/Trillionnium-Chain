"""Run the fixed grouped lottery audit on the retained consumer[0:16] corpus.

Requires a clean, committed --source-sha and a real native grouped example.
Source replay is mandatory. This is retrospective correctness/cost evidence;
all actual chainwork, model rewards, and business credit remain zero.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import os
from pathlib import Path
import shlex
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from bounded_process import ProcessFailure, run_bounded
from contract_wire import H, ROOT, canonical, unique
from experiments.grouped_cell_operator_v0 import (
    FIXTURE_ARRIVAL_NS, FIXTURE_DEADLINE_NS, FIXTURE_NOW_NS, cpu_children_ns,
    decode_frames, encode_frames, kernel_comparison, make_commands,
    toolchain, validate_prepared, validate_result,
)
from experiments.shared_cell_operator_v1 import (
    DEFAULT_BUNDLE, DEFAULT_MATERIAL, hardware_snapshot, load_inputs, save_json,
)
# Import the existing source producer before capturing the executing-source
# roster; load_inputs(replay_source=True) calls this exact implementation.
from experiments import model_loop as _source_producer
import grouped_work_lottery_v0 as lottery


SCHEMA = 'pon-grouped-work-lottery-source-audit-v0'
PRIMARY_NONCES = tuple(range(64)) + (0,)
EXPIRED_NONCES = tuple(range(8))
CONTEXT_MUTATIONS = ('parent', 'batch_id', 'task', 'payee', 'parameters')
TARGET = f'{(1 << 252) - 1:064x}'
NATIVE_SAMPLES = 12
NATIVE_WARMUP = 2
SOURCE_STATIC_PATHS = (
    'formal/pon-nakamoto-v1/experiments/grouped_work_lottery_audit_v0.py',
    'formal/pon-nakamoto-v1/grouped_work_lottery_v0.py',
    'formal/pon-nakamoto-v1/work_query_bound.py',
    'formal/pon-nakamoto-v1/requirements.txt',
    'config/pon/devnet-v1.json', 'config/pon/ledger-v1.json',
    'config/pon/work-profile-v1.json', 'config/pon/model-family-v1.json',
    'config/portability-inventory-v1.json',
    'trillionnium/crates/trnm-crypto-primitives/src/pon_routed_int257_grouped.rs',
    'trillionnium/crates/trnm-crypto-primitives/examples/pon_routed_int257_grouped.rs',
    'trillionnium/crates/trnm-crypto-primitives/src/lib.rs',
    'trillionnium/crates/trnm-crypto-primitives/Cargo.toml',
    'trillionnium/Cargo.toml', 'trillionnium/Cargo.lock', 'rust-toolchain.toml',
    'evidence/pon-native-node-v1/model-current/model/model.json',
    'evidence/pon-native-node-v1/model-current/model/consumer.json',
    'evidence/pon-native-node-v1/model-current/model/evaluation-bundle.json',
)


def require(ok, code):
    if not ok:
        raise ValueError(code)


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def git_bytes(root, *args):
    # Reading a missing historical blob must fail explicitly, not silently
    # initiate an unrecorded network fetch in a source-replay measurement.
    result = subprocess.run(['git', *args], cwd=root, capture_output=True,
                            env=dict(os.environ, GIT_NO_LAZY_FETCH='1'), timeout=20)
    require(result.returncode == 0, 'GIT_' + args[0].upper().replace('-', '_'))
    require(len(result.stdout) <= 16 * 1024 * 1024, 'GIT_OUTPUT_LIMIT')
    return result.stdout


def source_roster(root=ROOT):
    root = Path(root).resolve()
    names = set(SOURCE_STATIC_PATHS)
    for module in tuple(sys.modules.values()):
        filename = getattr(module, '__file__', None)
        if filename is None:
            continue
        path = Path(filename).resolve()
        if path.suffix == '.py' and path.is_relative_to(root):
            names.add(path.relative_to(root).as_posix())
    return tuple(sorted(names))


def source_snapshot(expected_sha, runner, *, root=ROOT, source_files=None):
    """Bind actual executing bytes to HEAD, including otherwise-untracked code.

    Untracked evidence is allowed. Every selected source file must be present
    as an ordinary tracked blob at the requested HEAD and match its exact bytes.
    A clean tracked status alone would not protect a newly added Python module.
    """
    require(type(expected_sha) is str and len(expected_sha) == 40 and
            all(c in '0123456789abcdef' for c in expected_sha), 'SOURCE_SHA')
    root = Path(root).resolve()
    head = git_bytes(root, 'rev-parse', 'HEAD').decode().strip()
    require(head == expected_sha, 'SOURCE_HEAD_MISMATCH')
    dirty = git_bytes(root, 'status', '--porcelain=v1', '--untracked-files=no').decode().strip()
    require(not dirty, 'TRACKED_SOURCE_DIRTY')
    names = source_roster(root) if source_files is None else tuple(sorted(source_files))
    require(names and all(type(name) is str and not Path(name).is_absolute() and
                         '..' not in Path(name).parts for name in names), 'SOURCE_PATHS')
    raw = git_bytes(root, 'ls-tree', '-rz', '--full-tree', expected_sha, '--', *names)
    entries = {}
    for entry in raw.split(b'\0'):
        if not entry:
            continue
        metadata, name = entry.split(b'\t', 1)
        mode, kind, blob = metadata.decode().split()
        require(mode in ('100644', '100755') and kind == 'blob', 'SOURCE_BLOB_KIND')
        entries[name.decode()] = blob
    require(set(entries) == set(names), 'SOURCE_PATH_UNTRACKED_OR_MISSING')
    files = {}
    for name in names:
        path = root / name
        require(path.is_file() and not path.is_symlink(), 'SOURCE_FILE')
        data = path.read_bytes()
        # Git SHA-1 identifies the repository object; SHA-256 separately binds
        # the actual measured bytes. This is not a new cryptographic assumption.
        blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        require(blob == entries[name], 'SOURCE_BYTES_DIFFER_FROM_HEAD_' + name)
        files[name] = {'git_blob': blob, 'sha256': sha256(data), 'bytes': len(data)}
    runner = Path(runner).resolve()
    require(runner.is_file(), 'NATIVE_RUNNER_REQUIRED')
    return {'git_head': head, 'git_tree': git_bytes(root, 'rev-parse', 'HEAD^{tree}').decode().strip(),
            'tracked_source_clean': True, 'untracked_evidence_permitted': True,
            'files': files, 'native_runner_path': str(runner),
            'native_runner_sha256': sha256(runner.read_bytes()),
            'native_binary_build_attestation': None,
            'native_identity_scope': 'observed binary digest and relevant committed source; rebuild command/build receipt belongs to the invoking owner'}


def historical_source_identity(source):
    """Record every historical source blob consumed by the existing replayer."""
    inventory_path = 'config/portability-inventory-v1.json'
    inventory = json.loads(git_bytes(ROOT, 'show', source + ':' + inventory_path),
                           object_pairs_hook=unique)
    paths = git_bytes(ROOT, 'ls-tree', '-r', '--name-only', source).decode().splitlines()
    selected = {inventory_path}
    for owner in inventory['packages']:
        if owner['module'] not in _source_producer.CLASSES:
            continue
        selected.update(path for path in paths
                        if path.startswith(owner['path'] + '/src/') and path.endswith('.rs')
                        and '/tests/' not in path and not path.endswith('/tests.rs'))
    result = {}
    for path in sorted(selected):
        raw = git_bytes(ROOT, 'show', source + ':' + path)
        result[path] = {'sha256': sha256(raw), 'bytes': len(raw),
                        'git_blob': git_bytes(ROOT, 'rev-parse', source + ':' + path).decode().strip()}
    return {'source_commit': source, 'replay_source': True, 'files': result,
            'scope': 'complete source producer dependency set, including other corpus partitions needed to reproduce consumer exactly'}


def preregistration(source_sha, timeout):
    require(type(timeout) in (int, float) and math.isfinite(timeout) and 0 < timeout <= 60,
            'NATIVE_TIMEOUT')
    return {'schema': SCHEMA, 'source_sha': source_sha, 'profile': lottery.PROFILE,
            'fixed_material': {'directory': str(DEFAULT_MATERIAL.relative_to(ROOT)),
                'partition': 'consumer', 'offset': 0, 'count': 16, 'replay_source': True,
                'evaluation_bundle': DEFAULT_BUNDLE},
            'primary': {'target': TARGET, 'nonces': list(PRIMARY_NONCES),
                'planned_attempts': 65, 'unique_nonces': 64, 'stop_on_success': False},
            'expired': {'target': TARGET, 'nonces': list(EXPIRED_NONCES),
                'planned_attempts': 8, 'now_ns': FIXTURE_DEADLINE_NS,
                'expected_refusal': 'REQUEST_NOT_CURRENT', 'same_ticket_inputs_as_primary_prefix': True},
            'carrier_variants': {'count': 64, 'same_header_nonce': 0,
                'auxiliary_bytes_are_not_a_proof': True},
            'context_variants': {'fields': list(CONTEXT_MUTATIONS), 'same_arithmetic_product': True},
            'native': {'processes': 1, 'init_frames': 1, 'batch_frames': 1,
                'samples': NATIVE_SAMPLES, 'warmup': NATIVE_WARMUP, 'timeout_seconds': timeout,
                'context': 'exact nonce-zero audit candidate', 'performance_qualification': False},
            'demand': {'kind': 'retrospective_public_source_fixture', 'real_arrival_trace': None,
                'original_deadlines': None, 'synthetic_rows_added': 0, 'real_demand_verified': False},
            'chainwork_awarded': 0, 'business_credit': 0, 'model_reward': 0,
            'pow_qualified': False, 'production_activation': False}


def fixed_envelope(source_sha, init, requests, batch_id):
    def tagged(name, *parts):
        return H('grouped-lottery-source-audit-' + name + '-v0', *parts).hex()
    return {'network': tagged('network', b'research-no-chainwork'),
            'parameters': tagged('parameters', lottery.PROFILE.encode(), lottery.NUMERIC.encode(),
                                 canonical({'batch_size': 16, 'target': TARGET})),
            'parent': tagged('parent', bytes.fromhex(source_sha)),
            'target': TARGET, 'payee': tagged('payee', b'no-payment-authority'),
            'task': tagged('task', bytes.fromhex(lottery.model_commitment_checked(init)),
                           bytes.fromhex(lottery.request_precommitment(init, requests))),
            'batch_id': batch_id, 'transactions_commitment': tagged('transactions', b'no-transactions'),
            'prior_state_root': tagged('prior-state', b'no-authoritative-ledger-state'),
            'height': 1, 'timestamp_ms': 0, 'nonce': 0}


class Recorder:
    def __init__(self, out):
        self.out = Path(out)
        self.stages = {}
        self.rows = {}
        self.seen = set()
        self.events = self.out / 'events.ndjson'
        self.events.open('xb').close()

    def event(self, value):
        with self.events.open('ab') as output:
            output.write(canonical(value) + b'\n')

    def stage(self, name, call):
        self.event({'stage': name, 'status': 'started'})
        wall, cpu, child_cpu = time.perf_counter_ns(), time.process_time_ns(), cpu_children_ns()
        self.stages[name] = {'status': 'started'}
        try:
            value = call()
        except Exception as error:
            self.stages[name].update(status='failed', error_type=type(error).__name__, error=str(error))
            raise
        else:
            self.stages[name]['status'] = 'completed'
            return value
        finally:
            self.stages[name].update(wall_ns=time.perf_counter_ns() - wall,
                parent_cpu_ns=time.process_time_ns() - cpu, child_cpu_ns=cpu_children_ns() - child_cpu)
            self.event({'stage': name, **self.stages[name]})

    def observer(self, group):
        directory = self.out / group
        directory.mkdir(exist_ok=False)
        self.rows[group] = []
        group_seen = set()

        def observe(value):
            row = copy.deepcopy(value)
            if all(key in row for key in ('challenge', 'statement', 'ticket')):
                identity = (row['challenge'], row['statement'])
                row.setdefault('first_ticket_input', identity not in group_seen)
                group_seen.add(identity)
                row['global_first_ticket_input'] = identity not in self.seen
                self.seen.add(identity)
            self.rows[group].append(row)
            save_json(directory / f'attempt-{row["index"]:03d}.json', row)
            self.event({'stage': group, 'index': row['index'], 'status': row['status'],
                        'ticket_input_observed': 'ticket' in row})
        return observe


def carrier_audit(init, requests, header, product, recorder):
    observe = recorder.observer('carrier')
    payloads = recorder.out / 'carrier-transports'
    payloads.mkdir(exist_ok=False)
    rows = []
    for index in range(64):
        started = time.process_time_ns()
        row = {'index': index, 'auxiliary_hex': index.to_bytes(8, 'big').hex(), 'chainwork_awarded': 0}
        try:
            claim = lottery.package_claim(init, requests, header, product,
                                           transport_aux_hex=row['auxiliary_hex'])
            row.update(challenge=claim['context']['challenge'], statement=claim['statement_commitment'],
                       ticket=claim['ticket'], receipt_id=claim['receipt_id'])
            ordered = dict(reversed(list(claim.items()))) if index % 2 else claim
            raw = json.dumps(ordered, indent=index % 3).encode()
            with (payloads / f'variant-{index:03d}.json').open('xb') as output:
                output.write(raw)
            row['transport_sha256'] = sha256(raw)
            parsed = lottery.decode_package(raw)
            checked = lottery.verify_package(parsed, expected_header=header,
                init=init, requests=requests, now_ns=FIXTURE_NOW_NS)
            row.update(status='verified_research', **checked)
        except ValueError as error:
            row.update(status='rejected', error=str(error))
        row['producer_transport_and_full_verifier_cpu_ns'] = time.process_time_ns() - started
        rows.append(row)
        observe(row)
    return {'planned_attempts': 64, 'attempts': rows,
            'distinct_ticket_inputs': len({(row['challenge'], row['statement']) for row in rows if 'ticket' in row}),
            'distinct_receipt_ids': len({row['receipt_id'] for row in rows if 'receipt_id' in row}),
            'scope': 'carrier randomness and JSON formatting; not randomized succinct proofs or new demand',
            'chainwork_awarded': 0}


def context_audit(init, requests, envelope, product, recorder):
    observe = recorder.observer('context')
    rows = []
    for index, field in enumerate(CONTEXT_MUTATIONS):
        started = time.process_time_ns()
        row = {'index': index, 'field': field, 'producer_new_matrix_contractions': 0,
               'chainwork_awarded': 0}
        try:
            changed = dict(envelope)
            changed[field] = H('grouped-audit-context-control-v0', field.encode(),
                               bytes.fromhex(changed[field])).hex()
            header = lottery.make_candidate(init, requests, changed)
            claim = lottery.package_claim(init, requests, header, product)
            row.update(header=header, challenge=claim['context']['challenge'],
                       statement=claim['statement_commitment'], ticket=claim['ticket'])
            checked = lottery.verify_package(claim, expected_header=header,
                init=init, requests=requests, now_ns=FIXTURE_NOW_NS)
            row.update(status='verified_research', same_arithmetic_product=claim['product'] == product,
                       **checked)
        except ValueError as error:
            row.update(status='rejected', error=str(error))
        row['producer_binding_and_full_verifier_cpu_ns'] = time.process_time_ns() - started
        rows.append(row)
        observe(row)
    return {'planned_attempts': len(CONTEXT_MUTATIONS), 'attempts': rows,
            'chainwork_awarded': 0,
            'scope': 'hypothetical externally changed research envelopes; not authorization to choose a live parent, recipient or task'}


def native_crosscheck(runner, timeout, init, command, model, rows, expected_statement, recorder):
    wire = encode_frames([init, command])
    with (recorder.out / 'native-input.ndjson').open('xb') as output:
        output.write(wire)
    process = None
    try:
        process = recorder.stage('native_process', lambda: run_bounded(
            [str(Path(runner).resolve()), '--grouped-research-v0'], wire,
            timeout=timeout, stdout_limit=1024 * 1024, stderr_limit=65536, cwd=ROOT))
    except ProcessFailure as error:
        with (recorder.out / 'native-stdout.ndjson').open('xb') as output:
            output.write(error.stdout)
        with (recorder.out / 'native-stderr.txt').open('xb') as output:
            output.write(error.stderr)
        save_json(recorder.out / 'native-failure.json', {
            'error': str(error), 'returncode': error.returncode, 'stdin_written': error.stdin_written,
            'stdout_truncated': error.stdout_truncated, 'stderr_truncated': error.stderr_truncated,
            'stdout_prefix_bytes': len(error.stdout), 'stderr_prefix_bytes': len(error.stderr)})
        raise
    with (recorder.out / 'native-stdout.ndjson').open('xb') as output:
        output.write(process.stdout)
    with (recorder.out / 'native-stderr.txt').open('xb') as output:
        output.write(process.stderr)
    save_json(recorder.out / 'native-process-result.json', {
        'returncode': process.returncode, 'input_bytes': len(wire),
        'stdout_bytes': len(process.stdout), 'stderr_bytes': len(process.stderr),
        'input_sha256': sha256(wire), 'stdout_sha256': sha256(process.stdout),
        'stderr_sha256': sha256(process.stderr), 'stdout_truncated': False, 'stderr_truncated': False})
    require(process.returncode == 0, 'NATIVE_EXIT_' + str(process.returncode))
    frames = recorder.stage('native_decode', lambda: decode_frames(process.stdout, 2))
    validate_prepared(frames[0], init)
    result = frames[1]
    recorder.stage('native_independent_python_numpy_verification', lambda: validate_result(
        result, init, command, model, rows, prior_ids=set()))
    require(result['statement_commitment'] == expected_statement, 'NATIVE_LOTTERY_STATEMENT_BINDING')
    return {'native_statement_matches_nonce_zero': True,
            'model_commitment': result['model_commitment'], 'input_commitment': result['input_commitment'],
            'statement_commitment': result['statement_commitment'],
            'model_preparation_wall_ns': frames[0]['preparation_ns'],
            'native_phases_wall_ns': result['phase_ns'],
            'native_selected_phases_wall_ns': result['selected_phase_ns'],
            'native_selected_producer_with_verify_wall_ns': result['selected_producer_with_verify_wall_ns'],
            'native_selected_producer_with_verify_cpu_ns': result['selected_producer_with_verify_cpu_ns'],
            'native_selected_scope': result['selected_producer_with_verify_scope'],
            'native_handler_wall_ns': result['handler_wall_ns'], 'native_handler_cpu_ns': result['handler_cpu_ns'],
            'kernel_comparison': kernel_comparison(result),
            'whole_process': recorder.stages['native_process'],
            'whole_process_scope': 'one process startup, model init, single batch with all disclosed warmups and three-arm repetitions, full verifiers, input/output pipes, exit and process-group cleanup',
            'startup_only_ns': None, 'ipc_only_ns': None, 'per_phase_cpu_ns': None,
            'python_reticket_and_native_kernel_speedup_comparison': None,
            'full_native_verifier_dense_positions': 9 * 257 * 16,
            'correctness_checks': ['original-coefficient scalar all product fields',
                'existing model-contract prediction', 'ordinary cached selected-expert NumPy',
                'all native model/input/statement commitments', 'direct/packed statements equal',
                'native statement equals nonce-zero lottery audit statement'],
            'pow_qualified': False, 'production_activation': False, 'chainwork_awarded': 0}


def attempt_summary(rows):
    queried = [row for row in rows if 'ticket' in row]
    verified = [row for row in rows if row['status'] == 'verified_research']
    first = [row for row in rows if row.get('first_ticket_input') is True]
    return {'attempts': len(rows), 'ticket_evaluations_observed': len(queried),
            'verified_relation_attempts': len(verified), 'refused_attempts': len(rows) - len(verified),
            'target_hits_including_duplicates': sum(row.get('target_hit') is True for row in rows),
            'target_misses_including_duplicates': sum(row.get('target_hit') is False for row in rows),
            'distinct_ticket_inputs_in_group': len({(row['challenge'], row['statement']) for row in queried}),
            'first_query_target_hits': sum(row.get('target_hit') is True for row in first),
            'global_first_ticket_inputs': sum(row.get('global_first_ticket_input') is True for row in rows),
            'chainwork_awarded': 0}


def finish_manifest(out):
    files = {}
    for path in sorted(out.rglob('*')):
        if path.is_file() and path.name != 'manifest.json':
            raw = path.read_bytes()
            files[path.relative_to(out).as_posix()] = {'sha256': sha256(raw), 'bytes': len(raw)}
    save_json(out / 'manifest.json', {'schema': SCHEMA + '-files', 'files': files,
        'self_hash_excluded': True, 'scope': 'raw evidence bytes, not a signature or consensus certificate'})


def execute(args):
    started, cpu, child_cpu = time.perf_counter_ns(), time.process_time_ns(), cpu_children_ns()
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=False)
    recorder = Recorder(out)
    request = {'source_sha': args.source_sha, 'runner': str(Path(args.runner).resolve()),
               'out': str(out), 'native_timeout_seconds': args.native_timeout}
    save_json(out / 'request.json', request)
    before = after = None
    try:
        plan = preregistration(args.source_sha, args.native_timeout)
        save_json(out / 'preregistered-plan.json', plan)
        recorder.event({'stage': 'preregistration', 'status': 'recorded_before_inputs_and_tickets'})
        before = recorder.stage('source_before', lambda: source_snapshot(args.source_sha, args.runner))
        save_json(out / 'source-before.json', before)
        environment = recorder.stage('environment', lambda: {'hardware': hardware_snapshot(), 'toolchain': toolchain()})
        save_json(out / 'environment.json', environment)
        model, rows, provenance = recorder.stage('source_replay_and_input_load', lambda: load_inputs(
            DEFAULT_MATERIAL / 'model.json', DEFAULT_MATERIAL / 'consumer.json',
            DEFAULT_MATERIAL / 'evaluation-bundle.json', DEFAULT_BUNDLE,
            'consumer', 0, 16, replay_source=True))
        save_json(out / 'historical-source.json', recorder.stage('historical_source_identity',
            lambda: historical_source_identity(provenance['source_commit'])))
        save_json(out / 'provenance.json', provenance)
        save_json(out / 'selected-corpus-rows.json', rows)
        init, commands = make_commands(model, rows, provenance, [16], NATIVE_SAMPLES, NATIVE_WARMUP)
        command = commands[0]
        requests = command['requests']
        envelope = fixed_envelope(args.source_sha, init, requests, command['context']['batch_id'])
        header = lottery.make_candidate(init, requests, envelope)
        command['context'] = lottery.context_for(header)
        save_json(out / 'model-init.json', init)
        save_json(out / 'requests.json', requests)
        save_json(out / 'frozen-envelope.json', envelope)
        save_json(out / 'candidate-zero.json', header)
        with (out / 'candidate-zero.bin').open('xb') as output:
            output.write(lottery.encode_header(header))
        recorder.event({'stage': 'candidate', 'status': 'frozen_before_first_ticket',
                        'challenge': command['context']['challenge']})
        primary_observer = recorder.observer('primary')
        primary = recorder.stage('primary_queries', lambda: lottery.cached_reticket_audit(
            init, requests, envelope, nonces=list(PRIMARY_NONCES), now_ns=FIXTURE_NOW_NS,
            on_attempt=primary_observer))
        save_json(out / 'primary-audit.json', primary)
        expired_observer = recorder.observer('expired')
        expired = recorder.stage('expired_queries', lambda: lottery.cached_reticket_audit(
            init, requests, envelope, nonces=list(EXPIRED_NONCES), now_ns=FIXTURE_DEADLINE_NS,
            on_attempt=expired_observer))
        save_json(out / 'expired-audit.json', expired)
        product = primary['one_prepared_arithmetic_product']
        carriers = recorder.stage('carrier_variants', lambda: carrier_audit(init, requests, header, product, recorder))
        save_json(out / 'carrier-audit.json', carriers)
        contexts = recorder.stage('context_variants', lambda: context_audit(init, requests, envelope, product, recorder))
        save_json(out / 'context-audit.json', contexts)
        require(len(primary['attempts']) == 65 and primary['distinct_ticket_inputs'] == 64 and
                all(row['status'] == 'verified_research' and row['chainwork_awarded'] == 0
                    for row in primary['attempts']), 'PRIMARY_AUDIT_INCOMPLETE')
        require(len(expired['attempts']) == 8 and expired['distinct_ticket_inputs'] == 8 and
                all(row['status'] == 'rejected' and row['error'] == 'REQUEST_NOT_CURRENT' and 'ticket' in row
                    for row in expired['attempts']), 'EXPIRED_AUDIT_INCOMPLETE')
        require(carriers['distinct_ticket_inputs'] == carriers['distinct_receipt_ids'] == 1 and
                all(row['status'] == 'verified_research' for row in carriers['attempts']), 'CARRIER_AUDIT_INCOMPLETE')
        require(all(row['status'] == 'verified_research' and row['same_arithmetic_product'] and
                    row['ticket'] != primary['attempts'][0]['ticket'] for row in contexts['attempts']),
                'CONTEXT_AUDIT_INCOMPLETE')
        native = native_crosscheck(args.runner, args.native_timeout, init, command, model, rows,
                                  primary['attempts'][0]['statement'], recorder)
        save_json(out / 'native-crosscheck.json', native)
        after = recorder.stage('source_after', lambda: source_snapshot(args.source_sha, args.runner))
        save_json(out / 'source-after.json', after)
        require(before == after, 'EXECUTION_IDENTITY_CHANGED')
        report = {'schema': SCHEMA, 'status': 'completed_research_hold', 'source_sha': args.source_sha,
            'verdict': 'HOLD_CHALLENGE_INVARIANT_ARITHMETIC',
            'source_identity_unchanged': True, 'source_replayed': True,
            'native_differential_checks_passed': True,
            'plan': plan, 'provenance': provenance,
            'groups': {name: attempt_summary(values) for name, values in recorder.rows.items()},
            'distinct_ticket_inputs_across_all_observed_groups': len(recorder.seen),
            'query_count_scope': 'distinct (challenge, canonical statement) inputs observed in all producer groups; repeated internal verifier hashes are duplicates; this is not a raw SHA-256 invocation counter',
            'python_cached_reticket': {'preparation_cpu_ns': primary['preparation_cpu_ns'],
                'total_cpu_ns': primary['total_cpu_ns'], 'total_wall_ns': primary['total_wall_ns'],
                'producer_new_matrix_contractions_after_preparation': 0,
                'scope': primary['scope'], 'fresh_matrix_work_per_ticket_required': False},
            'native': native, 'stages': recorder.stages,
            'timing_before_final_report_and_manifest': {'wall_ns': time.perf_counter_ns() - started,
                'parent_cpu_ns': time.process_time_ns() - cpu, 'child_cpu_ns': cpu_children_ns() - child_cpu},
            'fixture_clock': {'arrival_ns': FIXTURE_ARRIVAL_NS, 'now_ns': FIXTURE_NOW_NS,
                'deadline_ns': FIXTURE_DEADLINE_NS, 'origin': 'declared retrospective transport test values; no real request-time evidence'},
            'qualification': {'pow_qualified': False, 'production_activation': False,
                'consensus_qualified': False, 'minimum_fresh_work_proved': False,
                'real_demand_verified': False, 'hardware_lower_bound_proved': False,
                'model_adoption_changed': False, 'chainwork_awarded': 0, 'business_credit': 0, 'model_reward': 0},
            'interpretation': ['A single exact cached arithmetic product serves all planned nonce queries.',
                'Full independent verification and all target misses/refusals remain charged in their recorded scopes.',
                'Carrier variants do not create new ticket identities; context changes do, without fresh neural arithmetic.',
                'The unchanged native W1 relation is not attacked or reweighted by these results.',
                'Python binding timings and native kernel/verification timings are different scopes; no cross-scope speedup is claimed.'],
            'reproduction_command': shlex.join([sys.executable, str(Path(__file__).resolve()),
                '--source-sha', args.source_sha, '--runner', str(Path(args.runner).resolve()),
                '--native-timeout', str(args.native_timeout), '--out', str(out) + '-replay'])}
        save_json(out / 'report.json', report)
        finish_manifest(out)
        return report
    except Exception as error:
        after_error = None
        if before is not None and after is None:
            try:
                after = source_snapshot(args.source_sha, args.runner)
                save_json(out / 'source-after-failure.json', after)
            except Exception as snapshot_error:
                after_error = {'type': type(snapshot_error).__name__, 'error': str(snapshot_error)}
        failure = {'schema': SCHEMA, 'status': 'failed', 'error_type': type(error).__name__, 'error': str(error),
            'source_before': before, 'source_after_failure': after, 'source_after_error': after_error,
            'completed_attempt_prefixes': recorder.rows, 'stages': recorder.stages,
            'planned_attempt_counts': {'primary': 65, 'expired': 8, 'carrier': 64, 'context': len(CONTEXT_MUTATIONS)},
            'unobserved_attempts': 'not certified; a started stage may have an in-flight outcome after its last persisted row, later stages were not started',
            'all_observed_cost_through_failure': {'wall_ns': time.perf_counter_ns() - started,
                'parent_cpu_ns': time.process_time_ns() - cpu, 'child_cpu_ns': cpu_children_ns() - child_cpu},
            'chainwork_awarded': 0, 'business_credit': 0, 'model_reward': 0,
            'pow_qualified': False, 'production_activation': False}
        recorder.event({'stage': 'audit', 'status': 'failed', 'error': str(error)})
        save_json(out / 'failure.json', failure)
        finish_manifest(out)
        raise


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument('--source-sha', required=True)
    result.add_argument('--runner', type=Path, required=True)
    result.add_argument('--out', type=Path, required=True)
    result.add_argument('--native-timeout', type=float, default=30)
    return result


if __name__ == '__main__':
    arguments = parser().parse_args()
    try:
        observation = execute(arguments)
    except Exception as error:
        print(json.dumps({'status': 'failed', 'error_type': type(error).__name__, 'error': str(error)}), file=sys.stderr)
        raise SystemExit(1)
    print(json.dumps({'status': observation['status'], 'verdict': observation['verdict'],
                      'source_sha': observation['source_sha'], 'out': str(arguments.out.resolve())}))

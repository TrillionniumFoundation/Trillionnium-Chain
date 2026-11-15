#!/usr/bin/env python3
"""Run one fresh pinned model operation after the existing Cell gates pass.

This external observer never builds, edits a repository or reuses an operation
directory. The native entry owns its unchanged 300-second deadline;
the independent 360-second outer watchdog only bounds cleanup initiation.
All inputs retain the #879 material pins. Source checks, admission hashing and
evidence collection are recorded outside the native operation interval.
"""
from __future__ import annotations

import argparse
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time


ORIGINAL_SPEC_SHA256 = 'f1a5f11fafda16ff865b1cc71fab4d64aa652e2ca7addb5a2a3ab9ce03deead6'
PROVIDER_SHA256 = 'ed29dfe14c0686c876833e39fbeedb277846987f3728acc279c256b32259cf62'
GATE_SCHEMA = 'cell-storage-four-gates-execution-v1'
EXAMPLE = 'cell_sealed_research_paged_next_use_v1'
INTERNAL_SECONDS = 300
WATCHDOG_SECONDS = 360
COLLECT = (
    'native-result.json', 'owner-paged-custody.json', 'next-use-result.json',
    'next-use-observations.json', 'independent-execution-inputs.json',
    'original-paged-source-inputs.json', 'owner-release-snapshot.cts1',
    'owner-content.tcv2', 'independent-catalog-anchor.cva3',
    'owner-authorization.cpv4', 'owner-handoff.chb1',
    'supervisor.stdout', 'supervisor.stderr', 'worker/cost-events.jsonl',
    'worker/process.log', 'worker/ready.json', 'worker/supervisor.json',
)
# These are required by this exact successful route, not a guessed inventory:
# native writes the custody/typed/input/log artifacts before returning success;
# the pinned sealed worker writes both next-use records and ready.json; its
# pinned default runtime supervisor writes process.log and supervisor.json;
# its first observed stage creates cost-events.jsonl. Failures retain each
# missing path explicitly and never turn missing evidence into a passing run.
GATES = {
    'candidate': {
        'preflight', 'source-before', 'source-after', 'rustc-version', 'cargo-version',
        'locked-graph', 'locked-all-feature-graph', 'format', 'inventory',
        'test_cell_discovery_v3_ci', 'test_cell_storage_convergence_ci',
        'test_ci_source_integrity', 'check_pq_research_integration',
        'test_pq_research_integration', 'check_repository', 'da-complete',
        'cell_sealed_research_next_use_v2-tests',
        'cell_sealed_research_paged_next_use_v1-tests', 'node-storage', 'strict-clippy',
        'next-architecture-python', 'counterexample-fixture',
        'cell_complete_version_vector', 'cell_discovery_epoch_v3_vector',
        'cell_version_content_vector', 'cell_version_retention_v3_vector',
        'cell_storage_descriptor_reference', 'sealed-research-python-controls',
        'sealed-research-python-readback', 'node-storage-default',
        'clippy-default-trnm-data-availability', 'clippy-default-trnm-pon-node',
        *{f'da-required-{index:02d}{suffix}'
          for index in range(1, 6) for suffix in ('', '-readback')},
        *{f'node-required-{index:02d}{suffix}'
          for index in range(1, 14) for suffix in ('', '-readback')},
    },
    'observers': {
        'preflight', 'source-before', 'source-after', 'rustc-version', 'cargo-version',
        'residency-observation', 'paged-model-build',
    },
}
ENVIRONMENT_KEYS = (
    'CARGO_HOME', 'CARGO_TARGET_DIR', 'CARGO_BUILD_JOBS', 'CARGO_INCREMENTAL',
    'RUSTC', 'RUSTDOC', 'LD_LIBRARY_PATH', 'RUST_TEST_THREADS',
    'OPENSSL_DIR', 'OPENSSL_STATIC', 'OPENSSL_CONF', 'OPENSSL_MODULES',
    'TRNM_PQ_OPENSSL', 'TRNM_PQ_OPENSSL_SHA256', 'TRNM_PQ_OPENSSL_VERSION',
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def regular_file(path: Path, maximum: int | None = None):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode), f'regular file required: {path}')
        require(maximum is None or info.st_size <= maximum, f'file size bound: {path}')
        return os.fdopen(descriptor, 'rb')
    except BaseException:
        os.close(descriptor)
        raise


def file_hash(path: Path) -> str:
    value = hashlib.sha256()
    with regular_file(path) as stream:
        before = os.fstat(stream.fileno())
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
        after = os.fstat(stream.fileno())
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
             before.st_ctime_ns) ==
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
             after.st_ctime_ns), f'file changed while hashing: {path}')
    return value.hexdigest()


def read_pinned_json(path: Path, pin: str) -> tuple[dict, bytes]:
    with regular_file(path, 4 * 1024 * 1024) as stream:
        raw = stream.read(4 * 1024 * 1024 + 1)
    require(len(raw) <= 4 * 1024 * 1024, 'JSON input bound')
    require(hashlib.sha256(raw).hexdigest() == pin, f'independent file pin: {path}')
    value = json.loads(raw)
    require(isinstance(value, dict), f'JSON object required: {path}')
    return value, raw


def write_new(path: Path, raw: bytes) -> None:
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def write_json(path: Path, value: dict) -> None:
    write_new(path, (json.dumps(value, sort_keys=True, indent=2) + '\n').encode())


def outside_source(path: Path, source: Path) -> bool:
    return path != source and source not in path.parents


def checked_identity(root: Path, source: str, tree: str) -> dict:
    def git(*args: str) -> str:
        return subprocess.check_output(['git', '--no-replace-objects', *args],
                                       cwd=root, text=True).strip()
    identity = {'commit': git('rev-parse', 'HEAD'), 'tree': git('rev-parse', 'HEAD^{tree}'),
                'status': git('status', '--porcelain', '--untracked-files=all')}
    require(identity == {'commit': source, 'tree': tree, 'status': ''},
            'exact clean candidate identity required')
    return identity


def verify_gate(path: Path, pin: str, lane: str, args, runner_pin: str) -> tuple[dict, bytes]:
    value, raw = read_pinned_json(path, pin)
    require(value.get('schema') == GATE_SCHEMA and value.get('lane') == lane
            and value.get('source') == args.source and value.get('root') == str(args.repo)
            and value.get('runner_sha256') == runner_pin, 'gate source/runner/lane binding')
    for field in ('completed', 'all_commands_passed', 'source_unchanged', 'provider_pin_unchanged'):
        require(value.get(field) is True, f'{lane} gate is not complete/passing: {field}')
    require(all(value.get(field) is False for field in
                ('production_qualified', 'independent_domains_qualified', 'wan_qualified')),
            'component observations cannot promote qualification')
    commands = value.get('commands')
    require(isinstance(commands, list) and commands, 'nonempty original gate command set')
    names = [entry['name'] for entry in commands]
    require(len(set(names)) == len(names) and GATES[lane] <= set(names),
            'complete unique original gate roster required')
    for item in commands:
        name = item['name']
        require(re.fullmatch(r'[a-zA-Z0-9_.-]+', name) is not None, 'canonical gate name')
        require(item.get('status') == 'completed' and type(item.get('exit_code')) is int
                and item['exit_code'] == 0 and item.get('timed_out') is False
                and item.get('exact_native_test_observed', True) is True,
                f'original gate command did not pass: {name}')
        if re.fullmatch(r'(da|node)-required-[0-9]{2}', name):
            require(item.get('exact_native_test_observed') is True,
                    f'exact native libtest receipt required: {name}')
        for stream in ('stdout', 'stderr'):
            log = path.parent / f'{name}.{stream}'
            require(log.stat().st_size == item.get(stream + '_bytes')
                    and file_hash(log) == item.get(stream + '_sha256'),
                    f'original command log identity: {name}.{stream}')
    before = (path.parent / 'source-before.stdout').read_bytes()
    after = (path.parent / 'source-after.stdout').read_bytes()
    require(before == after, 'original source receipts differ')
    receipt = json.loads(before)
    require(receipt.get('schema') == 'trnm-ci-source-v1'
            and receipt.get('tested_commit') == args.source
            and receipt.get('tested_tree') == args.tree
            and receipt.get('tracked_worktree_verified') is True,
            'original complete physical source receipt required')
    return value, raw


def verify_spec(spec: dict, original: dict) -> Path:
    operation = spec['source']['operation']
    require(isinstance(operation, str) and re.fullmatch(r'[0-9a-f]{64}', operation) is not None
            and operation != '0' * 64
            and operation not in (original['source']['operation'],
                                  original['expected']['previous_operation']),
            'fresh canonical operation identity required')
    require(spec['expected']['previous_operation'] == original['source']['operation'],
            'new observation must name the actual original operation')
    comparable = copy.deepcopy(spec)
    for field in ('operation', 'output'):
        comparable['source'][field] = original['source'][field]
    comparable['expected']['previous_operation'] = original['expected']['previous_operation']
    require(comparable == original, 'immutable input pins or original operation contract changed')
    source = spec['source']
    require(source['seconds'] == INTERNAL_SECONDS
            and source['max_snapshot_bytes'] == 512 << 20
            and source['runtime_rss_bytes'] == 8 << 30 and source['threads'] == 4
            and spec['custody']['available_slots'] == [0, 2, 4, 5]
            and spec['custody']['chunks_per_page'] == 64,
            'original time, memory, parallelism and four-slot contract required')
    return Path(source['output'])


def gate_command(name: str, argv: list[str], args, environment: dict) -> dict:
    started = time.monotonic_ns()
    item = {'argv': argv, 'cwd': str(args.repo), 'started_unix_ns': time.time_ns(),
            'timeout_seconds': 300, 'scope': 'outside native operation'}
    write_json(args.output / f'{name}-start.json', item)
    with (args.output / f'{name}.stdout').open('xb') as out, \
            (args.output / f'{name}.stderr').open('xb') as err:
        result = subprocess.run(argv, cwd=args.repo, env=environment, stdout=out, stderr=err,
                                timeout=300, check=False)
    item.update(exit_code=result.returncode, elapsed_ns=time.monotonic_ns() - started)
    for stream in ('stdout', 'stderr'):
        path = args.output / f'{name}.{stream}'
        item[stream + '_sha256'] = file_hash(path)
        item[stream + '_bytes'] = path.stat().st_size
    write_json(args.output / f'{name}-result.json', item)
    require(result.returncode == 0, f'existing source gate failed: {name}')
    if name.startswith('source-'):
        observed = json.loads((args.output / f'{name}.stdout').read_bytes())
        require(observed.get('tested_commit') == args.source
                and observed.get('tested_tree') == args.tree
                and observed.get('tracked_worktree_verified') is True,
                f'complete physical source identity failed: {name}')
    return item


def stop_and_reap(pid: int):
    try:
        os.killpg(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    for _ in range(40):
        completed = os.wait4(pid, os.WNOHANG)
        if completed[0]:
            return completed
        time.sleep(0.25)
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    return os.wait4(pid, 0)


def execute_native(binary: Path, args, environment: dict, report: dict) -> dict:
    argv = [str(binary), str(args.spec), args.spec_sha256]
    launch = {'source': args.source, 'tree': args.tree, 'argv': argv,
              'cwd': str(args.repo / 'trillionnium'), 'binary_sha256': args.binary_sha256,
              'input_sha256': args.spec_sha256, 'started_unix_ns': time.time_ns(),
              'internal_original_seconds': INTERNAL_SECONDS,
              'external_cleanup_watchdog_seconds': WATCHDOG_SECONDS}
    write_json(args.output / 'execution-start.json', launch)
    started = time.monotonic_ns()
    watchdog = False
    interruption = None
    with (args.output / 'native.stdout').open('xb') as out, \
            (args.output / 'native.stderr').open('xb') as err:
        process = subprocess.Popen(argv, cwd=args.repo / 'trillionnium', env=environment,
                                   stdout=out, stderr=err, start_new_session=True)
        report['native_started'] = True
        done = 0
        try:
            write_json(args.output / 'native-pid.json', {'pid': process.pid})
            while True:
                done, status, usage = os.wait4(process.pid, os.WNOHANG)
                if done:
                    break
                if time.monotonic_ns() - started >= WATCHDOG_SECONDS * 1_000_000_000:
                    watchdog = True
                    done, status, usage = stop_and_reap(process.pid)
                    break
                time.sleep(0.25)
        except BaseException as error:
            interruption = type(error).__name__
            if not done:
                done, status, usage = stop_and_reap(process.pid)
        process.returncode = os.waitstatus_to_exitcode(status)
    observed = {
        'pid': process.pid, 'reaped_pid': done, 'wait_status': status,
        'exit_code': process.returncode, 'watchdog_terminated': watchdog,
        'interruption': interruption, 'elapsed_ns': time.monotonic_ns() - started,
        'child_user_cpu_seconds': usage.ru_utime, 'child_system_cpu_seconds': usage.ru_stime,
        'child_max_rss_kib': usage.ru_maxrss,
        'scope': 'One native process wait4; native packaging, recovery and forwards included. '
                 'Source checks, build and evidence collection excluded. '
                 'Not simultaneous process-tree RSS or independent WAN service.',
    }
    for stream in ('stdout', 'stderr'):
        path = args.output / f'native.{stream}'
        observed[stream + '_sha256'] = file_hash(path)
        observed[stream + '_bytes'] = path.stat().st_size
    write_json(args.output / 'execution-result.json', observed)
    return observed


def collect_metadata(operation: Path, destination: Path) -> list[dict]:
    destination.mkdir()
    entries = []
    for relative in COLLECT:
        path = operation / relative
        if not path.exists():
            entries.append({'path': relative, 'present': False})
            continue
        parent = path.parent
        while parent != operation:
            require(not parent.is_symlink() and parent.is_dir(), 'metadata parent type')
            parent = parent.parent
        with regular_file(path, 16 * 1024 * 1024) as stream:
            data = stream.read(16 * 1024 * 1024 + 1)
        require(len(data) <= 16 * 1024 * 1024, 'retained metadata bound')
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        write_new(target, data)
        entries.append({'path': relative, 'present': True, 'bytes': len(data),
                        'sha256': hashlib.sha256(data).hexdigest()})
    return entries


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('repo', 'target', 'original-spec', 'spec', 'candidate-summary',
                 'observer-summary', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('source', 'tree', 'spec-sha256', 'candidate-summary-sha256',
                 'observer-summary-sha256', 'binary-sha256'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    require(sys.platform == 'linux', 'original Linux model route required')
    for name in ('source', 'tree'):
        require(re.fullmatch(r'[0-9a-f]{40}', getattr(args, name)) is not None,
                'exact canonical source/tree required')
    for name in ('spec_sha256', 'candidate_summary_sha256', 'observer_summary_sha256',
                 'binary_sha256'):
        require(re.fullmatch(r'[0-9a-f]{64}', getattr(args, name)) is not None,
                'independent SHA-256 pin required')
    for name in ('repo', 'target', 'original_spec', 'spec', 'candidate_summary',
                 'observer_summary', 'output'):
        path = getattr(args, name)
        require(path.is_absolute() and path == path.resolve(), f'canonical absolute {name}')
    require(outside_source(args.output, args.repo) and outside_source(args.target, args.repo),
            'operation records and target must be outside source')
    require(not args.output.exists(), 'fresh evidence output required; preserve prior results')
    args.output.mkdir(mode=0o700)
    report = {'schema': 'cell-storage-four-gates-paged-operation-v1',
              'source': args.source, 'tree': args.tree, 'root': str(args.repo),
              'runner_sha256': file_hash(Path(__file__).resolve()),
              'started_unix_ns': time.time_ns(), 'completed': False, 'native_started': False,
              'run_passed': False, 'production_qualified': False, 'independent_domains_qualified': False,
              'wan_qualified': False, 'ordinary_hepta_final_use_qualified': False}
    lock = None
    try:
        identity = checked_identity(args.repo, args.source, args.tree)
        runner_pin = file_hash(args.repo / 'scripts/ci/run_cell_storage_four_gates_v1.py')
        candidate, candidate_raw = verify_gate(args.candidate_summary,
            args.candidate_summary_sha256, 'candidate', args, runner_pin)
        observer, observer_raw = verify_gate(args.observer_summary,
            args.observer_summary_sha256, 'observers', args, runner_pin)
        environment_values = observer['environment']
        require(all(candidate['environment'].get(key) == environment_values.get(key)
                    for key in ENVIRONMENT_KEYS), 'candidate/build environment identity differs')
        require(environment_values['CARGO_TARGET_DIR'] == str(args.target),
                'binary target must be the passing observer target')
        require(environment_values['TRNM_PQ_OPENSSL_SHA256'] == PROVIDER_SHA256
                and environment_values['TRNM_PQ_OPENSSL_VERSION'] == '3.5.9',
                'original provider pin/version required')
        provider = Path(environment_values['TRNM_PQ_OPENSSL'])
        require(file_hash(provider) == PROVIDER_SHA256, 'current provider pin mismatch')
        lock = Path(str(args.target) + '.owner.lock').open('a+b')
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        binary = args.target / 'release/examples' / EXAMPLE
        require(file_hash(binary) == args.binary_sha256, 'independent current binary pin')
        original, original_raw = read_pinned_json(args.original_spec, ORIGINAL_SPEC_SHA256)
        spec, spec_raw = read_pinned_json(args.spec, args.spec_sha256)
        operation = verify_spec(spec, original)
        require(operation.is_absolute() and operation == operation.resolve()
                and outside_source(operation, args.repo) and operation != args.output
                and not operation.exists() and args.output not in operation.parents,
                'fresh separate operation output required')
        materials = []
        for group in ('environment', 'model'):
            for name, item in spec['source'][group].items():
                path = Path(item['path'])
                require(path.is_absolute() and file_hash(path) == item['sha256'],
                        f'original material pin: {group}/{name}')
                materials.append({'group': group, 'name': name, 'path': str(path),
                                  'bytes': path.stat().st_size, 'sha256': item['sha256']})
        require(len(materials) == 30 and sum(item['bytes'] for item in materials) == 280269602,
                'original complete model/environment payload scope')
        python = spec['source']['python']
        require(file_hash(Path(python['path'])) == python['sha256'], 'original interpreter pin')
        temporary = args.output / 'tmp'
        temporary.mkdir(mode=0o700)
        environment = os.environ.copy()
        environment.update({key: environment_values[key] for key in ENVIRONMENT_KEYS})
        environment.update({'PATH': str(Path(environment_values['RUSTC']).parent)
                            + os.pathsep + environment.get('PATH', ''),
                            'TMPDIR': str(temporary), 'PYTHONDONTWRITEBYTECODE': '1',
                            'CARGO_TERM_COLOR': 'never'})
        for name, raw in (('original-input.json', original_raw), ('fresh-input.json', spec_raw),
                          ('candidate-gates.json', candidate_raw), ('observer-gates.json', observer_raw)):
            write_new(args.output / name, raw)
        write_json(args.output / 'admission.json', {
            'identity': identity, 'binary': str(binary), 'binary_sha256': args.binary_sha256,
            'original_spec_sha256': ORIGINAL_SPEC_SHA256, 'fresh_spec_sha256': args.spec_sha256,
            'candidate_summary_sha256': args.candidate_summary_sha256,
            'observer_summary_sha256': args.observer_summary_sha256,
            'original_materials': materials, 'python': python, 'environment': environment_values,
            'native_tmpdir': str(temporary), 'operation': spec['source']['operation'],
            'operation_output': str(operation), 'internal_seconds': INTERNAL_SECONDS,
            'outer_watchdog_seconds': WATCHDOG_SECONDS,
            'no_rs_precomputation': True, 'no_build_by_this_observer': True,
        })
        gate_command('preflight', ['bash', 'scripts/project-preflight.sh', '--audit'], args, environment)
        source_command = [sys.executable, '-B', 'scripts/ci/verify_ci_source.py',
                          '--kind', 'head', '--expected-head', args.source]
        gate_command('source-before', source_command, args, environment)
        require(file_hash(binary) == args.binary_sha256 and file_hash(provider) == PROVIDER_SHA256,
                'binary/provider changed before execution')
        report['native_start_attempted'] = True
        observed = execute_native(binary, args, environment, report)
        report['native'] = observed
        report['operation_output'] = str(operation)
        report['collection'] = collect_metadata(operation, args.output / 'operation-metadata')
        report['metadata_evidence_complete'] = all(item['present'] for item in report['collection'])
        native_path = args.output / 'operation-metadata/native-result.json'
        native = json.loads(native_path.read_bytes()) if native_path.is_file() else {}
        report['native_observed_passed'] = native.get('passed') is True
        report['native_stage'] = native.get('stage')
        report['native_error'] = native.get('error')
        report['latency_observation_v1'] = native.get('latency_observation_v1')
        gate_command('source-after', source_command, args, environment)
        report['source_unchanged'] = ((args.output / 'source-before.stdout').read_bytes()
                                      == (args.output / 'source-after.stdout').read_bytes())
        report['identity_after'] = checked_identity(args.repo, args.source, args.tree)
        report['provider_pin_unchanged'] = file_hash(provider) == PROVIDER_SHA256
        report['binary_pin_unchanged'] = file_hash(binary) == args.binary_sha256
        report['spec_pin_unchanged'] = file_hash(args.spec) == args.spec_sha256
        captured_spec = args.output / 'operation-metadata/original-paged-source-inputs.json'
        report['native_input_pin_matches'] = (captured_spec.is_file()
                                             and file_hash(captured_spec) == args.spec_sha256)
        report['completed'] = True
        report['run_passed'] = (report['native_observed_passed'] and observed['exit_code'] == 0
                               and not observed['watchdog_terminated']
                               and observed['interruption'] is None
                               and report['source_unchanged'] and report['provider_pin_unchanged']
                               and report['binary_pin_unchanged'] and report['spec_pin_unchanged']
                               and report['native_input_pin_matches'] and report['metadata_evidence_complete'])
    except BaseException as error:
        report['failure_type'] = type(error).__name__
        report['failure'] = str(error)
    finally:
        report['ended_unix_ns'] = time.time_ns()
        write_json(args.output / 'summary.json', report)
        if lock is not None:
            lock.close()
    print(json.dumps({'summary': str(args.output / 'summary.json'),
                      'native_started': report['native_started'],
                      'run_passed': report['run_passed'], 'failure': report.get('failure')}, sort_keys=True),
          flush=True)
    return 0 if report['run_passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())

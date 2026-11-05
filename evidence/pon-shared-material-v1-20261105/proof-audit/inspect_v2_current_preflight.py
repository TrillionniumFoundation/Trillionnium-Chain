#!/usr/bin/env python3
"""Read current v2 prerequisites; write only the requested observation JSON.

No dependency download, compilation, prover, verifier or stage is invoked.
The coordinator's actual disk expression is read from its AST and evaluated
against a fresh disk sample and its actual read-only footprint() function.
"""
import ast
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

sys.dont_write_bytecode = True
BASE = Path('/workspace/scratch/8de1bcb09af8')
REPO = BASE / 'chain'
OUTPUT = BASE / 'proof-audit/v2-current-preflight.json'
COORDINATOR = REPO / 'formal/pon-nakamoto-v1/experiments/w1_full_staged_run.py'
RUNTIME = BASE / 'v2-runtime'
CHECKPOINT = BASE / 'v2-full-checkpoint'


def stamp():
    value = time.time_ns()
    return {'unix_ns': value, 'utc': datetime.datetime.fromtimestamp(
        value / 1e9, datetime.timezone.utc).isoformat()}


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def command(argv, cwd=REPO):
    started = stamp()
    result = subprocess.run(argv, cwd=cwd, text=True, capture_output=True,
                            timeout=30, check=False)
    return {'argv': list(map(str, argv)), 'cwd': str(cwd),
            'started': started, 'finished': stamp(),
            'returncode': result.returncode, 'succeeded': result.returncode == 0,
            'stdout': result.stdout, 'stderr': result.stderr}


def observe(sources, action):
    started = stamp()
    try:
        data = action()
        return {'started': started, 'finished': stamp(), 'sources': sources,
                'observation_succeeded': True, 'data': data}
    except Exception as error:
        return {'started': started, 'finished': stamp(), 'sources': sources,
                'observation_succeeded': False,
                'error': f'{type(error).__name__}: {error}'}


def retained_metadata():
    path = BASE / 'frozen-v2-locked-dependency-resolution.json'
    log = BASE / 'frozen-v2-locked-dependency-resolution.log'
    value = json.loads(path.read_text())
    return {'record': value, 'record_sha256': sha(path),
            'raw_log_exists': log.is_file(), 'raw_log_sha256': sha(log),
            'locked_metadata_succeeded': value.get('returncode') == 0
                and '--locked' in value.get('command', [])
                and value.get('lockfile_relaxed') is False,
            'metadata_rerun_by_this_inspector': False,
            'original_command_start_time_available_in_record': False,
            'timestamp_scope': 'Current read of retained real command evidence; not its original execution time.'}


def source_state():
    head = command(['git', 'rev-parse', 'HEAD'])
    status = command(['git', 'status', '--porcelain', '--untracked-files=normal'])
    merge = command(['git', 'rev-parse', '-q', '--verify', 'MERGE_HEAD'])
    frozen_path = BASE / 'frozen-source-checks.json'
    frozen = json.loads(frozen_path.read_text())
    return {'head': head, 'status': status, 'merge_head': merge,
            'current_git_status_clean_observed': status['succeeded'] and not status['stdout'],
            'merge_pending_observed': merge['succeeded'],
            'current_raw_source_verification_run': False,
            'snapshot_is_atomic': False,
            'historical_frozen_source_commit': frozen.get('source_commit'),
            'historical_frozen_source_checks_sha256': sha(frozen_path),
            'historical_checks_are_current_clean_source_attestation': False}


def tools_state():
    roots = ['/root', '/workspace/scratch', '/opt', '/tmp']
    names = ['r0vm', 'w1-staged-prover-v2', 'w1-verify-v2',
             'cargo-risczero', 'rzup', 'rustc']
    argv = ['rg', '--files', '--hidden', '--no-ignore']
    for name in names:
        argv += ['-g', name]
    scan = command(argv + roots)
    found = {}
    for line in scan['stdout'].splitlines():
        path = Path(line)
        if path.is_file() and os.access(path, os.X_OK):
            found.setdefault(path.name, []).append(str(path))
    rustup = command(['/root/.cargo/bin/rustup', 'toolchain', 'list'])
    risc0_home = Path(os.environ.get('RISC0_HOME', '/root/.risc0'))
    guest_candidates = [p for p in found.get('rustc', [])
                        if 'risc0' in p.lower() or '1.88.0' in p]
    return {'path_lookup': {name: shutil.which(name) for name in
                ('cargo', 'rustc', 'rustup', 'rzup', 'r0vm', 'cargo-risczero')},
            'host_cargo_absolute_exists': Path('/root/.cargo/bin/cargo').is_file(),
            'host_toolchains': rustup, 'filename_scan': scan,
            'scan_complete_without_reported_errors': scan['returncode'] in (0, 1)
                and not scan['stderr'],
            'executable_matches': found,
            'r0vm_executable_found': bool(found.get('r0vm')),
            'v2_staged_runner_executable_found': bool(found.get('w1-staged-prover-v2')),
            'v2_fresh_verifier_executable_found': bool(found.get('w1-verify-v2')),
            'risc0_guest_rustc_candidate_found': bool(guest_candidates),
            'risc0_guest_rustc_candidates': guest_candidates,
            'configured_risc0_home': str(risc0_home),
            'configured_risc0_home_exists': risc0_home.is_dir(),
            'configured_risc0_toolchain_directory_exists': (risc0_home / 'toolchains').is_dir(),
            'guest_candidate_executed_or_authenticated': False,
            'scope': 'Executable filename inventory of listed roots and configured toolchain directory; no download or installation.'}


def official_pins():
    directory = REPO / 'evidence/pon-w1-statement-v2-20261105'
    rows = []
    for name in ('risc0-rust-1.88.0.tar.gz.json', 'cargo-risczero-v3.0.3.tgz.json'):
        path = directory / name
        rows.append(observe([str(path)], lambda path=path: {
            'record_sha256': sha(path), 'retained_record': json.loads(path.read_text()),
            'download_performed_now': False, 'remote_availability_checked_now': False}))
    source = (REPO / 'formal/pon-nakamoto-v1/w1_zkvm/host/src/bin/w1-staged-prover.rs').read_text()
    expected = '2acdf550f9aca4d05b74072463e4ed307c3824309c754a5cb5f93aa84f3390e6'
    return {'archive_pins': rows, 'r0vm_sha256': expected,
            'r0vm_pin_found_in_actual_runner_source': f'const R0VM_SHA256: &str = "{expected}";' in source,
            'r0vm_historical_bytes': 108764424,
            'guest_rust_version': '1.88.0', 'host_rust_version': '1.95.0',
            'host_guest_sdk_version': '3.0.3', 'independent_verifier_sdk_version': '3.0.6',
            'historical_binaries_recovered_now': False}


def fixtures():
    declaration = REPO / 'evidence/pon-w1-statement-v2-20261105/input-declaration.json'
    declared = json.loads(declaration.read_text())
    selected = [
        (REPO / 'evidence/pon-w1-complete-succinct-20261028/full-proof/input.bin',
         declared['input_sha256'], 49506),
        (REPO / 'evidence/pon-w1-statement-v2-20261105/expected-artifacts.bin',
         declared['expected_artifacts_sha256'], 64)]
    rows = []
    for path, expected, size in selected:
        def inspect(path=path, expected=expected, size=size):
            exists = path.is_file()
            actual_hash = sha(path) if exists else None
            actual_size = path.stat().st_size if exists else None
            return {'exists': exists, 'bytes': actual_size, 'sha256': actual_hash,
                    'declared_sha256': expected, 'expected_bytes': size,
                    'matches_retained_input_declaration': exists and actual_hash == expected and actual_size == size,
                    'cryptographic_receipt_verification_performed': False}
        rows.append(observe([str(path), str(declaration)], inspect))
    return rows


def actual_coordinator_guard():
    raw = COORDINATOR.read_text()
    parsed = ast.parse(raw)
    stage = next(node for node in ast.walk(parsed)
                 if isinstance(node, ast.FunctionDef) and node.name == 'stage')
    guard = next(node for node in ast.walk(stage)
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                 and node.func.id == 'require' and len(node.args) == 2
                 and isinstance(node.args[1], ast.Constant)
                 and node.args[1].value == 'declared disk guard reached before next stage')
    sys.path.insert(0, str(COORDINATOR.parent))
    spec = importlib.util.spec_from_file_location('v2_current_readonly_coordinator', COORDINATOR)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    location = CHECKPOINT if CHECKPOINT.exists() else BASE
    sample_time = stamp()
    free = shutil.disk_usage(location).free
    size = module.footprint(CHECKPOINT)
    expression = ast.Expression(body=guard.args[0])
    passed = eval(compile(expression, str(COORDINATOR), 'eval'),
                  {'__builtins__': {}}, {'free': free, 'size': size})
    return {'coordinator_sha256': sha(COORDINATOR),
            'actual_condition': ast.get_source_segment(raw, guard.args[0]),
            'condition_function': 'main.<locals>.stage', 'condition_line': guard.lineno,
            'condition_evaluation_uses_actual_coordinator_ast': True,
            'footprint_uses_actual_coordinator_function': True,
            'disk_sample_time': sample_time, 'disk_sample_path': str(location),
            'disk_free_bytes': free, 'checkpoint_path': str(CHECKPOINT),
            'checkpoint_exists': CHECKPOINT.exists(), 'checkpoint_footprint': size,
            'free_disk_floor_bytes': 1024**3, 'checkpoint_disk_cap_bytes': 256*1024**2,
            'original_disk_guard_satisfied': bool(passed),
            'disk_floor_satisfied': free >= 1024**3,
            'checkpoint_cap_satisfied': size['allocated_bytes'] <= 256*1024**2,
            'stage_invoked': False, 'stage_receipt_created': False,
            'interpretation': 'Read-only evaluation of actual stage admission condition; not an invoked proof stage or a failed cryptographic proof.'}


def memory_state():
    data = {}
    for name in ('memory.current', 'memory.max', 'memory.peak', 'memory.events', 'cpu.max'):
        path = Path('/sys/fs/cgroup') / name
        data[name] = observe([str(path)], lambda path=path: {
            'exists': path.exists(), 'value': path.read_text().strip() if path.exists() else None})
    data['scope'] = 'Shared cgroup, not this task allocation or an aggregate proof-only resource measurement.'
    data['coordinator_has_separate_ram_admission_guard'] = False
    data['oom_events_attributed_to_this_task'] = False
    return data


def main():
    started = stamp()
    report = {'schema': 'TRNM-W1-V2-CURRENT-READONLY-PREFLIGHT1',
              'started': started, 'repo': str(REPO),
              'inspector': {'path': str(Path(__file__).resolve()), 'sha256': sha(__file__)},
              'proof_started': False, 'new_proof_generated': False,
              'full_v2_proof_observed': False, 'saved_receipt_controls_run': False,
              'dependency_download_performed': False, 'compilation_started': False,
              'original_guard_lowered': False, 'stage_receipt_created': False}
    report['locked_metadata'] = observe([str(BASE / 'frozen-v2-locked-dependency-resolution.json'),
        str(BASE / 'frozen-v2-locked-dependency-resolution.log')], retained_metadata)
    report['current_source'] = observe([str(REPO), str(BASE / 'frozen-source-checks.json')], source_state)
    report['tool_inventory'] = observe(['/root/.cargo/bin', '/root/.rustup/toolchains',
        '/root/.risc0', '/workspace/scratch', '/opt', '/tmp'], tools_state)
    report['official_pins'] = observe([str(REPO / 'evidence/pon-w1-statement-v2-20261105'),
        str(REPO / 'formal/pon-nakamoto-v1/w1_zkvm/host/src/bin/w1-staged-prover.rs')], official_pins)
    report['fixtures'] = fixtures()
    report['resource_guard'] = observe([str(COORDINATOR), str(BASE), str(CHECKPOINT)], actual_coordinator_guard)
    report['memory'] = memory_state()
    report['original_execution_budget'] = {
        'source_path': str(COORDINATOR), 'total_wall_seconds': 7200,
        'per_new_segment_wall_seconds': 300, 'prepare_wall_seconds': 180,
        'free_disk_floor_bytes': 1024**3, 'checkpoint_disk_cap_bytes': 256*1024**2,
        'budget_changed': False, 'rayon_num_threads': 8,
        'receipt_controls_source_path': str(REPO / 'scripts/w1_v2_receipt_controls.py'),
        'receipt_controls_separate_total_wall_seconds': 120,
        'receipt_controls_expected_total': 58, 'receipt_controls_expected_positive': 1,
        'receipt_controls_expected_negative': 57}
    report['installation_space_preconditions'] = {
        'original_disk_floor_must_remain_satisfied': True,
        'pinned_guest_archive_bytes': 490849318, 'pinned_backend_archive_bytes': 72795381,
        'floor_plus_both_retained_archives_bytes': 1024**3 + 490849318 + 72795381,
        'expanded_guest_toolchain_bytes': None, 'cargo_build_working_set_bytes': None,
        'sufficient_installation_space_established': False,
        'scope': 'Archive lower bound excludes extraction, build caches, binaries, logs and checkpoints. Do not download or build while the original free-space floor is unsatisfied.'}
    report['reproduction'] = {
        'inspector_command': ['python3', str(Path(__file__).resolve())],
        'inspector_output_create_new_only': True,
        'planned_runtime_paths_currently_installed': False,
        'build_commands': [
            ['/root/.cargo/bin/cargo', '+1.95.0', 'build', '--locked', '--release', '--jobs', '1',
             '--manifest-path', 'formal/pon-nakamoto-v1/w1_zkvm/Cargo.toml', '-p', 'trnm-w1-zk-host-v2', '--bin', 'w1-staged-prover-v2'],
            ['/root/.cargo/bin/cargo', '+1.95.0', 'build', '--locked', '--release', '--jobs', '1',
             '--manifest-path', 'formal/pon-nakamoto-v1/w1_v2_verifier/Cargo.toml', '--bin', 'w1-verify-v2']],
        'build_environment_after_pinned_installation': {'RISC0_HOME': str(RUNTIME / 'risc0'),
             'CARGO_TARGET_DIR': str(RUNTIME / 'target'), 'CARGO_BUILD_JOBS': '1', 'RISC0_BUILD_LOCKED': '1'},
        'proof_environment': {'RAYON_NUM_THREADS': '8', 'PYTHONDONTWRITEBYTECODE': '1'},
        'proof_command_after_all_prerequisites': ['python3', str(COORDINATOR),
             '--runner', str(RUNTIME / 'target/release/w1-staged-prover-v2'),
             '--r0vm', str(RUNTIME / 'risc0/bin/r0vm'),
             '--fresh-verifier', str(RUNTIME / 'target/release/w1-verify-v2'),
             '--statement-version', '2', '--prepare-input', str(REPO / 'evidence/pon-w1-complete-succinct-20261028/full-proof/input.bin'),
             '--expected-artifacts', str(REPO / 'evidence/pon-w1-statement-v2-20261105/expected-artifacts.bin'),
             '--checkpoint', str(CHECKPOINT), '--out', str(BASE / 'v2-full-observation'),
             '--total-wall-seconds', '7200', '--local-bytes-per-second', '1000000'],
        'commands_executed_by_inspector': False,
        'preflight_and_clean_frozen_source_required_before_build_and_proof': True}
    report['finished'] = stamp()
    with OUTPUT.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, indent=2, ensure_ascii=False, allow_nan=False)
        stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
    guard = report['resource_guard'].get('data', {})
    print(json.dumps({'output': str(OUTPUT), 'output_sha256': sha(OUTPUT),
        'disk_free_bytes': guard.get('disk_free_bytes'),
        'original_disk_guard_satisfied': guard.get('original_disk_guard_satisfied'),
        'proof_started': False, 'new_proof_generated': False}))


if __name__ == '__main__':
    main()

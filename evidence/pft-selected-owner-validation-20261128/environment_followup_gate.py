import datetime
import hashlib
import json
import os
import pathlib
import re
import signal
import stat
import subprocess
import time

ROOT = pathlib.Path('/tmp/hepta-chain-6523704f97df-real-crate-attempt-1')
SOURCE = ROOT / 'source'
OUT = ROOT / 'owner-wrapper-environment-followup-180s-attempt-1'
HEAD = '1bd4a71c6efaa6921237fd4612d37cb7ef0e4645'
TREE = 'f00edac77554e3ff3a649cd6159b25d1c193ac13'
RUST_TREE = '6b348e35c55a324630aeeb5e2f7727e3a5b1905b'
CLOSURE_SHA = '8da00894e955d760309bad7b161a7223625ecea2a9eefd723937bcb7d9743c44'
NAMES = [
    'selected_catalog_wrapper_returns_frozen_descriptor_and_cold_reopen_agrees',
    'original_owner_refuses_empty_stale_and_changed_execution_before_model_parse',
    'selected_catalog_payload_and_profile_refuse_without_changing_selection',
    'selected_catalog_repinned_invalid_pft_is_refused_by_original_parser',
]


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def source_hash(path):
    current = SOURCE
    assert stat.S_ISDIR(current.lstat().st_mode)
    parts = pathlib.PurePosixPath(path).parts
    assert parts and all(p not in ('..', '.', '/') for p in parts)
    for i, part in enumerate(parts):
        current = current / part
        mode = current.lstat().st_mode
        assert stat.S_ISREG(mode) if i == len(parts) - 1 else stat.S_ISDIR(mode)
    return sha(current.read_bytes())


def run(started):
    deadline = started / 1e9 + 180
    cleanup_end = deadline + 66
    OUT.mkdir(mode=0o700, exist_ok=False)
    pins = {}
    receipts = {}
    result = {
        'schema': 'chain-selected-owner-environment-followup-v1', 'head': HEAD,
        'whole_tree': TREE, 'rust_subtree': RUST_TREE, 'command_cap_seconds': 180,
        'cleanup_reservation_seconds': 66, 'same_monotonic_origin_for_all_commands': True,
        'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'result': 'RUNNING', 'commands': [], 'frozen_control_names': NAMES,
        'named_tests_seen': [], 'new_controls_passed': 0, 'cleanup_complete': True,
        'source_verified_before': False, 'source_unchanged_after': False,
        'original_receipts_unchanged': False, 'actual_wrapper_exercised_public_synthetic': False,
        'old_9_11_6_and_two_sqlite_controls_rerun': False,
        'cargo_or_lockfile_changed': False, 'cargo_profiles_changed': False,
        'complete_repository_checkout': False, 'repository_wide_verification': False,
        'new_scientific_fit': False, 'model_inference': False,
        'private_or_historical_input_read': False, 'host_permission': False,
        'real_user_adoption': False, 'final_use': False, 'quality': False,
        'reward': False, 'payment': False, 'production_activation': False,
    }
    env = os.environ.copy()
    removed = ['CARGO_ENCODED_RUSTFLAGS', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER']
    removed += [k for k in env if k.startswith('CARGO_PROFILE_')]
    for key in removed:
        env.pop(key, None)
    env.update(CARGO_HOME=str(ROOT / 'isolated-cargo-home'), CARGO_TARGET_DIR=str(ROOT / 'target'),
               RUSTC='/home/qian-qi/.cargo/bin/rustc', RUSTFLAGS='-D warnings',
               CARGO_BUILD_JOBS='2', CARGO_NET_OFFLINE='true', GIT_NO_LAZY_FETCH='1')
    result['process_local_removed_overrides'] = removed
    result['process_local_env'] = {k: env.get(k) for k in ['CARGO_HOME', 'CARGO_TARGET_DIR', 'RUSTC', 'RUSTFLAGS', 'CARGO_BUILD_JOBS', 'CARGO_NET_OFFLINE', 'GIT_NO_LAZY_FETCH', 'CARGO_INCREMENTAL']}

    def save():
        (OUT / 'GATE.json').write_text(json.dumps(result, sort_keys=True))

    def command(name, argv, cwd):
        if time.monotonic() >= deadline:
            raise TimeoutError('original 180-second outer command deadline exhausted')
        begin = time.monotonic_ns()
        print(json.dumps({'command_started': name, 'remaining_seconds': deadline - time.monotonic()}), flush=True)
        child = subprocess.Popen(argv, cwd=cwd, env=env, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, start_new_session=True)
        timed_out = False
        try:
            stdout, stderr = child.communicate(timeout=max(0.001, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                stdout, stderr = child.communicate(timeout=max(0.001, cleanup_end - time.monotonic()))
            except subprocess.TimeoutExpired as failure:
                result['cleanup_complete'] = False
                stdout, stderr = failure.output or b'', failure.stderr or b''
                child.stdout.close()
                child.stderr.close()
                child.poll()
        (OUT / (name + '.stdout')).write_bytes(stdout)
        (OUT / (name + '.stderr')).write_bytes(stderr)
        deadline_exceeded = time.monotonic() > deadline
        item = {'outer_command_deadline_exceeded': deadline_exceeded, 'name': name, 'argv': argv, 'exit_code': child.returncode, 'timed_out': timed_out,
                'wall_ns': time.monotonic_ns() - begin, 'stdout_bytes': len(stdout), 'stderr_bytes': len(stderr),
                'stdout_sha256': sha(stdout), 'stderr_sha256': sha(stderr)}
        result['commands'].append(item)
        if name == 'original_owner_wrapper_four_controls':
            seen = re.findall(rb'^test ([^ ]+) \.\.\. (ok|FAILED|ignored)$', stdout, re.MULTILINE)
            result['named_tests_seen'] = [[n.decode(), status.decode()] for n, status in seen]
            result['new_controls_passed'] = sum(status == b'ok' for _, status in seen)
        save()
        print(json.dumps({'command_completed': item}), flush=True)
        if child.returncode or timed_out or deadline_exceeded or not result['cleanup_complete']:
            raise RuntimeError(name + ' failed; no retry in this allocation')
        return stdout

    try:
        raw = (ROOT / 'full-include-closure-materialization/RESULT.json').read_bytes()
        assert sha(raw) == CLOSURE_SHA
        closure = json.loads(raw)
        assert closure['head'] == HEAD and closure['whole_tree'] == TREE and closure['closure_ready'] is True
        assert not closure['missing_targets'] and not closure['unresolved_expressions'] and not closure['lexer_failures']
        assert not closure['include_rust_targets_outside_scanned_subtree']
        pins = closure['source_sha256']
        receipts = closure['original_receipt_sha256']
        assert len(pins) == 1850 and len(receipts) == 7
        assert all(source_hash(p) == h for p, h in pins.items())
        assert all(sha((ROOT / p).read_bytes()) == h for p, h in receipts.items())
        remaining = deadline - time.monotonic()
        assert remaining > 0
        revision = subprocess.run(['git', 'rev-parse', 'HEAD', 'HEAD^{tree}', 'HEAD:trillionnium'],
                                  cwd=SOURCE, env=env, capture_output=True, timeout=min(10, remaining))
        assert revision.returncode == 0 and revision.stdout.decode().splitlines() == [HEAD, TREE, RUST_TREE]
        result.update(source_verified_before=True, source_sha256=pins, source_pin_count=len(pins),
                      original_receipt_sha256=receipts, closure_sha256=CLOSURE_SHA)
        save()
        command('project_preflight', ['bash', 'scripts/project-preflight.sh'], SOURCE)
        stdout = command('original_owner_wrapper_four_controls', [
            '/home/qian-qi/.cargo/bin/cargo', 'test', '--offline', '--locked', '-p', 'trnm-pon-node',
            '--lib', 'pft_selected_inspection_v1::owner_tests::', '--', '--test-threads=1',
        ], SOURCE / 'trillionnium')
        assert sorted(result['named_tests_seen']) == sorted([['pft_selected_inspection_v1::owner_tests::' + n, 'ok'] for n in NAMES])
        assert re.search(rb'test result: ok\. 4 passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out', stdout)
        result.update(result='PASS', actual_wrapper_exercised_public_synthetic=True,
                      synthetic_sqlite_selection_exercised=True)
    except Exception as error:
        result.update(result='FOLLOWUP_GATE_FAILURE', error=repr(error))
    finally:
        try:
            result['source_unchanged_after'] = bool(pins) and all(source_hash(p) == h for p, h in pins.items())
            result['original_receipts_unchanged'] = bool(receipts) and all(sha((ROOT / p).read_bytes()) == h for p, h in receipts.items())
        except Exception as error:
            result['postflight_error'] = repr(error)
            result['source_unchanged_after'] = False
            result['original_receipts_unchanged'] = False
        if not result['source_unchanged_after'] or not result['original_receipts_unchanged'] or time.monotonic() > cleanup_end:
            result['result'] = 'FOLLOWUP_GATE_FAILURE'
        result['outer_elapsed_ns_before_final_serialization'] = time.monotonic_ns() - started
        result['finished_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        save()
        print(json.dumps({k: v for k, v in result.items() if k != 'source_sha256'}), flush=True)
    return result['result'] == 'PASS'

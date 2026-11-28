import datetime, hashlib, json, os, pathlib, signal, subprocess, time

root = pathlib.Path('/tmp/hepta-chain-6523704f97df-selected-pft-binding-offline-attempt-1')
manifest = json.loads((root / 'PREPARATION_MANIFEST.json').read_text())
prepared = json.loads((root / 'PREPARATION_RESULT.json').read_text())
assert not (root / 'FIRST_GATE.json').exists(), 'do not replay the first gate'
pins = dict(manifest['sha256'])
pins.update(prepared['formatted_sha256'])
result = {
    'schema': 'trnm-pft-selected-binding-first-controls-v1', 'attempt': 1,
    'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'source_sha256': pins, 'engineering_deadline_seconds': 120,
    'gate_scope': 'pure-selected-profile-binding-and-refusal-only',
    'prior_loader_gate_wall_ns': 7654649710, 'prior_loader_gate_replayed': False,
    'expected_new_control_groups': 6, 'expected_old_control_groups_filtered': 20,
    'actual_owner_compiled_or_exercised': False, 'wrapper_typechecked': False,
    'full_crate_build': False, 'historical_read_or_xw': False,
    'original_core_controls_rerun': False, 'scientific_experiment_completed': False,
    'source_authentication': False, 'training_statistics_verified': False,
    'normal_equations_verified': False, 'quality_improved': False,
    'current_permission': False, 'native_adoption': False, 'final_use': False,
    'real_user_b': False, 'reward': False, 'payment': False,
    'production_activation': False, 'consensus': False, 'commands': [],
}
(root / 'FIRST_GATE.json').write_text(json.dumps(result, sort_keys=True))
env = os.environ.copy()
cleared = ['CARGO_ENCODED_RUSTFLAGS', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER']
for name in cleared:
    env.pop(name, None)
env['CARGO_HOME'] = str(root / 'isolated-cargo-home')
env['CARGO_TARGET_DIR'] = str(root / 'target')
env['RUSTC'] = '/home/qian-qi/.cargo/bin/rustc'
env['RUSTFLAGS'] = '-D warnings'
result['process_local_env'] = {key: env[key] for key in ['CARGO_HOME', 'CARGO_TARGET_DIR', 'RUSTC', 'RUSTFLAGS']}
result['process_local_removed_overrides'] = cleared
deadline = time.monotonic() + 120
try:
    assert prepared['result'] == 'PASS' and not prepared['compilation_started']
    for relative, digest in pins.items():
        assert hashlib.sha256((root / relative).read_bytes()).hexdigest() == digest, relative
    metadata = json.loads((root / 'metadata.stdout').read_bytes())
    features = next(n['features'] for n in metadata['resolve']['nodes'] if 'serde_json@1.0.149' in n['id'])
    assert 'arbitrary_precision' in features
    result['serde_json_resolved_features'] = features
    for name, command in [
        ('version', ['/home/qian-qi/.cargo/bin/rustc', '--version', '--verbose']),
        ('controls', ['/home/qian-qi/.cargo/bin/cargo', 'test', '--offline', '--locked', '--lib', 'pft_selected_inspection_binding_v1::tests', '--', '--test-threads=1']),
    ]:
        started = time.monotonic_ns()
        process = subprocess.Popen(command, cwd=root, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        timed_out = False
        try:
            stdout, stderr = process.communicate(timeout=max(0.001, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            stdout, stderr = process.communicate()
        (root / (name + '.stdout')).write_bytes(stdout)
        (root / (name + '.stderr')).write_bytes(stderr)
        result['commands'].append({'name': name, 'argv': command, 'exit_code': process.returncode, 'timed_out': timed_out, 'wall_ns': time.monotonic_ns() - started, 'stdout_sha256': hashlib.sha256(stdout).hexdigest(), 'stderr_sha256': hashlib.sha256(stderr).hexdigest()})
        (root / 'FIRST_GATE.json').write_text(json.dumps(result, sort_keys=True))
        if process.returncode or timed_out:
            raise RuntimeError(name + ' first gate did not pass')
    assert b'6 passed; 0 failed; 0 ignored; 0 measured; 20 filtered out' in stdout
    fingerprints = list((root / 'target/debug/.fingerprint').glob('chain-pft-selected-inspection-controls-*/test-lib-*.json'))
    assert len(fingerprints) == 1, 'one executed harness fingerprint required'
    fingerprint = json.loads(fingerprints[0].read_bytes())
    result['effective_rustflags'] = fingerprint['rustflags']
    assert result['effective_rustflags'] == ['-D', 'warnings']
    result['fingerprint_sha256'] = hashlib.sha256(fingerprints[0].read_bytes()).hexdigest()
    result['result'] = 'PASS'
except Exception as error:
    result['result'] = 'FIRST_GATE_FAILURE'
    result['error'] = repr(error)
finally:
    result['source_unchanged_after'] = all((root / path).is_file() and hashlib.sha256((root / path).read_bytes()).hexdigest() == digest for path, digest in pins.items())
    if not result['source_unchanged_after']:
        result['result'] = 'FIRST_GATE_FAILURE'
    result['finished_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    (root / 'FIRST_GATE.json').write_text(json.dumps(result, sort_keys=True))
    print(json.dumps(result, separators=(',', ':')))
    for name in ['controls.stdout', 'controls.stderr']:
        if (root / name).exists():
            print(name + ':')
            print((root / name).read_text())

import datetime, hashlib, json, os, pathlib, signal, subprocess, time

root = pathlib.Path('/tmp/hepta-chain-6523704f97df-native-loader-offline-attempt-1')
manifest = json.loads((root / 'PREPARATION_MANIFEST.json').read_text())
prepared = json.loads((root / 'PREPARATION_RESULT.json').read_text())
split = json.loads((root / 'SPLIT_PREPARATION.json').read_text())
assert prepared['result'] == 'PASS' and split['exit_code'] == 0
assert not (root / 'FIRST_GATE.json').exists()
pins = dict(manifest['sha256'])
pins.update(prepared['formatted_sha256'])
pins.update(split['sha256'])
for relative, digest in pins.items():
    assert hashlib.sha256((root / relative).read_bytes()).hexdigest() == digest
metadata = json.loads((root / 'metadata.stdout').read_bytes())
features = next(n['features'] for n in metadata['resolve']['nodes'] if 'serde_json@1.0.149' in n['id'])
assert 'arbitrary_precision' in features
result = {
    'schema': 'trnm-pft-native-loader-first-controls-v1', 'attempt': 1,
    'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'source_sha256': pins, 'engineering_deadline_seconds': 120,
    'serde_json_resolved_features': features,
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
env['CARGO_HOME'] = str(root / 'isolated-cargo-home')
env['CARGO_TARGET_DIR'] = str(root / 'target')
env['RUSTC'] = '/home/qian-qi/.cargo/bin/rustc'
env['RUSTFLAGS'] = '-D warnings'
deadline = time.monotonic() + 120
try:
    for name, command in [
        ('version', ['/home/qian-qi/.cargo/bin/rustc', '--version', '--verbose']),
        ('controls', ['/home/qian-qi/.cargo/bin/cargo', 'test', '--offline', '--locked', '--lib', 'pft_native_loader_v1::tests', '--', '--test-threads=1']),
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
    result['result'] = 'PASS'
except Exception as error:
    result['result'] = 'FIRST_GATE_FAILURE'
    result['error'] = repr(error)
finally:
    result['source_unchanged_after'] = all(hashlib.sha256((root / path).read_bytes()).hexdigest() == digest for path, digest in pins.items())
    result['finished_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    (root / 'FIRST_GATE.json').write_text(json.dumps(result, sort_keys=True))
    print(json.dumps(result, separators=(',', ':')))
    for name in ['controls.stdout', 'controls.stderr']:
        if (root / name).exists():
            print(name + ':')
            print((root / name).read_text())

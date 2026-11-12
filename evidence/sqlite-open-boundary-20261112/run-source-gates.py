import hashlib
import json
import os
import pathlib
import subprocess
import sys
import time

ROOT = pathlib.Path('/workspace/scratch/3069292387f3/chain-sqlite')
OUT = pathlib.Path('/workspace/scratch/3069292387f3/sqlite-evidence')
BIN = pathlib.Path('/workspace/scratch/747d27b1ca86/build-setup/rust195/bin')
HEAD = '9021d15ffe1dfdfb1358a2372b5a472babbf80ac'
ENV = os.environ.copy()
ENV.update(PATH=str(BIN) + ':' + ENV['PATH'], RUSTC=str(BIN / 'rustc'),
           CARGO_HOME='/workspace/scratch/3069292387f3/sqlite-cargo-home',
           CARGO_TARGET_DIR='/workspace/scratch/3069292387f3/sqlite-target',
           CARGO_BUILD_JOBS='2', CARGO_TERM_COLOR='never')
COMMANDS = {
    'source-integrity': (ROOT, ['python3', 'scripts/ci/test_ci_source_integrity.py']),
    'format': (ROOT / 'trillionnium', ['cargo', 'fmt', '--all', '--', '--check']),
    'metadata': (ROOT / 'trillionnium', ['cargo', 'metadata', '--locked', '--offline', '--format-version', '1']),
    'clippy': (ROOT / 'trillionnium', ['cargo', 'clippy', '--locked', '--offline',
        '-p', 'trnm-data-availability', '-p', 'trnm-mvcc-fee',
        '-p', 'trnm-service-settlement', '-p', 'trnm-task-kernel',
        '--all-targets', '--', '-D', 'warnings']),
}

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def snapshot():
    build = json.loads((OUT / 'positive-owners-trnm-data-availability.json').read_text())
    expected = build['source_after']
    return {
        'head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
        'scope': expected['scope'],
        'files_sha256': {name: sha(ROOT / name) for name in expected['files_sha256']},
        'rustc_path': str(BIN / 'rustc'), 'rustc_sha256': sha(BIN / 'rustc'),
    }

receipts = []
for name in sys.argv[1:]:
    cwd, argv = COMMANDS[name]
    subprocess.run(['bash', 'scripts/project-preflight.sh'], cwd=ROOT, check=True)
    before = snapshot()
    assert before['head'] == HEAD
    prefix = OUT / f'gate-{name}'
    started = time.time()
    print(json.dumps({'event': 'start', 'gate': name, 'source_commit': HEAD, 'argv': argv}), flush=True)
    with prefix.with_suffix('.stdout').open('w') as stdout, prefix.with_suffix('.stderr').open('w') as stderr:
        try:
            result = subprocess.run(argv, cwd=cwd, env=ENV, stdout=stdout, stderr=stderr, timeout=1800)
            exit_code = result.returncode
        except subprocess.TimeoutExpired:
            exit_code = 124
    after = snapshot()
    record = {'gate': name, 'argv': argv, 'cwd': str(cwd), 'source_commit': HEAD,
              'started_unix': started, 'elapsed_seconds': time.time() - started,
              'exit_code': exit_code, 'source_before': before, 'source_after': after,
              'selected_sources_unchanged': before == after,
              'environment': {key: ENV.get(key) for key in [
                  'RUSTC', 'RUSTFLAGS', 'RUSTC_WRAPPER', 'CARGO_HOME', 'CARGO_TARGET_DIR', 'CARGO_BUILD_JOBS']}}
    for stream in ['stdout', 'stderr']:
        path = prefix.with_suffix('.' + stream)
        record[stream] = {'path': path.name, 'bytes': path.stat().st_size, 'sha256': sha(path)}
    prefix.with_suffix('.json').write_text(json.dumps(record, indent=2) + '\n')
    receipts.append(record)
    print(json.dumps({key: record[key] for key in ['gate', 'exit_code', 'elapsed_seconds', 'selected_sources_unchanged']}), flush=True)
raise SystemExit(0 if all(r['exit_code'] == 0 and r['selected_sources_unchanged'] for r in receipts) else 1)

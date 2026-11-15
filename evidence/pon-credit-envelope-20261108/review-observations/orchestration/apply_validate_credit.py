from pathlib import Path
import datetime
import hashlib
import json
import os
import re
import subprocess
import time
import zlib

ROOT = Path('/home/qian-qi/chain-credit-envelope-20261108-f7e62')
OUT = Path('/home/qian-qi/credit-envelope-f7e62-run1')
PACKET = Path('/home/qian-qi/credit-envelope-f7e62-transfer-v5.zlib')
BASE = '8d5389748873dad6e296d17f2ff20483b5afa5bc'
BRANCH = 'fix/chain-credit-envelope-20261108-f7e62'
ORIGIN = 'https://github.com/TrillionniumFoundation/Trillionnium-Chain.git'
PACKET_HASH = '5d8d82ce5e5e7cfc1156f2c74c2ea1b32edcc0fcbc977126c995014a1cbe104b'
EXPECTED_NEW = {
    '.github/workflows/pon-credit-envelope.yml',
    'docs/protocol/pon-nakamoto-v1/details/CLASSICAL_QUANTUM_COST_AUDIT_20261108.md',
    'evidence/pon-credit-envelope-20261108/README.md',
    'formal/pon-nakamoto-v1/CREDIT_ENVELOPE_CONTRACT_V1.md',
    'formal/pon-nakamoto-v1/credit_envelope_contract.py',
    'formal/pon-nakamoto-v1/credit_envelope_test_roster_v1.json',
    'formal/pon-nakamoto-v1/normalized_search_cost.py',
    'formal/pon-nakamoto-v1/test_credit_envelope_contract.py',
    'formal/pon-nakamoto-v1/test_normalized_search_cost.py',
    'scripts/ci/run_credit_envelope_checks.py',
}
CI_PATHS = {'scripts/ci/ci_job.sh', 'scripts/ci/check_ci_contract.py',
            'scripts/ci/test_ci_contract.py'}
PLAN = 'docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md'
env = dict(os.environ)
env['PATH'] = str(Path.home()/'.cargo/bin') + os.pathsep + env.get('PATH', '')
env['PYTHONDONTWRITEBYTECODE'] = '1'
env['CARGO_TARGET_DIR'] = '/home/qian-qi/credit-envelope-f7e62-cargo-target'
env['CARGO_BUILD_JOBS'] = '2'
env['GIT_TERMINAL_PROMPT'] = '0'

def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT, env=env, text=True).strip()

def execute(*args, input_text=None):
    result = subprocess.run(args, cwd=ROOT, env=env, input=input_text, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        raise RuntimeError(json.dumps({'command': list(args), 'exit': result.returncode,
                                       'stdout': result.stdout, 'stderr': result.stderr}))
    return result.stdout

def write_json(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')

assert git('rev-parse', 'HEAD') == BASE
assert git('branch', '--show-current') == BRANCH
assert git('remote', 'get-url', 'origin') == ORIGIN
assert not git('status', '--porcelain', '--untracked-files=all')
print(execute('bash', 'scripts/project-preflight.sh'), end='', flush=True)
packed = PACKET.read_bytes()
assert hashlib.sha256(packed).hexdigest() == PACKET_HASH
payload = json.loads(zlib.decompress(packed))
assert payload['schema'] == 'pon-credit-envelope-transfer-v1' and payload['base_sha'] == BASE
assert [row[0] for row in payload['validation_spec']['stages']] == ['preflight', 'finite-math', 'candidate-clock', 'restricted-oracle', 'source-integrity', 'ci-contract', 'repository-negative', 'project-boundary-negative', 'repository-check', 'inventory-check', 'cargo-graph', 'cargo-graph-all-features', 'rust-format', 'rust-clippy', 'retained-native-work']
assert len(payload['files']) == len(EXPECTED_NEW)
assert {row['path'] for row in payload['files']} == EXPECTED_NEW
for row in payload['files']:
    assert hashlib.sha256(row['content'].encode()).hexdigest() == row['sha256']
    assert not (ROOT/row['path']).exists()
assert {m.group(1) for m in re.finditer(r'^diff --git a/(.+) b/\1$', payload['ci_patch'], re.M)} == CI_PATHS
execute('git', 'apply', '--check', '-', input_text=payload['ci_patch'])
plan = (ROOT/PLAN).read_text()
assert payload['plan_append'] and payload['plan_append'] not in plan
OUT.mkdir(exist_ok=False)
(OUT/'development-observations').mkdir()
for name, content in payload['development_observations'].items():
    assert name in {'ci-prefix-initial-failure.log', 'ci-prefix-final.log', 'retained-footer-controls.json', 'runtime-apply-initial-failure.json', 'ci-patch-validation.json'}
    (OUT/'development-observations'/name).write_text(content)
write_json(OUT/'transfer-receipt.json', {
    'packet_sha256': PACKET_HASH, 'base_commit': BASE, 'branch': BRANCH,
    'applied_new_files': sorted(EXPECTED_NEW), 'ci_patch_files': sorted(CI_PATHS),
    'plan_update': 'append-only', 'started_utc': now(),
})
for row in payload['files']:
    target = ROOT/row['path']
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open('x') as stream:
        stream.write(row['content'])
execute('git', 'apply', '-', input_text=payload['ci_patch'])
(ROOT/PLAN).write_text(plan + payload['plan_append'])
execute('git', 'diff', '--check')
execute('git', 'add', '--', *sorted(EXPECTED_NEW | CI_PATHS | {PLAN}))
staged = set(execute('git', 'diff', '--cached', '--name-only').splitlines())
assert staged == EXPECTED_NEW | CI_PATHS | {PLAN}
print(execute('bash', 'scripts/project-preflight.sh', '--staged'), end='', flush=True)
print(execute('git', '-c', 'user.name=Qian QI',
              '-c', 'user.email=102159240+ProfHepta@users.noreply.github.com',
              'commit', '-m', 'formal(pon): add exact classical and quantum credit envelope contract'),
      end='', flush=True)
head = git('rev-parse', 'HEAD')
tree = git('rev-parse', 'HEAD^{tree}')
assert not git('status', '--porcelain', '--untracked-files=all')
write_json(OUT/'source-commit.json', {'commit': head, 'tree': tree, 'base': BASE})
print(json.dumps({'source_commit': head, 'source_tree': tree, 'validation_output': str(OUT)}), flush=True)

stages = []
unittest_stages = {'candidate-clock', 'restricted-oracle', 'source-integrity',
                   'ci-contract', 'repository-negative', 'project-boundary-negative'}

def run_stage(name, argv, timeout=1800):
    started = now()
    tick = time.monotonic()
    stdout = OUT/(name+'.stdout.log')
    stderr = OUT/(name+'.stderr.log')
    exception = None
    with stdout.open('xb') as out_stream, stderr.open('xb') as err_stream:
        try:
            result = subprocess.run(argv, cwd=ROOT, env=env, stdout=out_stream,
                                    stderr=err_stream, timeout=timeout)
            code = result.returncode
        except subprocess.TimeoutExpired:
            code, exception = 124, 'timeout'
        except OSError as error:
            code, exception = 127, type(error).__name__ + ': ' + str(error)
    evidence = {'stage': name, 'argv': argv, 'cwd': str(ROOT), 'started_utc': started,
                'finished_utc': now(), 'elapsed_seconds': round(time.monotonic()-tick, 6),
                'exit_code': code, 'exception': exception,
                'stdout': stdout.name, 'stderr': stderr.name,
                'stdout_sha256': hashlib.sha256(stdout.read_bytes()).hexdigest(),
                'stderr_sha256': hashlib.sha256(stderr.read_bytes()).hexdigest()}
    if code == 0 and name in unittest_stages:
        contents = stdout.read_text(errors='replace') + '\n' + stderr.read_text(errors='replace')
        runs = re.findall(r'^Ran ([0-9]+) tests? in .+$', contents, re.M)
        terminal = re.search(r'(?:\A|\n)Ran ([1-9][0-9]*) tests? in [0-9]+(?:\.[0-9]+)?s\n\nOK\s*\Z', contents)
        evidence['unittest_terminal_receipt_valid'] = len(runs) == 1 and terminal is not None and runs[0] == terminal.group(1)
        evidence['test_methods'] = int(runs[0]) if len(runs) == 1 else None
        if not evidence['unittest_terminal_receipt_valid']:
            evidence['validation_error'] = 'missing, duplicate, zero, skipped or unsuccessful terminal unittest receipt'
    if code == 0 and name == 'finite-math':
        completion = json.loads((OUT/'finite-math/completion.json').read_text())
        evidence['completion'] = completion
        if completion.get('finite_math_checks') != 'PASS' or completion.get('distinct_named_tests_passed') != 77 or completion.get('overall') != 'HOLD' or completion.get('production_activation') is not False:
            evidence['validation_error'] = 'unexpected finite-math completion'
    if code == 0 and name.startswith('cargo-graph'):
        metadata = json.loads(stdout.read_text())
        evidence['workspace_members'] = len(metadata['workspace_members'])
        if len(metadata['workspace_members']) != 26:
            evidence['validation_error'] = 'workspace package inventory mismatch'
    if code == 0 and name == 'retained-native-work':
        lines = re.findall(r'^test result: ok\. ([0-9]+) passed; ([0-9]+) failed; ([0-9]+) ignored;.*$', stdout.read_text(), re.M)
        evidence['native_test_results'] = lines
        if len(lines) != 1 or int(lines[0][0]) <= 0 or lines[0][1:] != ('0', '0'):
            evidence['validation_error'] = 'missing or incomplete native test receipt'
    evidence['passed'] = code == 0 and 'validation_error' not in evidence
    write_json(OUT/(name+'.stage.json'), evidence)
    stages.append(evidence)
    print(json.dumps({'stage': name, 'passed': evidence['passed'], 'exit_code': code,
                      'test_methods': evidence.get('test_methods'), 'elapsed_seconds': evidence['elapsed_seconds'],
                      'validation_error': evidence.get('validation_error')}), flush=True)
    return evidence

before = run_stage('source-before', ['python3', 'scripts/ci/verify_ci_source.py', '--kind', 'head',
                                   '--expected-head', head, '--output', str(OUT/'source-before.json')])
assert before['passed'], 'complete source verification failed before tests'
for name, arguments in payload['validation_spec']['stages']:
    assert re.fullmatch(r'[a-z][a-z-]*', name)
    run_stage(name, [arg.replace('@OUT@', str(OUT)) for arg in arguments])
after = run_stage('source-after', ['python3', 'scripts/ci/verify_ci_source.py', '--kind', 'head',
                                 '--expected-head', head, '--output', str(OUT/'source-after.json')])
identical = after['passed'] and (OUT/'source-before.json').read_bytes() == (OUT/'source-after.json').read_bytes()
summary = {'schema': 'pon-credit-envelope-runtime-validation-v1', 'source_commit': head,
           'source_tree': tree, 'integration_base': BASE, 'finished_utc': now(),
           'stages': stages, 'complete_source_receipts_identical': identical,
           'all_stages_passed': identical and all(stage['passed'] for stage in stages),
           'overall_security_qualification': 'HOLD', 'production_activation': False,
           'source_kind': 'head', 'prospective_merge_executed_here': False}
write_json(OUT/'validation-summary.json', summary)
print(json.dumps({'validation_complete': True, 'source_commit': head,
                  'all_stages_passed': summary['all_stages_passed'], 'overall': 'HOLD'}), flush=True)
raise SystemExit(0 if summary['all_stages_passed'] else 1)

from pathlib import Path
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import time

ROOT = Path('/workspace/scratch/3a200666069f/consensus-pq')
OUT = Path('/workspace/scratch/3a200666069f/qrom-bb-followup-20261108/validation-v2-02')
OUT.mkdir()
os.chdir(ROOT)
ENV = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT)


def source():
    names = set(git('diff', '--name-only').decode().splitlines())
    names.update(git('ls-files', '--others', '--exclude-standard').decode().splitlines())
    for rel in ('config/pon/w1-qrom-implementation-v1.json',
                'config/pon/w1-qrom-required-tests-v1.json',
                'scripts/w1_qrom_implementation_audit.py', 'scripts/w1_lifetime_ledger.py'):
        names.add(rel)
    return {
        'head': git('rev-parse', 'HEAD').decode().strip(),
        'tree': git('rev-parse', 'HEAD^{tree}').decode().strip(),
        'scope': 'uncommitted reviewed patch on bb; not a clean-source CI receipt',
        'status': git('status', '--porcelain=v1', '--untracked-files=all').decode(),
        'tracked_diff_sha256': sha(git('diff', '--binary')),
        'files': [{'path': name, 'bytes': len((ROOT / name).read_bytes()),
                   'sha256': sha((ROOT / name).read_bytes())} for name in sorted(names)],
    }


def write(name, value):
    (OUT / name).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


before = source()
write('source-before.json', before)
(OUT / 'tracked-source.patch').write_bytes(git('diff', '--binary'))
records = []


def run(name, argv, stdout=None, timeout=300):
    output = OUT / (stdout or name + '.stdout.log')
    errors = OUT / (name + '.stderr.log')
    start = time.time()
    with output.open('xb') as out, errors.open('xb') as err:
        p = subprocess.run(argv, cwd=ROOT, env=ENV, stdout=out, stderr=err,
                           timeout=timeout, check=False)
    row = {'name': name, 'argv': argv, 'exit_code': p.returncode,
           'started_unix_seconds': start, 'elapsed_seconds': time.time() - start,
           'stdout': {'path': str(output.relative_to(OUT)), 'sha256': sha(output.read_bytes())},
           'stderr': {'path': errors.name, 'sha256': sha(errors.read_bytes())}}
    records.append(row)
    write('commands.json', records)
    print(json.dumps({'name': name, 'exit_code': p.returncode,
                      'elapsed_seconds': row['elapsed_seconds']}), flush=True)
    if p.returncode:
        raise RuntimeError('fresh command failed: ' + name)


spec = importlib.util.spec_from_file_location('gate_extract', ROOT / 'scripts/ci/test_w1_qrom_workflow_gate.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
workflow = module.WORKFLOW.read_text()
for step in ('named_tests', 'report_scopes'):
    (OUT / (step + '.py')).write_text(module.embedded_python(workflow, step))
implementation = OUT / 'implementation'
implementation.mkdir()
closure = OUT / 'closure'
closure.mkdir()
py = sys.executable
run('implementation-named-84', [py, '-B', str(OUT / 'named_tests.py'), str(implementation)])
run('implementation-map-v2', [py, '-B', 'scripts/w1_qrom_implementation_audit_v2.py',
                            '--output', str(implementation / 'implementation.json')])
run('budget-unknown', [py, '-B', 'scripts/w1_qrom_conditional_budget.py'],
    'implementation/budget-unknown.json')
run('budget-hypothetical-input', [py, '-B', 'scripts/w1_qrom_conditional_budget.py', '--example-input'],
    'implementation/budget-hypothetical-input.json')
run('budget-hypothetical', [py, '-B', 'scripts/w1_qrom_conditional_budget.py', '--input',
                          str(implementation / 'budget-hypothetical-input.json')],
    'implementation/budget-hypothetical.json')
run('implementation-report-scopes', [py, '-B', str(OUT / 'report_scopes.py'), str(implementation)])
digest = 'ee2b11492a362bd4be2f2df4e7ad691f4dd8a78cd9df884979cb3409e117745f'
for mode in ('run', 'check'):
    run('closure-' + mode, [py, '-B', 'scripts/ci/w1_qrom_closure_controls.py', mode,
                           '--roster-sha256', digest, '--output', str(closure)])
commands = {
    'semantics': ['scripts/w1_qrom_semantics_audit.py'],
    'lifetime': ['scripts/w1_lifetime_ledger.py', '--input',
                 'evidence/pon-w1-lifetime-20261107/project-input.json'],
    'composition-unknown': ['scripts/w1_qrom_composition_budget.py'],
    'composition-example': ['scripts/w1_qrom_composition_budget.py', '--example'],
    'joint-oracle-unknown': ['scripts/w1_qrom_joint_oracle_diagnostic.py'],
    'joint-oracle-alias': ['scripts/w1_qrom_joint_oracle_diagnostic.py', '--example', 'alias'],
    'joint-oracle-separated': ['scripts/w1_qrom_joint_oracle_diagnostic.py', '--example', 'separated'],
}
for name, args in commands.items():
    run('reproduce-' + name, [py, '-B', *args], 'closure/' + name + '.json')
    if name in ('semantics', 'lifetime'):
        expected = 'evidence/pon-w1-qrom-source-convergence-20261108/' + name + '-bb026697.json'
    else:
        expected = 'evidence/pon-w1-qrom-formal-bridge-20261107/' + name + '.json'
    run('compare-' + name, ['/usr/bin/cmp', expected, str(closure / (name + '.json'))])
after = source()
write('source-after.json', after)
if before != after:
    raise RuntimeError('source changed during fixed-source validation')
impl = json.loads((implementation / 'named-tests.json').read_bytes())
cl = json.loads((closure / 'named-controls.json').read_bytes())
summary = {
    'scope': 'fresh bounded local controls on retained dirty patch; no hosted CI or clean-source native qualification',
    'source_unchanged': before == after,
    'implementation_required_tests': impl['required_tests'],
    'implementation_passed': impl['all_named_controls_passed'],
    'closure_required_tests': cl['required_tests'],
    'closure_successes': sum(len(row['success_ids']) for row in cl['suites']),
    'lifetime_ledger_tests_within_closure': next(row['tests_run'] for row in cl['suites']
                                               if row['module'] == 'test_w1_lifetime_ledger'),
    'native_C_kernel_controls_within_closure': next(row['tests_run'] for row in cl['suites']
                                                   if row['module'] == 'test_w1_zkr_control_id_audit'),
    'exact_report_comparisons': 7,
    'new_Rust_source_compiled_or_executed': False,
    'post_quantum_soundness_qualified': False,
    'independent_cryptographic_review': False,
    'production_qualified': False,
    'consensus_admission': False,
}
write('summary.json', summary)
print(json.dumps(summary, sort_keys=True), flush=True)

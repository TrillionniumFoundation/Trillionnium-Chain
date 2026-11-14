#!/usr/bin/env python3
"""Compare the exact C0 and repaired scope gates on the six observed source forgeries.

Uses actual generated mapping reports and the existing isolated workflow harness.
Supplemental completion fixtures are inert named cases; this is a gate negative
control, not execution of the real supplemental suites or a security qualification.
"""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path('/workspace/scratch/d4d2da8133e2/chain-pq-closure')
OUT = Path(__file__).resolve().parent
C0 = '8add285b6c0a91d8b7812efe2d02c9342f74c91b'
WORKFLOW = '.github/workflows/pon-w1-qrom-implementation.yml'
sys.path.insert(0, str(ROOT / 'scripts/ci'))
from test_w1_qrom_workflow_gate import WorkflowGateTests, embedded_python


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def baseline(reports):
    pass


def forged_historical_blob_oid(reports):
    reports['historical-source.json']['project_files'][0]['git_blob_oid'] = '0' * 40


def forged_historical_regular_mode(reports):
    row = reports['historical-source.json']['project_files'][0]
    row['git_mode'] = '100755' if row['git_mode'] == '100644' else '100644'


def mutually_forged_historical_source(reports):
    for row in (reports['historical-source.json']['project_files'][0],
                reports['implementation.json']['project_files'][0]):
        row.update(path='unreviewed-source.rs', bytes=1, sha256='0' * 64)


def forged_current_revision(reports):
    reports['implementation-current.json']['source_base_commit'] = '0' * 40


def forged_current_contract(reports):
    reports['implementation-current.json']['contract_sha256'] = '0' * 64


def forged_current_closure_and_count(reports):
    closure = reports['implementation-current.json']['local_path_closure']
    closure['files'] = [{'path': 'unreviewed-source.rs', 'bytes': 1, 'sha256': '0' * 64}]
    closure['source_files_checked'] = 1


def main():
    before = subprocess.check_output(['git', '--no-replace-objects', 'show', C0 + ':' + WORKFLOW],
                                     cwd=ROOT, timeout=15)
    after = (ROOT / WORKFLOW).read_bytes()
    sources = {'before-c0': before, 'after-repair': after}
    mutations = (baseline, forged_historical_blob_oid, forged_historical_regular_mode,
                 mutually_forged_historical_source, forged_current_revision,
                 forged_current_contract, forged_current_closure_and_count)
    WorkflowGateTests.setUpClass()
    case = WorkflowGateTests()
    case.setUp()
    results = []
    try:
        for phase, workflow in sources.items():
            (OUT / (phase + '-workflow.yml')).write_bytes(workflow)
            gate = embedded_python(workflow.decode(), 'report_scopes')
            (OUT / (phase + '-report-scopes.py')).write_text(gate)
            case.codes['report_scopes'] = gate
            for mutation in mutations:
                reports = deepcopy(case.reports)
                mutation(reports)
                root, out = case.workspace(reports)
                code, stdout, stderr = case.execute('report_scopes', root, out)
                name = phase + '-' + mutation.__name__
                (OUT / (name + '.stdout.log')).write_text(stdout)
                (OUT / (name + '.stderr.log')).write_text(stderr)
                results.append({'phase': phase, 'mutation': mutation.__name__,
                                'exit_code': code, 'accepted': code == 0,
                                'workflow_sha256': digest(workflow),
                                'gate_sha256': digest(gate.encode()),
                                'stdout_file': name + '.stdout.log',
                                'stderr_file': name + '.stderr.log'})
    finally:
        case.doCleanups()
    bindings = [
        'scripts/ci/test_w1_qrom_workflow_gate.py',
        'scripts/ci/w1_qrom_supplemental_controls.py',
        'config/pon/w1-qrom-supplemental-tests-v1.json',
        'scripts/w1_qrom_historical_fixture.py',
        'scripts/w1_qrom_current_implementation_audit.py',
        'scripts/w1_qrom_implementation_audit.py',
    ]
    report = {
        'schema': 'TRNM-W1-QROM-SCOPE-GATE-ADVERSARIAL-COMPARISON1',
        'scope': __doc__.strip(), 'old_gate_commit': C0,
        'harness_sha256': digest(Path(__file__).read_bytes()),
        'source_bindings': {name: digest((ROOT / name).read_bytes()) for name in bindings},
        'observations': results,
        'all_expected_outcomes_observed': all(
            row['accepted'] == (row['phase'] == 'before-c0' or row['mutation'] == 'baseline')
            for row in results),
        'proof_security_qualified': False, 'quantum_security_qualified': False,
        'native_execution_performed': False, 'real_supplemental_suites_executed': False,
    }
    (OUT / 'comparison.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'comparison': str(OUT / 'comparison.json'),
                      'old_gate_commit': C0, 'harness_sha256': report['harness_sha256'],
                      'all_expected_outcomes_observed': report['all_expected_outcomes_observed'],
                      'outcomes': [{key: row[key] for key in ('phase', 'mutation', 'exit_code')}
                                   for row in results]}, sort_keys=True))
    return 0 if report['all_expected_outcomes_observed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())

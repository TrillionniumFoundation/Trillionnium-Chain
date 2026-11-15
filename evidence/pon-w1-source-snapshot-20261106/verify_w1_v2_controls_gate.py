#!/usr/bin/env python3
"""Replay actual saved v2 evidence and deterministic inconsistencies offline.

No verifier, prover, or subprocess under observation is executed.  The only
subprocess is the original Python evidence validator, for before/after results.
The original CI binary is hashed to supply the expected executable identity.

Supply --repo for this checkout and --artifact for an extracted original CI
artifact containing v2-controls/ and bin/w1-verify-v2.  --out must name a new
JSON file; original reports and artifact files are never modified.  Historical
absolute paths inside the reports remain recorded identities, not input paths.
"""
from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile


OLD_VALIDATOR = Path(__file__).resolve().with_name('w1_v2_controls_gate_baseline_validator.py')
GATE = Path('scripts/ci/w1_v2_controls_gate.py')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_json(path):
    return json.loads(path.read_bytes())


def load_gate(repo):
    path = repo / GATE
    spec = importlib.util.spec_from_file_location('independent_w1_v2_gate', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Editor:
    """Synchronize report copies so semantic guards, not missing files, are tested."""
    def __init__(self, root):
        self.root = root
        self.originals = {}
        self.report = read_json(root / 'result.json')

    def write(self, relative, data):
        path = self.root / relative
        if relative not in self.originals:
            self.originals[relative] = path.read_bytes()
        path.write_bytes(data)

    def json(self, relative, value):
        self.write(relative, (json.dumps(value, indent=2, sort_keys=True) + '\n').encode())

    def row(self, index, modify, *, sync_declaration=False):
        row = self.report['controls'][index]
        modify(row)
        case = row['case_directory']
        self.json(Path('result.json'), self.report)
        self.json(Path(case) / 'result.json', row)
        self.json(Path(case) / 'process/result.json', row['process'])
        if sync_declaration:
            path = Path(case) / 'process/declaration.json'
            declared = read_json(self.root / path)
            for key in declared:
                if key in row['process']:
                    declared[key] = row['process'][key]
            self.json(path, declared)

    def restore(self):
        for relative, data in self.originals.items():
            (self.root / relative).write_bytes(data)


def nested(index, key, value, **options):
    def modify(editor):
        editor.row(index, lambda row: row['process'].__setitem__(key, value), **options)
    return modify


def flag(key, value):
    return lambda editor: editor.row(1, lambda row: row.__setitem__(key, value))


def tamper_identity(editor):
    value = read_json(editor.root / 'identity.json')
    value['verifier_sha256'] = '0' * 64
    editor.json(Path('identity.json'), value)


def tamper_mutation(editor):
    case = editor.report['controls'][1]['case_directory']
    path = Path(case) / 'mutation.json'
    value = read_json(editor.root / path)
    value['assets']['receipt']['sha256'] = '0' * 64
    editor.json(path, value)


def tamper_stderr(editor):
    index = 1
    case = editor.report['controls'][index]['case_directory']
    replacement = b'Error: rejection without the claimed W1 layer marker\n'
    editor.write(Path(case) / 'process/stderr.log', replacement)
    editor.row(index, lambda row: row['process'].__setitem__('stderr_sha256', digest(replacement)))


def tamper_positive_stdout(editor):
    case = editor.report['controls'][0]['case_directory']
    path = Path(case) / 'process/stdout.log'
    value = read_json(editor.root / path)
    value['work_id'] = '0' * 64
    replacement = (json.dumps(value) + '\n').encode()
    editor.write(path, replacement)
    editor.row(0, lambda row: row['process'].__setitem__('stdout_sha256', digest(replacement)))


def present_group(editor):
    index = 1
    value = copy.deepcopy(editor.report['controls'][index]['process']['final_known_group_probes'])
    value[0]['state'] = 'PRESENT'
    editor.row(index, lambda row: row['process'].__setitem__('final_known_group_probes', value))


def omit_child_group(editor):
    def modify(row):
        process = row['process']
        unrelated = process['pid'] + 1000000
        process['known_owned_groups'] = [unrelated]
        process['final_known_group_probes'] = [{'group': unrelated, 'state': 'ABSENT'}]
    editor.row(1, modify)


def benign_disappearance(editor):
    pid = editor.report['controls'][1]['process']['pid']
    value = [{
        'phase': 'final', 'operation': 'read_proc_member',
        'path': f'/proc/{pid}', 'type': 'FileNotFoundError', 'errno': 2,
        'message': 'deterministic ENOENT disappearance control',
    }]
    editor.row(1, lambda row: row['process'].__setitem__('proc_disappearance_races', value))


def run_new(gate, root, proof, *, verifier_path, verifier_sha256, recorded_out):
    try:
        gate.validate(root, proof, verifier_path=verifier_path,
                      verifier_sha256=verifier_sha256, recorded_out=recorded_out)
    except (ValueError, KeyError, TypeError, OSError, AssertionError) as error:
        return {'status': 'REFUSED', 'error_type': type(error).__name__, 'error': str(error)}
    return {'status': 'ACCEPTED'}


def run_old(root, proof, binary, repo):
    result = subprocess.run([sys.executable, str(OLD_VALIDATOR), str(root), str(proof), str(binary)],
                            cwd=repo, text=True, capture_output=True)
    return {'status': 'ACCEPTED' if result.returncode == 0 else 'REFUSED',
            'returncode': result.returncode, 'stdout': result.stdout.strip(),
            'stderr': result.stderr.strip()}


def recorded_root(report):
    return Path(report['controls'][0]['process']['command'][1]).parent.parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True, help='repository checkout to validate')
    parser.add_argument('--artifact', type=Path, required=True,
                        help='extracted original CI artifact containing v2-controls/ and bin/w1-verify-v2')
    parser.add_argument('--out', type=Path, required=True, help='new JSON result path; never overwrites')
    args = parser.parse_args()
    args.repo = args.repo.resolve(strict=True)
    args.artifact = args.artifact.resolve(strict=True)
    if args.out.exists():
        parser.error('--out already exists; preserve prior observations and select a new path')
    gate = load_gate(args.repo)
    proof = args.repo / 'evidence/pon-w1-full-v2-20261105'
    binary = args.artifact / 'bin/w1-verify-v2'
    verifier_sha256 = digest(binary.read_bytes())
    original_report = read_json(args.artifact / 'v2-controls/result.json')
    identity = read_json(args.artifact / 'v2-controls/identity.json')
    assert verifier_sha256 == identity['verifier_sha256'] == original_report['verifier_sha256']
    kwargs = {
        'verifier_path': Path(identity['verifier_path']),
        'verifier_sha256': verifier_sha256,
        'recorded_out': recorded_root(original_report),
    }
    results = {
        'purpose': 'Evidence-consistency replay of actual retained controls. No new cryptographic verification, proof generation, or qualification.',
        'generated_at_utc': datetime.now(timezone.utc).isoformat(),
        'gate_sha256': digest((args.repo / GATE).read_bytes()),
        'old_validator_sha256': digest(OLD_VALIDATOR.read_bytes()),
        'ci_report_sha256': digest((args.artifact / 'v2-controls/result.json').read_bytes()),
        'actual_ci_binary_sha256': verifier_sha256,
        'expectation_correction': 'An initial exploratory run expected sample_log_truncated to be refused. Source review confirmed it describes resource sampling only, not verifier-output scan completeness or final session observation. That initial result is preserved separately; truncated resource samples are intentionally accepted without a resource-completeness claim.',
        'cases': [],
    }
    cases = [
        ('unchanged_actual_ci_artifact', None, 'ACCEPTED'),
        ('negative_nested_returncode_zero', nested(1, 'returncode', 0), 'REFUSED'),
        ('positive_nested_returncode_nonzero', nested(0, 'returncode', 1), 'REFUSED'),
        ('positive_nested_returncode_bool_false', nested(0, 'returncode', False), 'REFUSED'),
        ('nested_timeout_true', nested(1, 'timed_out', True), 'REFUSED'),
        ('stderr_scan_truncated', flag('stderr_scan_truncated', True), 'REFUSED'),
        ('stdout_scan_truncated', flag('stdout_scan_truncated', True), 'REFUSED'),
        ('owned_session_incomplete', nested(1, 'owned_session_observation_complete', False), 'REFUSED'),
        ('proc_scan_errors_despite_complete_flag', nested(1, 'proc_scan_errors', [{'operation': 'injected-error'}]), 'REFUSED'),
        ('group_probe_errors_despite_complete_flag', nested(1, 'group_probe_errors', [{'state': 'UNKNOWN'}]), 'REFUSED'),
        ('cleanup_errors_despite_complete_flag', nested(1, 'cleanup_errors', [{'operation': 'injected-cleanup-error'}]), 'REFUSED'),
        ('resource_sample_log_truncated_without_resource_claim', nested(1, 'sample_log_truncated', True), 'ACCEPTED'),
        ('negative_stage_process_complete_true', nested(1, 'stage_process_complete', True), 'REFUSED'),
        ('positive_stage_process_complete_false', nested(0, 'stage_process_complete', False), 'REFUSED'),
        ('final_group_present', present_group, 'REFUSED'),
        ('known_groups_exclude_child_pid', omit_child_group, 'REFUSED'),
        ('pid_boolean_false', nested(1, 'pid', False), 'REFUSED'),
        ('identity_verifier_digest_changed', tamper_identity, 'REFUSED'),
        ('mutation_asset_digest_changed', tamper_mutation, 'REFUSED'),
        ('stderr_marker_removed_and_rehashed', tamper_stderr, 'REFUSED'),
        ('positive_stdout_changed_and_rehashed', tamper_positive_stdout, 'REFUSED'),
        ('legitimate_enoent_disappearance_race', benign_disappearance, 'ACCEPTED'),
    ]
    with tempfile.TemporaryDirectory(prefix='w1-v2-independent-') as temp:
        root = Path(temp) / 'ci-controls'
        shutil.copytree(args.artifact / 'v2-controls', root)
        for name, mutate, expected in cases:
            editor = Editor(root)
            try:
                if mutate is not None:
                    mutate(editor)
                before = run_old(root, proof, binary, args.repo)
                after = run_new(gate, root, proof, **kwargs)
                results['cases'].append({
                    'name': name, 'old': before, 'new': after,
                    'expected_old': 'ACCEPTED', 'expected_new': expected,
                    'pass': before['status'] == 'ACCEPTED' and after['status'] == expected,
                })
            finally:
                editor.restore()
        retained_archive = proof / 'controls-3-repaired.tar.xz'
        with tarfile.open(retained_archive, 'r:xz') as archive:
            archive.extractall(Path(temp) / 'retained', filter='data')
        retained = Path(temp) / 'retained/controls-3-repaired'
        retained_report = read_json(retained / 'result.json')
        retained_identity = read_json(retained / 'identity.json')
        assert retained_report == read_json(proof / 'controls-result.json')
        results['retained_original'] = {
            **run_new(gate, retained, proof,
                      verifier_path=Path(retained_identity['verifier_path']),
                      verifier_sha256=retained_identity['verifier_sha256'],
                      recorded_out=recorded_root(retained_report)),
            'archive_sha256': digest(retained_archive.read_bytes()),
            'scope': 'Archived evidence identity only; historical executable is not supplied or executed.',
        }
    results['status'] = 'PASS' if (all(row['pass'] for row in results['cases'])
                                    and results['retained_original']['status'] == 'ACCEPTED') else 'FAIL'
    with args.out.open('x') as output:
        output.write(json.dumps(results, indent=2, sort_keys=True) + '\n')
    print(json.dumps({
        'status': results['status'], 'output': str(args.out),
        'gate_sha256': results['gate_sha256'],
        'actual_ci_binary_sha256': verifier_sha256,
        'cases_passed': sum(row['pass'] for row in results['cases']),
        'cases_total': len(results['cases']),
        'retained_original': results['retained_original']['status'],
        'failures': [row for row in results['cases'] if not row['pass']],
    }, indent=2))
    return 0 if results['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())

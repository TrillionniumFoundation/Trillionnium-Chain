#!/usr/bin/env python3
"""Validate this continuation's actual full regression, without repinning ML evidence."""
from __future__ import annotations
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path
from check_invariant_evidence import ROOT, load, require, safe, source_bytes
from report_module_evidence import runtime_path, python_symbols, observed_selector

TEST_FILE = 'formal/pon-nakamoto-v1/test_client_confirmation.py'
RUNNER = 'scripts/run_evaluation_qualification.py'
HISTORICAL = {'evidence/' + name + '/manifest.json' for name in
              ['pon-v1', 'pon-v3', 'pon-v4', 'pon-evaluation-bundle-v1', 'pon-contract-authority-v1']}
FLAGS = ['ordinary_hepta_entry', 'independent_accepted', 'three_improving_generations',
         'physical_power_loss', 'public_network_ready', 'production_activation']
REQUIRED = {
    'preflight', 'source-contract', 'source-rejections', 'invariant-registry',
    'native-build', 'native-suite', 'native-doctests', 'native-ignored-helper',
    'native-lints', 'native-format', 'test_reference', 'test_contracts', 'test_invariants',
    'test_evaluation', 'test_evaluation_bundle', 'test_artifacts', 'test_model_contract',
    'test_inference_receipt', 'test_bounded_process', 'test_work_backend',
    'test_strict_signature', 'test_native_execution', 'test_interop',
    'test_client_confirmation', 'accepted-block', 'native-ledger',
    'historical-v1-rejections', 'historical-v4', 'historical-v4-rejections',
    'native-client-confirmation', 'historical-evaluation-components',
    'historical-evaluation-rejections', 'responsibility-evidence',
    'work-cost-rejections', 'whitespace',
}


def validate(root=ROOT, evidence=None):
    root = Path(root).resolve()
    folder = Path(evidence or root / 'evidence/pon-client-confirmation-v1').resolve()
    manifest = load(folder / 'manifest.json')
    require(manifest['schema'] == 'pon-client-confirmation-evidence-v1', 'schema')
    require(manifest['source_clean'] is True and manifest['all_commands_passed'] is True, 'incomplete measurement')
    for flag in FLAGS:
        require(manifest[flag] is False, 'unsupported authority ' + flag)
    require('qualification.json' in manifest['files'], 'missing qualification')
    for relative, expected in manifest['files'].items():
        require(re.fullmatch('[0-9a-f]{64}', expected), 'digest shape')
        require(hashlib.sha256(safe(folder, relative).read_bytes()).hexdigest() == expected, 'changed artifact ' + relative)
    q = load(folder / 'qualification.json')
    require(q['source_commit'] == manifest['implementation_commit']
            and q['source_tree'] == manifest['implementation_tree'], 'source identity')
    require(q['source_clean'] is True and q['source_clean_after'] is True
            and q['all_commands_passed'] is True, 'dirty or failed qualification')
    require(q['workstream'] == 'client-confirmation' and q['model_experiments_rerun'] is False, 'wrong experiment scope')
    for flag in ['ordinary_hepta_entry', 'independent_accepted', 'future_window_accepted', 'production_activation']:
        require(q[flag] is False, 'qualification authority ' + flag)
    tree = subprocess.check_output(['git', 'rev-parse', q['source_commit'] + '^{tree}'], cwd=root, text=True).strip()
    require(tree == q['source_tree'], 'source tree')
    require(RUNNER in q['source_files_sha256'], 'missing measured qualification runner')
    require(set(q['historical_evidence_sha256']) == HISTORICAL, 'historical inventory')
    for relative, expected in q['historical_evidence_sha256'].items():
        require(hashlib.sha256(safe(root, relative).read_bytes()).hexdigest() == expected, 'historical evidence changed ' + relative)
    require(manifest['historical_v4_sha256'] == q['historical_evidence_sha256']['evidence/pon-v4/manifest.json'], 'historical manifest mismatch')
    originals = source_bytes(root, q['source_commit'], list(q['source_files_sha256']))
    for relative, raw in originals.items():
        require(hashlib.sha256(raw).hexdigest() == q['source_files_sha256'][relative], 'false source digest')
        require(safe(root, relative).read_bytes() == raw, 'current source differs ' + relative)
    tracked = set(subprocess.check_output(['git', 'ls-files'], cwd=root, text=True).splitlines())
    untracked = set(subprocess.check_output(['git', 'ls-files', '--others', '--exclude-standard'], cwd=root, text=True).splitlines())
    require({p for p in tracked | untracked if runtime_path(p)} == {p for p in originals if runtime_path(p)}, 'current runtime inventory')
    require(TEST_FILE in originals and 'formal/pon-nakamoto-v1/client_confirmation.py' in originals, 'missing client source')
    rows = q['results']
    require({r['name'] for r in rows} == REQUIRED and len(rows) == len(REQUIRED), 'execution matrix')
    records, native_count = [], 0
    by_name = {r['name']: r for r in rows}
    for row in rows:
        require(type(row['returncode']) is int and row['returncode'] == 0 and row['timed_out'] is False, 'failed execution')
        require(row['log'] in manifest['files'], 'unmanifested log')
        text = safe(folder, row['log']).read_text()
        require(row['vram_bytes'] is None and row['included_transactions'] is None
                and row['client_confirmed_transactions'] is None, 'unmeasured network metric')
        if row['name'].startswith('test_') or row['name'] in {'native-ledger', 'native-client-confirmation', 'accepted-block', 'source-rejections', 'invariant-registry', 'historical-v1-rejections', 'historical-v4-rejections', 'historical-evaluation-rejections', 'responsibility-evidence', 'work-cost-rejections'}:
            require('python_tests' in row, 'missing executed Python summary ' + row['name'])
        if row['name'].startswith('test_'):
            require(row['command'] == ['python3', 'formal/pon-nakamoto-v1/' + row['name'] + '.py'], 'wrong Python invocation ' + row['name'])
        if 'python_tests' in row:
            require(type(row['python_tests']) is int and row['python_tests'] > 0, 'test counter')
            require(re.search(r'(?m)^Ran ' + str(row['python_tests']) + r' tests?\b', text)
                    and re.search(r'(?m)^OK\s*$', text), 'Python log result')
        if row['name'] in {'native-suite', 'native-doctests', 'native-ignored-helper'}:
            require(row['command'][:2] == ['cargo', 'test'] and '--locked' in row['command'], 'native invocation')
            counts = []
            for part in re.split(r'(?m)^\s*(?:Running (?:unittests|tests/)|Doc-tests )', text):
                found = re.findall(r'test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored', part)
                if found:
                    counts.append(found[-1])
            require(counts and all(c[0] == 'ok' and int(c[2]) == 0 for c in counts), 'native failures')
            require(type(row['native_passed']) is int and sum(int(c[1]) for c in counts) == row['native_passed'], 'native result count')
            if row['name'] == 'native-suite':
                require({'--workspace', '--all-targets', '--all-features'} <= set(row['command']), 'incomplete native suite')
                native_count = row['native_passed']
        records.append(dict(row, _log_text=text))
    selectors = [TEST_FILE + '::' + name for name in python_symbols(originals[TEST_FILE].decode())
                 if name.startswith('VerifiedHistoryTests.test_')]
    require(selectors, 'missing client assertions')
    for name in ['test_client_confirmation', 'native-client-confirmation']:
        row = by_name[name]
        require(row['command'] == ['python3', TEST_FILE], 'client invocation')
        exact = [r for r in records if r['name'] == name]
        require(all(observed_selector(s, exact) for s in selectors), 'unobserved client selector')
    build = by_name['native-build']['command']
    require(build[:2] == ['cargo', 'build'] and {'--offline', '--locked', '--release', '--examples'} <= set(build), 'native build invocation')
    require({'trnm-protocol', 'trnm-crypto-primitives', 'trnm-mvcc-fee', 'trnm-transport'} <= set(build), 'native build scope')
    overrides = by_name['native-client-confirmation']['environment_overrides']
    require(overrides.get('TRNM_EXECUTION_WORKERS') == '8'
            and overrides.get('TRNM_NATIVE_WORK', '').endswith('/release/examples/pon_work_io')
            and overrides.get('TRNM_NATIVE_EXECUTOR', '').endswith('/release/examples/pon_execute'), 'missing actual native client selection')
    for binary in ['pon_work_io', 'pon_execute']:
        require(re.fullmatch('[0-9a-f]{64}', q['native_binary_sha256'][binary]), 'native binary digest')
    require(q['environment']['cargo_locked'] is True and q['environment']['cargo_offline'] is True
            and q['environment']['physical_power_loss'] is False, 'environment scope')
    return {'measured_commit': q['source_commit'], 'runtime_matches': True,
            'native_tests': native_count, 'client_selectors_per_backend': len(selectors),
            'backends': ['reference', 'explicit-native-work-and-eight-worker-execution'],
            'model_experiments_rerun': False, 'public_confirmed_tps': None,
            'native_full_node': False, 'independent_accepted': False, 'production_activation': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence')
    args = parser.parse_args()
    print(json.dumps(validate(evidence=args.evidence), sort_keys=True))

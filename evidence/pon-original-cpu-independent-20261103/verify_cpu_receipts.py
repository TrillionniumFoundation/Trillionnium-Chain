#!/usr/bin/env python3
"""Read-only qualification of the retained, exact GitHub CPU artifacts.

No archive member or repository source is executed. No budget is recalculated
or relaxed. Full runtime, fixed Host and pressure qualification are separate.
"""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import zipfile

if sys.flags.optimize:
    raise SystemExit('verification requires Python assertions enabled')

HEAD = '116a3caf6046dd0db3caf1d0797e636c35c877b8'
TREE = 'e07dee8cad7727845063ced35933c9408341945d'
OLD = '0443a5e2e68be9c5df68b87ebeb5fed3b96ec5d2'
MERGE = '4f10f1858ca9dbf6fdfb55e2abce569bca21acbe'
CPU = [
    'store::detached_admission::tests::admitted_custom_genesis_over_eight_mib_keeps_original_held_schedule_and_cpu_owner',
    'store::detached_admission::tests::authenticated_large_parent_original_schedule_supplementary_denominator',
]
EXITS = [
    'ingress::public_v2::tests::public_loop_exit_records_lifetime_before_internal_stop',
    'ingress::public_v2::tests::public_loop_exit_records_external_stop_after_signed_read',
]

def sha(data):
    return hashlib.sha256(data).hexdigest()

def unique(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError('duplicate JSON key: ' + key)
        out[key] = value
    return out

def parsed(raw):
    return json.loads(raw, object_pairs_hook=unique)

def table(raw):
    return list(csv.DictReader(io.StringIO(raw.decode()), delimiter='\t'))

def decoded_archive(path):
    with zipfile.ZipFile(path) as archive:
        rows = archive.infolist()
        assert len({r.filename for r in rows}) == len(rows)
        assert sum(r.file_size for r in rows) <= 32 * 1024 * 1024
        assert all(r.file_size <= 8 * 1024 * 1024 for r in rows)
        return {r.filename: archive.read(r) for r in rows}

def native_result(data, path, selector):
    receipt = parsed(data[path + '.execution.json'])
    assert receipt['result'] == 'PASS' and receipt['executed_tests'] == 1
    assert receipt['test'] == selector
    log = data[path + '.log'].decode()
    result = re.findall(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out; finished in ([0-9.]+)s', log)
    assert len(result) == 1 and result[0][:4] == ('1', '0', '0', '0')
    assert re.search(r'\btest ' + re.escape(selector) + r' \.\.\.', log)
    return {'execution': receipt, 'result_line': result[0], 'log_sha256': sha(data[path + '.log'])}

def records(log):
    out = []
    for line in log.decode().splitlines():
        pos = line.find('{')
        if pos < 0:
            continue
        try:
            value = parsed(line[pos:])
        except ValueError:
            continue
        if isinstance(value, dict) and value.get('schema') in (
            'native-large-parent-original-dispatch-diagnostic-v1',
            'native-large-parent-schedule-parity-v1',
        ):
            out.append(value)
    return out

def verify_one(directory, row):
    path = directory / (str(row['id']) + '.zip')
    raw = path.read_bytes()
    assert len(raw) == row['zip_bytes'] and sha(raw) == row['zip_sha256']
    data = decoded_archive(path)
    source = parsed(data['source-before.json'])
    assert source == parsed(data['source-after.json'])
    assert source['candidate'] == HEAD and source['tested_tree'] == TREE
    assert source['tracked_worktree_verified'] is True
    assert source['kind'] in ('head', 'prospective-merge')
    assert source['tested_commit'] == (HEAD if source['kind'] == 'head' else MERGE)
    assert data['rustc.txt'].decode().splitlines()[0].startswith('rustc 1.95.0 ')
    assert data['cargo.txt'].decode().splitlines()[0].startswith('cargo 1.95.0 ')
    workspace = 'workspace-test-cpu' in row['name']
    arm = '-arm-' in row['name']
    assert ('aarch64' if arm else 'x86_64') in data['host.txt'].decode()
    build = parsed(data['build-command.json'])
    expected = ['cargo', '+1.95.0', 'test']
    if not workspace:
        expected += ['--release']
    expected += ['--locked', '--manifest-path', 'trillionnium/Cargo.toml']
    expected += ['--workspace', '--all-targets', '--all-features'] if workspace else ['-p', 'trnm-pon-node', '--lib']
    expected += ['--no-run', '--message-format=json']
    assert build['argv'] == expected
    environment = build['environment']
    for key in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'RUSTC', 'CARGO_BUILD_RUSTFLAGS', 'CARGO_BUILD_TARGET'):
        assert environment.get(key) is None
    assert not any(key.startswith('CARGO_PROFILE_') for key in environment)
    assert environment['CARGO_INCREMENTAL'] == '0' and environment['RUST_TEST_THREADS'] == '1'
    binary = parsed(data['binary.json'])
    assert data['binary.sha256'].decode().split()[0] == binary['sha256']
    profile = binary['artifact']['profile']
    assert profile['opt_level'] == '3' and profile['test'] is True
    assert profile['debug_assertions'] is workspace and profile['overflow_checks'] is workspace
    assert binary['artifact']['features'] == (['default', 'pq-native-openssl'] if workspace else ['default'])
    if workspace:
        assert data['binary.sha256'] == data['binary-before.sha256'] == data['binary-after.sha256']
        assert data['m06-binary.sha256'] == data['m06-binary-after.sha256'] == data['semantic-controls/m06-binary-before.sha256']
        assert data['binary.sha256'] == data['semantic-controls/node-binary-before.sha256']
    exits = table(data['test-exits.tsv'])
    assert [r['selector'] for r in exits] == CPU + EXITS
    assert all(r[key] == '0' for r in exits for key in ('native_exit', 'log_exit', 'reader_exit'))
    tests = []
    for selector in CPU + EXITS:
        stem = selector.rsplit('::', 1)[1]
        result = native_result(data, stem, selector)
        result['selector'] = selector
        if selector in CPU:
            result['original_records'] = records(data[stem + '.log'])
            parity = [r for r in result['original_records'] if r['schema'] == 'native-large-parent-schedule-parity-v1']
            assert len(parity) == (2 if selector == CPU[0] else 1)
            assert [r['authenticated_backend'] for r in parity] == ([False, True] if selector == CPU[0] else [True])
            for record in parity:
                assert record['native_result'] == {'Ok': 'ok'}
                assert record['complete_key_utf8_and_canonical_value_bytes'] == 8625548
                assert record['host_qualified'] is False and record['all_honest_service_qualified'] is False
                cpu = record['original_cpu_receipt']
                assert cpu['accounting_unavailable'] is False and cpu['live_refused'] is False
                assert cpu['spawned_workers'] == cpu['started_workers'] == cpu['known_workers'] == cpu['finished_workers'] == 2
                assert cpu['total_cpu_ns'] == cpu['owner_cpu_ns'] + cpu['scoped_worker_cpu_ns'] > 0
        tests.append(result)
    semantic = []
    registry = None
    if workspace:
        registry = parsed(data['semantic-controls/registry-check.json'])
        selected = list(csv.DictReader(
            io.StringIO(data['semantic-controls/selected-tests.tsv'].decode()),
            fieldnames=('crate', 'group', 'selector'), delimiter='\t'))
        outcomes = table(data['semantic-controls/test-exits.tsv'])
        assert registry['result'] == 'PASS' and registry['selected_count'] == 45
        assert len(selected) == len(outcomes) == 45
        assert len({r['selector'] for r in selected}) == 45
        assert [r['selector'] for r in outcomes] == [r['selector'] for r in selected]
        assert data['semantic-controls/executed-selector-count.txt'].strip() == b'45'
        assert all(r[key] == '0' for r in outcomes for key in ('native_exit', 'log_exit', 'reader_exit'))
        for index, item in enumerate(selected, 1):
            stem = f"semantic-controls/{index:02d}-{item['crate']}-{item['selector'].rsplit('::', 1)[1]}"
            result = native_result(data, stem, item['selector'])
            result.update(item)
            semantic.append(result)
    keep = ['source-before.json', 'source-after.json', 'build-command.json', 'binary.json', 'binary.sha256', 'test-exits.tsv', 'rustc.txt', 'cargo.txt', 'host.txt']
    if workspace:
        keep += ['binary-before.sha256', 'binary-after.sha256', 'm06-binary.json', 'm06-binary.sha256', 'm06-binary-after.sha256', 'semantic-controls/registry-check.json', 'semantic-controls/selected-tests.tsv', 'semantic-controls/test-exits.tsv']
    return {'artifact': {k: row[k] for k in ('id', 'name', 'zip_sha256', 'zip_bytes')},
            'profile': 'original-workspace-test' if workspace else 'original-release',
            'architecture': 'aarch64' if arm else 'x86_64', 'source': source,
            'binary_sha256': binary['sha256'], 'original_tests': tests,
            'semantic_control_count': len(semantic), 'semantic_controls': semantic,
            'raw_small_members': {name: data[name].decode() for name in keep},
            'all_member_hashes': {name: {'bytes': len(value), 'sha256': sha(value)} for name, value in data.items()},
            'scope': 'Named CPU and reactor-exit tests; selected semantic controls. No complete native runtime or fixed-Host/pressure qualification.'}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--artifact-dir', type=Path, required=True)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    inputs = parsed((args.artifact_dir / 'DOWNLOADS_VERIFIED.json').read_bytes())
    assert len(inputs) == 8 and len({r['id'] for r in inputs}) == 8
    rows = []
    for row in inputs:
        result = verify_one(args.artifact_dir, row)
        path = args.output / (str(row['id']) + '.json')
        path.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
        rows.append({'id': row['id'], 'profile': result['profile'], 'architecture': result['architecture'], 'source_kind': result['source']['kind'], 'original_tests_passed': len(result['original_tests']), 'semantic_controls_passed': len(result['semantic_controls']), 'proof_sha256': sha(path.read_bytes())})
    assert len({(r['profile'], r['architecture'], r['source_kind']) for r in rows}) == 8
    def source(ref, path):
        return subprocess.check_output(['git', 'show', ref + ':' + path], cwd=args.repo)
    unchanged = {}
    for path in ['trillionnium/Cargo.toml', 'trillionnium/Cargo.lock', '.github/workflows/pon-original-large-state-cpu.yml', '.github/workflows/pon-original-workspace-large-state-cpu.yml', 'scripts/ci/check_required_native_test.py', 'scripts/ci/verify_ci_source.py']:
        a, b = source(OLD, path), source(HEAD, path)
        assert a == b
        unchanged[path] = sha(a)
    path = 'trillionnium/crates/trnm-pon-node/src/store/detached_admission/tests.rs'
    a, b = source(OLD, path).decode(), source(HEAD, path).decode()
    pattern = r'(?ms)^fn assert_custom_genesis_held_schedule_and_cpu_owner\(authenticated: bool\) \{.*?^\}'
    a, b = re.search(pattern, a).group(), re.search(pattern, b).group()
    prefix = '    let cpu_budget_after = original.observe().ok();'
    suffix = '    let result = attempt.unwrap();'
    assert a[:a.index(prefix)] == b[:b.index(prefix)]
    assert a[a.index(suffix):] == b[b.index(suffix):]
    summary = {'schema': 'chain-original-cpu-independent-readback-v1', 'candidate': HEAD, 'tree': TREE, 'prospective_merge': MERGE, 'cells': rows, 'unchanged_original_inputs_from_failed_0443': unchanged, 'original_setup_dispatch_and_budget_prefix_sha256': sha(b[:b.index(prefix)].encode()), 'original_strict_unwrap_settlement_and_reopen_suffix_sha256': sha(b[b.index(suffix):].encode()), 'intervening_test_delta': 'additional diagnostic-only readback when native settlement refuses; original budget, operation and strict acceptance remain unchanged', 'original_distinct_native_selectors': len(CPU + EXITS), 'original_native_selector_executions_passed': sum(r['original_tests_passed'] for r in rows), 'semantic_control_executions_passed': sum(r['semantic_controls_passed'] for r in rows), 'all_verified': True, 'fixed_host_qualified': False, 'four_second_sixteen_hostile_qualified': False, 'thirty_second_campaign_qualified': False, 'full_workspace_native_suite_qualified': False}
    (args.output / 'VERIFIED.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n')
    print(json.dumps(summary, indent=2))

if __name__ == '__main__':
    main()

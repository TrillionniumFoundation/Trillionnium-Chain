#!/usr/bin/env python3
"""Freeze terminal local Submit-recovery evidence without running native code.

Run only after root supplies the terminal handoff. All recorded invocation
directories must have terminal result/source-after records and exact stream
hashes. The output stores each distinct original byte sequence once, by SHA-256.
"""
from __future__ import annotations
import argparse
import base64
import datetime
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import stat
import subprocess

ROOT = Path('/workspace/scratch/b5a148b09b11/chain-six-axis')
VAL = ROOT.parent / 'next-validation'
PUB = VAL / 'hosted-evidence-publication'
BASE = 'b4bdf142f513081715ecc8d1f9674291e85302cc'
C1 = 'c5dd7c7718925b951dc6e4d5ccc5a86ccfa8e3c1'
PROD = 'trillionnium/crates/trnm-pon-node/src/public_submit.rs'
FIXTURE = 'trillionnium/crates/trnm-pon-node/tests/public_submit_recovery.rs'
PROD_SHA = '90f748bd5c7f6046e0d5340b4f36c70de7f030b4432ad4ec3674d7e2d020eb6c'
FIXTURE_SHA = '62df5e98a5a8f793b319f5232d3cae3b7e2b59a3ed459bc30658fd93f631fcb3'
FINAL_SOURCE_SHA = 'aab2fa9de01f64a8739fbf941287d06c80a0ec2e16719845aaf5717e4f14b9df'
TERMINAL_SHA = '200dc213e4a9bd6039314b6b56151dbf7fa9411b03de9e8c86388f4bbe09cd08'
SUMMARY = re.compile(r'^test result: (ok|FAILED)\. ([0-9]+) passed; ([0-9]+) failed; ([0-9]+) ignored; ([0-9]+) measured; ([0-9]+) filtered out; finished in ([0-9]+(?:\.[0-9]+)?)s$', re.M)
CASE = re.compile(r'^test ([a-zA-Z0-9_:]+) \.\.\. (ok|FAILED|ignored)(?: .*)?$', re.M)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def encoded(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode()

def stable_read(path):
    a = path.stat(follow_symlinks=False)
    assert stat.S_ISREG(a.st_mode), path
    assert a.st_size <= 64 * 1024 * 1024, ('unexpected large evidence file', path)
    raw = path.read_bytes()
    b = path.stat(follow_symlinks=False)
    assert (a.st_dev, a.st_ino, a.st_size, a.st_mtime_ns, a.st_ctime_ns) == (b.st_dev, b.st_ino, b.st_size, b.st_mtime_ns, b.st_ctime_ns)
    assert len(raw) == a.st_size
    return raw

def directory_bytes(path):
    return {p.relative_to(path).as_posix(): stable_read(p) for p in sorted(path.rglob('*')) if p.is_file()}

def json_bytes(data, path):
    return json.loads(data[path])

def summary(text):
    found = SUMMARY.findall(text)
    assert len(found) <= 1
    if not found:
        return None
    status, passed, failed, ignored, measured, filtered, seconds = found[0]
    return dict(status=status, passed=int(passed), failed=int(failed), ignored=int(ignored), measured=int(measured), filtered_out=int(filtered), elapsed_seconds=seconds)

def check_embedded_records(data):
    verified = []
    for path, raw in data.items():
        if not path.endswith('.json.gz'):
            continue
        obj = json.loads(gzip.decompress(raw))
        count = 0
        for r in obj.get('records', []):
            if 'text' in r:
                b = r['text'].encode('utf-8')
                assert len(b) == r['bytes'] and sha(b) == r['sha256'], (path, r.get('path'))
                count += 1
        if 'entries' in obj and 'blobs' in obj:
            for r in obj['entries']:
                blob = obj['blobs'][r['blob']]
                b = base64.b64decode(blob['data'], validate=True)
                assert len(b) == blob['bytes'] == r['bytes'] and sha(b) == r['sha256'] == r['blob']
                count += 1
        verified.append(dict(file=path, verified_inner_records=count))
    return verified

def git(*argv):
    return subprocess.run(['git', *argv], cwd=ROOT, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout

def base_source_hashes(names):
    """Read the exact base Git blobs without changing index, worktree or refs."""
    names = sorted(names)
    assert all('\n' not in name for name in names)
    requests = ''.join(BASE + ':' + name + '\n' for name in names).encode()
    result = subprocess.run(['git', 'cat-file', '--batch'], cwd=ROOT, input=requests, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stream = io.BytesIO(result.stdout)
    hashes = {}
    for name in names:
        header = stream.readline().decode().rstrip('\n').split(' ')
        assert len(header) == 3 and header[1] == 'blob', ('base source blob missing', name, header)
        raw = stream.read(int(header[2]))
        assert len(raw) == int(header[2]) and stream.read(1) == b'\n'
        hashes[name] = sha(raw)
    assert not stream.read()
    return hashes

def executable_receipts(value):
    found = []
    if isinstance(value, dict):
        if {'path', 'bytes', 'sha256'} <= set(value) and isinstance(value['path'], str):
            found.append(value)
        else:
            for child in value.values():
                found.extend(executable_receipts(child))
    elif isinstance(value, list):
        for child in value:
            found.extend(executable_receipts(child))
    return found

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--terminal-handoff', type=Path, required=True)
    args = ap.parse_args()
    handoff_raw = stable_read(args.terminal_handoff)
    assert args.terminal_handoff.name == 'terminal-summary-v2.json' and sha(handoff_raw) == TERMINAL_SHA
    terminal = json.loads(handoff_raw)
    assert terminal['base_commit'] == BASE and terminal['all_scoped_final_gates_pass'] is True
    assert all(terminal[k] is False for k in ['whole_node_974_executed', 'whole_workspace_executed', 'new_source_hosted_qualified', 'performance_or_all_blocker_closure'])
    preflight = subprocess.run(['bash', 'scripts/project-preflight.sh'], cwd=ROOT, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    directories = {
        'native': VAL / 'public-submit-fixture-repair',
        'fixture-review': VAL / 'c1-runtime-liveness-static-review',
        'remote-boundary-review': VAL / 'public-submit-remote-boundary-review',
    }
    data = {}
    raw_parts = {}
    for prefix, directory in directories.items():
        original = directory_bytes(directory)
        assert original
        raw_parts[prefix] = original
        data.update({prefix + '/' + p: b for p, b in original.items()})
    native = raw_parts['native']
    assert 'native-source.final.json' in native, 'root final source manifest must exist before freeze'
    stage_names = sorted({p.rsplit('/', 1)[0] for p in native if p.endswith('/invocation.json')})
    assert {'baseline-v1', 'corrected-v1', 'corrected-v2', 'fmt-v1', 'clippy-v1', 'source-negative-v1', 'source-negative-v2', 'error-boundaries-v1', 'eof-boundary-v1', 'registry-v1'} == set(stage_names)
    stages = []
    for name in stage_names:
        prefix = name + '/'
        assert all(prefix + p in native for p in ['invocation.json', 'result.json', 'source-before.json', 'source-after.json', 'stdout', 'stderr']), ('stage has no terminal complete record', name)
        invocation = json_bytes(native, prefix + 'invocation.json')
        assert invocation['head'] == BASE
        result = json_bytes(native, prefix + 'result.json')
        before = json_bytes(native, prefix + 'source-before.json')
        after = json_bytes(native, prefix + 'source-after.json')
        assert before == after and result['source_unchanged'] is True
        assert len(before) == 1342
        for stream in ['stdout', 'stderr']:
            b = native[prefix + stream]
            assert len(b) == result[stream + '_bytes'] and sha(b) == result[stream + '_sha256']
        text = native[prefix + 'stdout'].decode('utf-8')
        err = native[prefix + 'stderr'].decode('utf-8')
        profiles = []
        for line in text.splitlines():
            if not line.startswith('{'):
                continue
            row = json.loads(line)
            if row.get('reason') == 'compiler-artifact' and any('/' + p + '#' in row.get('package_id', '') for p in ['trnm-pon-node', 'trnm-mvcc-fee']):
                profiles.append({k: row[k] for k in ['package_id', 'target', 'profile', 'features', 'executable', 'fresh']})
        cases = [dict(name=n, result=r) for n, r in CASE.findall(text)]
        stages.append(dict(name=name, invocation=invocation, result=result, native_summary=summary(text), observed_completed_harness_cases=cases, stdout_sha256=sha(native[prefix + 'stdout']), stderr_sha256=sha(native[prefix + 'stderr']), source_path_count=len(before), source_before_after_equal=True, source_before_sha256=sha(native[prefix + 'source-before.json']), source_after_sha256=sha(native[prefix + 'source-after.json']), production_sha256=before[PROD], fixture_sha256=before[FIXTURE], actual_compiler_profile_rows=profiles, sigabrt_observed='signal: 6, SIGABRT' in err))
    by_name = {s['name']: s for s in stages}
    baseline = by_name['baseline-v1']
    assert baseline['result']['returncode'] == 101 and baseline['native_summary'] is None and baseline['sigabrt_observed']
    assert baseline['production_sha256'] == sha(git('show', BASE + ':' + PROD)) == sha(git('show', C1 + ':' + PROD))
    assert baseline['fixture_sha256'] == sha(git('show', BASE + ':' + FIXTURE)) == sha(git('show', C1 + ':' + FIXTURE))
    v1, v2 = by_name['corrected-v1'], by_name['corrected-v2']
    assert v1['result']['returncode'] == 101 and v1['native_summary'] == dict(status='FAILED', passed=21, failed=3, ignored=0, measured=0, filtered_out=0, elapsed_seconds='15.93') and not v1['sigabrt_observed']
    assert v2['result']['returncode'] == 0 and v2['native_summary'] == dict(status='ok', passed=24, failed=0, ignored=0, measured=0, filtered_out=0, elapsed_seconds='16.21')
    assert v2['production_sha256'] == PROD_SHA and v2['fixture_sha256'] == FIXTURE_SHA
    original_fixture_names = re.findall(r'#\[test\]\s*fn\s+(\w+)\s*\(', git('show', BASE + ':' + FIXTURE).decode())
    assert len(original_fixture_names) == 24
    assert {c['name'] for c in v2['observed_completed_harness_cases']} == set(original_fixture_names)
    assert len(v2['observed_completed_harness_cases']) == 24 and all(c['result'] == 'ok' for c in v2['observed_completed_harness_cases'])
    assert {c['name'] for c in v1['observed_completed_harness_cases']} == set(original_fixture_names)
    assert len(v1['observed_completed_harness_cases']) == 24 and sum(c['result'] == 'FAILED' for c in v1['observed_completed_harness_cases']) == 3
    for name in ['fmt-v1', 'clippy-v1', 'source-negative-v1', 'source-negative-v2', 'error-boundaries-v1', 'eof-boundary-v1', 'registry-v1']:
        assert by_name[name]['result']['returncode'] == 0
    error = by_name['error-boundaries-v1']
    assert error['native_summary']['passed'] == 10 and error['native_summary']['failed'] == error['native_summary']['ignored'] == error['native_summary']['measured'] == 0 and error['native_summary']['filtered_out'] == 964
    original_error_names = re.findall(r'#\[test\]\s*fn\s+(\w+)\s*\(', (ROOT / 'trillionnium/crates/trnm-pon-node/src/error.rs').read_text())
    assert {c['name'] for c in error['observed_completed_harness_cases']} == {'error::tests::' + n for n in original_error_names}
    assert len(error['observed_completed_harness_cases']) == 10 and all(c['result'] == 'ok' for c in error['observed_completed_harness_cases'])
    eof_stages = [s for s in stages if any('public_submit::tests::' in word for word in s['invocation']['command'])]
    assert len(eof_stages) == 1, 'exact typed-EOF control must be terminal before freeze'
    eof = eof_stages[0]
    assert eof['result']['returncode'] == 0 and eof['native_summary']['passed'] == 1 and eof['native_summary']['failed'] == eof['native_summary']['ignored'] == eof['native_summary']['measured'] == 0 and eof['native_summary']['filtered_out'] == 973
    assert eof['observed_completed_harness_cases'] == [dict(name='public_submit::tests::retry_requires_local_frame_eof_at_one_of_the_existing_response_stages', result='ok')]
    for s in [v1, v2, error, eof]:
        assert s['actual_compiler_profile_rows'], ('compiler profile rows missing', s['name'])
        for row in s['actual_compiler_profile_rows']:
            if row['target']['kind'] not in [['lib'], ['bin'], ['test']]:
                continue
            node = '/trnm-pon-node#' in row['package_id']
            assert row['profile']['opt_level'] == ('3' if node else '1')
            assert row['profile']['debuginfo'] == 2 and row['profile']['debug_assertions'] is True and row['profile']['overflow_checks'] is True
            assert row['features'] == ['default', 'pq-native-openssl']
    final_source = json_bytes(native, 'native-source.final.json')
    assert sha(native['native-source.final.json']) == FINAL_SOURCE_SHA and len(final_source) == 1190
    gate_source = json_bytes(native, 'corrected-v2/source-after.json')
    shared_names = set(final_source) & set(gate_source)
    assert len(shared_names) == 1148 and all(final_source[k] == gate_source[k] for k in shared_names)
    source_scope_comparison = dict(final_manifest_paths=len(final_source), run_recorded_snapshot_paths=len(gate_source), shared_paths=len(shared_names), shared_hashes_equal=True, final_only_paths=sorted(set(final_source) - set(gate_source)), run_recorded_only_paths=sorted(set(gate_source) - set(final_source)), identical_manifest_scope=False)
    for name in ['fmt-v1', 'clippy-v1', 'source-negative-v2', 'error-boundaries-v1', 'eof-boundary-v1', 'registry-v1']:
        assert json_bytes(native, name + '/source-after.json') == gate_source, ('final gate source mismatch', name)
    assert json_bytes(native, 'source-negative-v1/source-after.json') == json_bytes(native, 'corrected-v1/source-after.json')
    assert sha((ROOT / PROD).read_bytes()) == final_source[PROD] == PROD_SHA
    assert sha((ROOT / FIXTURE).read_bytes()) == final_source[FIXTURE] == FIXTURE_SHA
    for n, expected in final_source.items():
        assert sha((ROOT / n).read_bytes()) == expected, ('current final source mismatch', n)
    base_hashes = base_source_hashes(final_source)
    changed_source = {n: dict(before=base_hashes[n], after=final_source[n]) for n in final_source if base_hashes[n] != final_source[n]}
    assert set(changed_source) == {PROD, FIXTURE} and changed_source == terminal['changed_native_paths']
    for name, row in terminal['scoped_native_results'].items():
        observed = by_name[name]
        native_summary = observed['native_summary']
        assert [c['name'] for c in observed['observed_completed_harness_cases'] if c['result'] == 'ok'] == row['pass_names']
        assert all(row[key] == native_summary[key] for key in ['passed', 'failed', 'ignored', 'measured'])
        assert row['filtered'] == native_summary['filtered_out'] and str(row['native_seconds']) == native_summary['elapsed_seconds']
    registry = by_name['registry-v1']
    assert registry['native_summary'] is None and not registry['observed_completed_harness_cases']
    registry_names = [line[:-6] for line in native['registry-v1/stdout'].decode().splitlines() if line.endswith(': test')]
    assert len(registry_names) == len(set(registry_names)) == 974
    assert terminal['current_node_registry'] == dict(names=974, listed_not_executed=True, stdout_sha256=sha(native['registry-v1/stdout']))
    registry_identity = json_bytes(native, 'registry-identity.json')
    original_registry_path = Path(registry_identity['original_registry']['path'])
    original_registry_raw = stable_read(original_registry_path)
    assert sha(original_registry_raw) == registry_identity['original_registry']['sha256'] == 'c85222711cb8ef0a65c11a828d8471cfc6f7faa7bd9b9a6228f745530171e27d'
    assert json.loads(original_registry_raw)['registered'] == registry_names
    assert registry_identity['names'] == 974 and registry_identity['exact_names_and_order_match'] is True
    assert registry_identity['tests_executed_by_listing'] is False and registry_identity['full_suite_pass_inherited'] is False
    data['registry/original-frozen-plan.json'] = original_registry_raw
    registry_readback = dict(names=974, exact_original_names_and_order_match=True, tests_executed_by_listing=False, full_suite_pass_inherited=False, stdout_sha256=sha(native['registry-v1/stdout']), original_registry_sha256=sha(original_registry_raw), identity_record_sha256=sha(native['registry-identity.json']))
    correction = json_bytes(native, 'terminal-name-correction.json')
    assert sha(native['terminal-name-correction.json']) == terminal['pass_name_collector_correction']['sha256']
    assert sha(native['terminal-summary.json']) == correction['original_summary']['sha256']
    assert sha(native['finalize-scoped-validation-v1.py']) == correction['original_collector_sha256']
    assert sha(native['finalize-scoped-validation.py']) == correction['corrected_collector_sha256']
    final_executables = []
    for name, raw in native.items():
        if '/' in name or not name.endswith('.json') or not any(word in name for word in ['executable', 'elf']):
            continue
        for r in executable_receipts(json.loads(raw)):
            p = Path(r['path'])
            assert p.is_relative_to(ROOT.parent / 'target'), ('unexpected executable receipt path', p)
            before = p.stat()
            with p.open('rb') as stream:
                assert stream.read(4) == b'\x7fELF'
                stream.seek(0)
                digest = hashlib.file_digest(stream, 'sha256').hexdigest()
            after = p.stat()
            assert (before.st_size, before.st_mtime_ns, before.st_ctime_ns) == (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            assert before.st_size == r['bytes'] and digest == r['sha256']
            final_executables.append(dict(path=str(p), bytes=before.st_size, sha256=digest, root_receipt_file='native/' + name, root_receipt_sha256=sha(raw), independently_rehashed_at_packaging=True, executable_bytes_copied=False))
    assert len(final_executables) == len({r['path'] for r in final_executables}) == 3, 'three root final executable receipts must be present before freeze'
    assert registry_identity['current_binary_sha256'] == next(r['sha256'] for r in final_executables if r['path'] == registry['invocation']['command'][0])
    # Retain exact original/current production and fixture bytes and diffs.
    for source_name in [PROD, FIXTURE]:
        label = Path(source_name).name
        data['source/c1-' + label] = git('show', C1 + ':' + source_name)
        data['source/c2-' + label] = git('show', BASE + ':' + source_name)
        data['source/current-' + label] = stable_read(ROOT / source_name)
        data['source/' + label + '.patch'] = git('diff', BASE, '--', source_name)
    data['packaging/root-terminal-handoff'] = handoff_raw
    data['packaging/preflight.json'] = encoded(dict(exit_code=preflight.returncode, stdout=preflight.stdout.decode(), stderr=preflight.stderr.decode(), native_executed=False))
    report_review_path = PUB / 'submit-recovery-report-review-v2.json'
    data['packaging/submit-recovery-report-review-v2.json'] = stable_read(report_review_path)
    data['packaging/submit-recovery-final-readme-review.json'] = stable_read(PUB / 'submit-recovery-final-readme-review.json')
    python_match = re.search(r'Ran ([0-9]+) tests in ([0-9.]+)s\s+OK', native['source-negative-v2/stderr'].decode())
    assert python_match and int(python_match[1]) == 68
    inner_verified = check_embedded_records(data)
    assert sum(map(len, data.values())) < 64 * 1024 * 1024
    entries, blobs = [], {}
    for name, raw in sorted(data.items()):
        digest = sha(raw)
        entries.append(dict(path=name, bytes=len(raw), sha256=digest, blob=digest))
        if digest not in blobs:
            blobs[digest] = dict(bytes=len(raw), data=base64.b64encode(raw).decode('ascii'))
    archive = dict(schema='trnm-original-submit-recovery-local-byte-records-v1', base_head=BASE, source_phase='C3 corrected local working-tree source; no hosted or final commit claim', entries=entries, blobs=blobs)
    archive_raw = encoded(archive)
    compressed = gzip.compress(archive_raw, compresslevel=9, mtime=0)
    restored = json.loads(gzip.decompress(compressed))
    decoded = {}
    for r in restored['entries']:
        blob = restored['blobs'][r['blob']]
        b = base64.b64decode(blob['data'], validate=True)
        assert len(b) == blob['bytes'] == r['bytes'] and sha(b) == r['sha256'] == r['blob']
        decoded[r['path']] = b
    assert decoded == data
    # Final inventory + byte reread rejects additions, writes and incomplete streams during packaging.
    for prefix, directory in directories.items():
        assert directory_bytes(directory) == raw_parts[prefix], ('source evidence changed during packaging', prefix)
    assert stable_read(args.terminal_handoff) == handoff_raw
    target = PUB / 'extra-stage-v3' / 'submit-recovery'
    assert not target.exists(), 'do not overwrite frozen stage v3'
    target.mkdir(parents=True)
    def write(name, raw):
        p = target / name
        p.write_bytes(raw)
        return dict(file='submit-recovery/' + name, bytes=len(raw), sha256=sha(raw))
    archive_info = write('original-records.json.gz', compressed)
    report = dict(
        schema='trnm-submit-recovery-local-native-evidence-v1',
        observed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        base_head=BASE, source_phase='C3 local corrected working tree on C2; actual invocation HEAD remains C2 with recorded tracked modifications',
        corrected_production_sha256=PROD_SHA, corrected_fixture_sha256=FIXTURE_SHA,
        final_source_path_count=len(final_source), final_source_snapshot_sha256=sha(native['native-source.final.json']),
        source_manifest_scope_comparison=source_scope_comparison,
        final_source_readback_verified=True, base_source_blob_count_verified=len(base_hashes), changed_native_paths_vs_c2=changed_source,
        root_terminal_summary_sha256=TERMINAL_SHA, root_terminal_pass_names_independently_reparsed_and_equal=True,
        terminal_name_metadata_correction=correction, terminal_name_correction_is_native_failure=False,
        current_node_registry=registry_readback,
        final_local_executables=final_executables,
        all_original_stages=stages, original_records=archive_info,
        original_record_count=len(entries), distinct_byte_blobs=len(blobs), original_record_bytes=sum(r['bytes'] for r in entries), distinct_original_bytes=sum(v['bytes'] for v in blobs.values()),
        original_directory_file_counts={k: len(v) for k, v in raw_parts.items()},
        nested_original_archives_verified=inner_verified,
        successful_local_fixture=dict(passed=24, failed=0, ignored=0, measured=0, filtered_out=0, elapsed_seconds='16.21'),
        baseline_scope='Original retained 24-test fixture aborted with signal 6/SIGABRT; no complete test summary. Preserve the three earlier cap/label failures and the actual worker/proxy panic and secondary connection-refused assertion.',
        first_corrected_scope='Actual 21 PASS/3 FAIL. Newly added fixture assertion physical_execution == !existing was wrong; this field is not a full-W1/native-execution flag. Its corrected false assertion preserves original behavior, original 24 test identities and original 194 assertion sequence per independent fixture review.',
        production_fix_scope='Only two complete authenticated Submit refusal labels select existing bounded recovery actions; Error::remote remains untyped, local EOF/fatal authority remains separate.',
        final_fixture_fix_scope='Fixture setup and fork interventions use the existing original paid CPU domain and metered ingress after pinned Head readiness; preserve original packet/state/generation/nonce/epoch/call assertions. No CPU credit, policy or service limit increases.',
        profiles_scope='Use actual package compiler-artifact profiles retained per stage. Generic Cargo test-profile unoptimized banner is not evidence that trnm-pon-node is opt0. No full workspace native pass is inferred.',
        failure_observations_preserved=True, all_original_raw_bytes_roundtrip_verified=True,
        packaging_reran_native=False, packaging_reran_source_gates=False,
        complete_974_current_source_run=False, c3_hosted_runtime_qualified=False,
        c1_hosted_runtime_result_inherited=False, c2_hosted_results_inherited=False,
        public_host_qualified=False, confirmation_target_qualified=False,
        throughput_qualified=False, release_qualified=False, production_activation=False,
        no_duplicate_cpu_stage_v2_records=True,
    )
    report_info = write('readback.json', encoded(report))
    compact = dict(
        schema='trnm-submit-recovery-local-native-summary-v1',
        observed_utc=report['observed_utc'], base_head=BASE, source_phase=report['source_phase'],
        corrected_production_sha256=PROD_SHA, corrected_fixture_sha256=FIXTURE_SHA,
        final_source_path_count=len(final_source), final_source_snapshot_sha256=report['final_source_snapshot_sha256'],
        source_snapshot_scope=dict(final_manifest_paths=1190, run_recorded_paths=1342, shared_paths=1148, shared_hashes_equal=True, final_only_paths=42, run_recorded_only_paths=194),
        changed_native_paths_vs_c2=changed_source,
        terminal_summary_v2_sha256=TERMINAL_SHA, terminal_name_metadata_correction_sha256=sha(native['terminal-name-correction.json']),
        terminal_name_metadata_correction_scope=correction['scope'], original_summary_and_collector_retained=True,
        current_node_registry=registry_readback,
        native_results=[{k: s[k] for k in ['name', 'native_summary', 'sigabrt_observed', 'production_sha256', 'fixture_sha256']} | {'exit_code': s['result']['returncode'], 'total_invocation_wall_ns': s['result']['wall_ns'], 'source_unchanged': s['result']['source_unchanged']} for s in stages if s['name'] in ['baseline-v1', 'corrected-v1', 'corrected-v2', 'error-boundaries-v1', eof['name']]],
        nonnative_gates=[{'name': name, 'command': by_name[name]['invocation']['command'], 'exit_code': by_name[name]['result']['returncode'], 'source_unchanged': by_name[name]['result']['source_unchanged'], 'wall_ns': by_name[name]['result']['wall_ns']} for name in ['fmt-v1', 'clippy-v1', 'source-negative-v2']],
        source_negative_python_tests=68,
        source_negative_python_elapsed_seconds=python_match[2], repeated_68_not_additional_unique_tests=True,
        final_local_executables=final_executables,
        final_scoped_native_counts={'tcp_fixture': 24, 'error_boundaries': 10, 'typed_eof': 1, 'failed': 0, 'ignored': 0, 'distinct_selected_tests': 35, 'not_a_complete_974_run': True},
        failure_stage_meanings={'baseline': report['baseline_scope'], 'corrected_v1': report['first_corrected_scope']},
        production_fix_scope=report['production_fix_scope'], fixture_fix_scope=report['final_fixture_fix_scope'],
        raw_archive=archive_info, detailed_readback=report_info,
        original_record_count=len(entries), distinct_byte_blobs=len(blobs), original_record_bytes=report['original_record_bytes'],
        all_original_bytes_roundtrip_verified=True,
        packaging_executed_native=False, full_974_current_source_qualified=False,
        c3_hosted_runtime_qualified=False, c1_or_c2_hosted_outcomes_inherited=False,
        public_host_qualified=False, four_second_confirmation_target_qualified=False,
        production_activation=False,
    )
    summary_info = write('summary.json', encoded(compact))
    index_info = write('record-index.json', encoded(dict(schema='trnm-submit-recovery-original-record-index-v1', archive=archive_info, entries=[{k: r[k] for k in ['path', 'bytes', 'sha256']} for r in entries], blob_count=len(blobs), full_roundtrip_verified=True)))
    write('package-submit-recovery-v3.py', Path(__file__).read_bytes())
    files = [dict(path=p.relative_to(PUB / 'extra-stage-v3').as_posix(), bytes=p.stat().st_size, sha256=sha(p.read_bytes())) for p in sorted((PUB / 'extra-stage-v3').rglob('*')) if p.is_file()]
    handoff = dict(schema='trnm-submit-recovery-stage-v3-handoff-v1', frozen=True, target_repository_prefix='evidence/pon-runtime-fixture-closure-20261103/hosted-current/', base_head=BASE, corrected_production_sha256=PROD_SHA, corrected_fixture_sha256=FIXTURE_SHA, files=files, summary=summary_info, readback=report_info, archive=archive_info, index=index_info, native_executed_by_packager=False, repository_source_or_ref_mutated=False)
    write('handoff.json', encoded(handoff))
    print(json.dumps({'archive': archive_info, 'readback': report_info, 'entries': len(entries), 'unique_blobs': len(blobs), 'source_paths': len(final_source), 'final_stage': str(target), 'native_executed_by_packager': False}, sort_keys=True))

if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Read-only verification of the completed fixture native terminal package."""
from pathlib import Path
import base64
import gzip
import hashlib
import json

ROOT = Path(__file__).resolve().parent
sha = lambda raw: hashlib.sha256(raw).hexdigest()
index = json.loads((ROOT / 'artifact-index.json').read_bytes())
for name, row in index['files'].items():
    assert Path(name).name == name
    raw = (ROOT / name).read_bytes()
    assert len(raw) == row['bytes'] and sha(raw) == row['sha256'], name
summary = json.loads((ROOT / 'terminal-summary.json').read_bytes())
association = json.loads((ROOT / 'exact-commit-native-association.json').read_bytes())
assert summary['source'] == association
for filename, field in [('native.log.gz', 'native_log'), ('terminal-records.json.gz', 'records_bundle')]:
    compressed = (ROOT / filename).read_bytes()
    raw = gzip.decompress(compressed)
    row = summary[field]
    assert compressed[4:8] == b'\0' * 4
    assert len(compressed) == row['compressed_bytes'] and sha(compressed) == row['compressed_sha256']
    assert len(raw) == row['raw_bytes'] and sha(raw) == row['raw_sha256']
bundle = json.loads(gzip.decompress((ROOT / 'terminal-records.json.gz').read_bytes()))
originals = {}
for row in bundle['entries']:
    raw = base64.b64decode(bundle['blobs'][row['sha256']], validate=True)
    assert len(raw) == row['bytes'] and sha(raw) == row['sha256']
    assert row['path'] not in originals
    originals[row['path']] = raw
assert len(originals) == summary['records_bundle']['entries']
assert len(bundle['blobs']) == summary['records_bundle']['unique_blobs']
plan = json.loads(originals['full-registry/plan.json'])
reference = json.loads(originals['registry-reference/original971-plan.json'])
result = json.loads(originals['full-registry/result.json'])
scope = {'__name__': 'terminal_package_reader', '__file__': str(ROOT / 'prepare_terminal.py')}
exec(compile((ROOT / 'prepare_terminal.py').read_bytes(), str(ROOT / 'prepare_terminal.py'), 'exec'), scope)
registered, ignored = scope['validate_registry'](plan, reference)
raw_log = gzip.decompress((ROOT / 'native.log.gz').read_bytes())
readback = scope['parse_native_log'](raw_log, registered, ignored, result['exit_code'])
assert readback == json.loads((ROOT / 'independent-native-readback.json').read_bytes())
for name in ('passed', 'failed', 'ignored'):
    assert summary[name] == result[name] == readback[name]
assert result['exit_code'] == summary['actual_native_exit_code']
assert result['log_sha256'] == sha(raw_log)
assert result['binary_sha256'] == association['node_elf_sha256'] == plan['binary_sha256']
assert plan['native_source_manifest_sha256'] == association['native_manifest_sha256']
assert plan['base'] == association['native_execution_invocation_base']
assert result['reader_error'] is None and result['timed_out'] is False and result['binary_unchanged'] is True
for name in ('before', 'after', 'final', 'terminal'):
    raw = originals['build/native-source.' + name + '.json']
    assert sha(raw) == association['native_manifest_sha256'] and len(json.loads(raw)) == 1190
gate = json.loads(originals['exact-commit/summary.json'])
terminal = json.loads(originals['build/terminal.json'])
assert gate['finished_utc'] == association['exact_commit_gate_finished_utc']
assert terminal['completed_utc'] == association['native_driver_terminal_completed_utc']
assert gate['expected_commit'] == association['commit'] and gate['status'] == 'PASS'
assert association['native_executed_after_clean_commit_checkout'] is False
pending = json.loads(originals['prepublish-reference/source-bound-summary.json'])
assert pending['full_registry']['status'] == 'PENDING'
assert summary['pending_snapshot_modified'] is False
assert summary['prior_diagnostics_only_result_inherited'] is False
draft = json.loads(gzip.decompress((ROOT / 'chronology-draft-v1.json.gz').read_bytes()))
correction = json.loads((ROOT / 'chronology-correction.json').read_bytes())
for row in draft['entries']:
    raw = base64.b64decode(draft['blobs'][row['sha256']], validate=True)
    assert sha(raw) == row['sha256'] and len(raw) == row['bytes']
    assert correction['preserved_derived_v1'][row['path']] == {'bytes': len(raw), 'sha256': sha(raw)}
print(json.dumps({'package_integrity': 'PASS', 'original_records': len(originals),
                  'registered': len(registered), 'passed': readback['passed'],
                  'failed': readback['failed'], 'ignored': readback['ignored'],
                  'actual_native_exit_code': result['exit_code'],
                  'native_executions_by_verifier': 0,
                  'scope': 'evidence integrity only; retains actual native failure and separate service HOLD'}))

"""Read retained native evidence; execute no Rust or provider binaries."""
from pathlib import Path, PurePosixPath
import hashlib
import json
import re
import tarfile

BASE = Path('/workspace/scratch/0b53202edbbf/validation')
ROOT = BASE / 'desktop-native-m-validation-v1'
M = '11e242dbaaae14a9d16282fe8deaf36827e98395'
TREE = '1f42f41923d7761c02fc68b478df5b019c7d83e8'


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


archive = BASE / 'native-m-validation-v1-final-text.tar.gz'
archive_bytes = archive.read_bytes()
assert len(archive_bytes) == 188684
assert digest(archive_bytes) == '195c77615f45a15b1c547ccad35532bc9764d13f52255ecc1832d3d3b5dbc2bd'
manifest = json.loads((ROOT / 'archive-manifest.json').read_bytes())
assert manifest['source'] == M and manifest['tree'] == TREE
assert manifest['outer_finished'] is True and manifest['outer_success'] is True
assert manifest['ELF_included'] is False and len(manifest['files']) == 36
files = {row['name']: row for row in manifest['files']}
assert len(files) == 36
with tarfile.open(archive, 'r:gz') as tar:
    members = tar.getmembers()
    assert len(members) == 37
    assert {m.name for m in members} == set(files) | {'archive-manifest.json'}
    for member in members:
        path = PurePosixPath(member.name)
        assert member.isfile() and len(path.parts) == 1 and not path.is_absolute()
        raw = tar.extractfile(member).read()
        assert raw == (ROOT / member.name).read_bytes()
        assert not raw.startswith(b'\x7fELF')
        if member.name in files:
            row = files[member.name]
            assert len(raw) == row['bytes'] and digest(raw) == row['sha256']

summary_raw = (ROOT / 'summary.json').read_bytes()
assert digest(summary_raw) == 'ab05426922986387ed65bf3b90ef0179da5989506516f93ed5ff6e614d17dc34'
s = json.loads(summary_raw)
assert s['source'] == M and s['tree'] == TREE and s['success'] is True
assert s['build_overrides'] == {}
assert s.get('failure') is None and s.get('final_guard_failure') is None
assert s['whole_source_before'] == s['whole_source_after_library'] == s['final_source']
for source in s['final_source'].values():
    assert source['tested_commit'] == M and source['tested_tree'] == TREE
    assert source['tracked_worktree_verified'] is True
    assert source['tracked_entries'] == 28058 and source['tracked_bytes'] == 2592587811

streams = set()
processes = {}
for key in ('fixed_process', 'library_process', 'format_process', 'provider_version_process', 'clippy_process'):
    proc = s[key]
    assert proc['started'] is True and proc['exit_code'] == 0
    assert proc['failure'] is None and proc['cleanup_errors'] == []
    for stream in ('stdout', 'stderr'):
        row = proc[stream]
        name = Path(row['path']).name
        raw = (ROOT / name).read_bytes()
        assert len(raw) == row['bytes'] and digest(raw) == row['sha256']
        streams.add(name)
    processes[key] = {'command': proc['command'], 'exit_code': proc['exit_code'],
                      'elapsed_wall_ns': proc['elapsed_wall_ns'],
                      'stdout': proc['stdout'], 'stderr': proc['stderr']}
for step in s['steps']:
    assert step['started'] is True and step['exit_code'] == 0
    assert step['failure'] is None and step['cleanup_errors'] == []
    for stream in ('stdout', 'stderr'):
        name = Path(step[stream]).name
        assert digest((ROOT / name).read_bytes()) == step[stream + '_sha256']
        streams.add(name)

fixed_raw = (BASE / 'desktop-native-m-fixed-v1/report.json').read_bytes()
assert digest(fixed_raw) == s['fixed_report_sha256']
assert s['fixed_result'] == 'PASS'
fixed = json.loads(fixed_raw)
assert fixed['result'] == 'PASS'
assert set(s['final_binary_guards']) == {'libtest', 'pool-integration', 'cli'}
for role, guard in s['final_binary_guards'].items():
    original = fixed['executables'][role]
    assert guard['equal'] is True
    assert guard['built_after_all'] == original['built_before']
    assert guard['retained_after_all'] == original['retained_before']
    assert guard['compiler_artifact'] == original['compiler_artifact']
assert s['library_process']['command'] == [fixed['executables']['libtest']['execution_path'], '--nocapture', '--test-threads=1']
stdout = (ROOT / 'node-library.stdout').read_text()
pattern = re.compile(r'^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out; finished in ([0-9.]+)s$', re.MULTILINE)
matches = list(pattern.finditer(stdout))
assert matches and stdout.rstrip().endswith(matches[-1].group(0))
last = matches[-1]
assert last.groups() == ('ok', '1313', '0', '39', '0', '0', '4283.75')
assert 1313 + 39 == 1352 and s['library_pass'] is True
assert s['clippy_process']['command'] == ['/home/qian-qi/.cargo/bin/cargo', '+1.95.0', 'clippy', '--locked', '--manifest-path', 'trillionnium/Cargo.toml', '-p', 'trnm-pon-node', '--all-targets', '--all-features', '--', '-D', 'warnings']
assert s['provider_before'] == s['provider_after'] and len(s['provider_before']) == 5
assert s['provider_before']['bin/openssl']['sha256'] == '65b8f0423f3031a5f0eea5e3d571a24bcaaf79fb8a1b3ee68ad2e7438b3dbac0'
assert (ROOT / 'provider-version.stdout').read_text().startswith('OpenSSL 3.5.9 ')

runtime_path = BASE / 'native-m-runtime-final-status.json'
runtime_raw = runtime_path.read_bytes()
assert digest(runtime_raw) == '2fbba78231297f221fc8c76f47ec33b4e29ef1a7d5a99c3d0dec951357ad26d0'
runtime = json.loads(runtime_raw)
assert runtime['job_id'] == '1a1c8e525d6-135c4-2c1'
assert runtime['state'] == 'succeeded' and runtime['exit_code'] == 0
assert not any(runtime[k] for k in ('cancelled', 'timed_out', 'automatic_retry'))
assert all(runtime[k] for k in ('terminal_publication_confirmed', 'output_complete', 'output_durable'))

result = {
    'schema': 'root-native-M-final-evidence-readback-v1', 'result': 'PASS',
    'scope': 'Copied original text, recorded source/provider/binary guards and runtime receipt. No native execution, independent ELF/provider download or business qualification.',
    'source': M, 'tree': TREE, 'archive_bytes': len(archive_bytes),
    'archive_sha256': digest(archive_bytes), 'original_files_verified': len(files),
    'summary_sha256': digest(summary_raw), 'process_streams_verified': len(streams),
    'fixed_report_sha256': digest(fixed_raw), 'processes': processes,
    'whole_library': {'passed': 1313, 'failed': 0, 'ignored': 39, 'measured': 0,
                      'filtered_out': 0, 'listed_tests': 1352, 'reported_seconds': '4283.75',
                      'all_libtest_summaries_in_stream': len(matches), 'selected_summary': last.group(0)},
    'source_before_after_final_equal': True, 'provider_before_after_equal': True,
    'recorded_final_binary_guards': s['final_binary_guards'],
    'runtime_receipt_sha256': digest(runtime_raw),
    'qualification': {'complete_business_liveness': False, 'sustained_tps': False,
                      'wan_capacity': False, 'production_activation': False},
}
output = BASE / 'root-native-M-final-evidence-readback.json'
with output.open('x') as stream:
    json.dump(result, stream, indent=2)
    stream.write('\n')
print(json.dumps({'result': result['result'], 'original_files_verified': len(files),
                  'process_streams_verified': len(streams), 'whole_library': result['whole_library'],
                  'output': str(output), 'bytes': output.stat().st_size,
                  'sha256': digest(output.read_bytes())}))

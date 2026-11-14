#!/usr/bin/env python3
"""Resume the exact reviewed merge after lossless capture-format correction."""
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil

TASK = Path('/home/qian-qi/work/chain-pq-authority-20261108-9d315')
PREP = TASK / 'integration-preparation-01'
driver = PREP / 'integrate-authority-base.py'
assert hashlib.sha256(driver.read_bytes()).hexdigest() == '1370c1744617e0cd6cff8b80f7f1b61406baebc88dd6069d035ab7c7d92eed31'
spec = importlib.util.spec_from_file_location('reviewed_merge', driver)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
original_out = m.OUT
m.OUT = TASK / 'validation/concurrent-base-integration-recovery-01'
m.OUT.mkdir(parents=True, exist_ok=False)
m.commands = []
shutil.copyfile(Path(__file__).resolve(), m.OUT / 'driver.py')

assert m.git('rev-parse', 'HEAD').decode().strip() == m.OURS
assert m.git('rev-parse', 'MERGE_HEAD').decode().strip() == m.THEIRS
assert not m.git('diff', '--name-only', '--diff-filter=U').strip()
assert not m.git('diff', '--name-only').strip()
prior = json.loads((original_out / 'commands.json').read_text())
assert prior[-1]['label'] == 'staged-diff-check' and prior[-1]['exit_code'] == 2
counts = json.loads((PREP / 'first-validation-counts.json').read_text())
assert counts['result'] == 'PASS' and counts['source_commit'] == m.OURS
shutil.copyfile(PREP / 'first-validation-counts.json', m.OUT / 'first-validation-counts.json')
m.run('preflight', ['/bin/bash', 'scripts/project-preflight.sh'])
index_path = m.EVIDENCE / 'artifact-index.json'
index = json.loads(index_path.read_text())
corpus = json.loads((m.REPO / m.CORPUS).read_text())
assert len(corpus['pinned_blobs']) == 722 and len(corpus['required_paths']) == 641
assert len(corpus['assertions']) == 8 and all(v is False for v in corpus['assertions'].values())
for relative, expected in index['files'].items():
    data = (m.EVIDENCE / relative).read_bytes()
    assert len(data) == expected['bytes'] and m.digest(data) == expected['sha256']
    assert m.git('show', ':' + m.EVIDENCE_REL + '/' + relative) == data

check = m.run('complete-pr-diff-check-before-archive',
              ['/usr/bin/git', 'diff', '--cached', '--check', m.THEIRS], allowed=(0, 2))
headers = re.findall(r'^([^\n:]+):(\d+): ([^\n]+)$', check.stdout.decode(), re.M)
assert check.returncode == 2 and headers
paths = set()
for path, line, reason in headers:
    assert reason in ('trailing whitespace.', 'new blank line at EOF.'), (path, reason)
    assert path.startswith(m.EVIDENCE_REL + '/'), path
    assert Path(path).suffix in {'.log', '.diff', '.patch', '.raw', '.txt'}, path
    assert path not in corpus['pinned_blobs'] and path not in corpus['required_paths']
    paths.add(path)

compressed = {}
readme_path = m.EVIDENCE / 'README.md'
readme = readme_path.read_text()
for path in sorted(paths):
    source = m.REPO / path
    relative = source.relative_to(m.EVIDENCE).as_posix()
    data = source.read_bytes()
    assert m.digest(data) == index['files'][relative]['sha256']
    destination = Path(str(source) + '.gz')
    assert not destination.exists() and not source.is_symlink() and source.stat().st_nlink == 1
    encoded = gzip.compress(data, compresslevel=9, mtime=0)
    assert gzip.decompress(encoded) == data
    with destination.open('xb') as stream:
        stream.write(encoded)
    record = {'compressed_bytes': len(encoded), 'compressed_sha256': m.digest(encoded),
              'uncompressed': {'bytes': len(data), 'sha256': m.digest(data), 'relative_path': relative}}
    index['compression'][relative + '.gz'] = record
    compressed[relative + '.gz'] = record
    m.run('archive-raw-' + str(len(compressed)), ['/usr/bin/git', 'rm', '--cached', '--', path])
    assert source.read_bytes() == data
    source.unlink()
    readme = readme.replace('](' + relative + ')', '](' + relative + '.gz)')
readme += ('\n## Lossless capture formatting\n\n'
    'Raw native output includes deliberate final blank lines. Captures that trigger\n'
    'Git whitespace checks are stored as lossless gzip, with their original byte\n'
    'lengths and SHA-256 values in the compression mapping of `artifact-index.json`.\n'
    'No captured output is trimmed or rewritten, and original receipt paths and\n'
    'hashes remain unchanged. The initial archive-format check refusal is retained\n'
    'separately from the passing source and native validation.\n')
readme_path.write_text(readme)
m.save(index_path, index)
index = m.rebuild_index()
m.save(m.OUT / 'lossless-capture-format.json', {
    'result': 'PASS', 'original_failure_directory': str(original_out),
    'compressed_files': compressed, 'source_bytes_trimmed': False,
    'whitespace_policy_changed': False})
stage = [m.EVIDENCE_REL + '/' + name for name in index['files']]
stage.append(m.EVIDENCE_REL + '/artifact-index.json')
m.run('stage-exact-evidence-inventory', ['/usr/bin/git', 'add', '--force', '--', *stage])
for relative, expected in index['files'].items():
    data = m.git('show', ':' + m.EVIDENCE_REL + '/' + relative)
    assert len(data) == expected['bytes'] and m.digest(data) == expected['sha256']
native = ['trillionnium', 'tests/fuzz', '.cargo', 'rust-toolchain', 'rust-toolchain.toml']
m.run('native-source-equality', ['/usr/bin/git', 'diff', '--cached', '--exit-code', m.OURS, '--', *native])
m.run('staged-diff-check', ['/usr/bin/git', 'diff', '--cached', '--check'])
m.run('complete-pr-diff-check', ['/usr/bin/git', 'diff', '--cached', '--check', m.THEIRS])
m.run('staged-preflight', ['/bin/bash', 'scripts/project-preflight.sh', '--staged'])
m.run('integrated-ci-contract-precheck', ['/usr/bin/python3', '-B', 'scripts/ci/check_ci_contract.py'])
hold = m.run('integrated-pq-source-precheck', ['/usr/bin/python3', '-B', 'scripts/ci/check_pq_research_integration.py'])
value = json.loads(hold.stdout)
assert value['status'] == 'HOLD_NO_GO'
assert value['cryptographic_acceptance'] is False and value['node_activated'] is False
m.run('commit-integrated-source', ['/usr/bin/git', 'commit', '-m', 'merge(pq): retain concurrent migration qualification'])
head = m.git('rev-parse', 'HEAD').decode().strip()
parents = m.git('show', '-s', '--format=%P', 'HEAD').decode().split()
assert parents == [m.OURS, m.THEIRS]
assert not m.git('status', '--porcelain=v1', '--untracked-files=all').strip()
receipt = {'result': 'PASS', 'source_commit': head,
    'source_tree': m.git('rev-parse', 'HEAD^{tree}').decode().strip(),
    'parents': parents, 'branch': m.BRANCH, 'pinned_blobs': 722, 'required_paths': 641,
    'first_validation_commit': m.OURS, 'first_validation_gates': 28,
    'production_activation': False, 'whole_chain_pq_qualified': False,
    'native_source_unchanged_from_first_validation': True,
    'artifact_index_files': len(index['files']), 'lossless_archived_captures': len(compressed),
    'integrated_validation_executed': False, 'original_failed_attempt_preserved': True}
m.save(m.OUT / 'receipt.json', receipt)
print(json.dumps(receipt), flush=True)

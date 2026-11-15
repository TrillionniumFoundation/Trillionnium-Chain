#!/usr/bin/env python3
"""Refresh one omitted inventory entry and freeze the additional validation gate."""
from __future__ import annotations
import base64
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import time

ROOT = Path('/home/qian-qi/work/chain-pq-authority-20261108-9d315')
REPO = ROOT / 'repo'
OUT = ROOT / 'validation/distributed-inventory-fix-01'
PARENT = '527e2e58db6d7c1fd84ba88c3131289edea86b1d'
BRANCH = 'fix/chain-pq-authority-preflight-20261108-9d315'
EV = 'evidence/pq-authority-preflight-20261108-9d315'
OLD_RUNNER = REPO / EV / 'authority-integrated-validation-runner.py'
NEW_RUNNER = EV + '/authority-final-validation-runner.py'
INVENTORY = 'trillionnium/crates/trnm-pon-node/examples/support/distributed_source_inventory.rs'
REFRESH = 'scripts/refresh_distributed_source_inventory.py'
MISSING = 'trillionnium/crates/trnm-release-bundle/src/pq_release/quorum_preflight_tests.rs'
REPORT = 'docs/security/PQ_AUTHORITY_PREFLIGHT_20261108.md'
PLAN = 'docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md'
CORPUS = 'config/pon/pq-cross-branch-corpus-v1.json'
INDEX = EV + '/artifact-index.json'
CHANGED = sorted([INVENTORY, REPORT, PLAN, CORPUS, NEW_RUNNER, INDEX])
RUNNER_GZIP_B64 = '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'
RUNNER_SHA = 'd81437a1cef461666b9103cc3f9e8f8ab0c67a90903b5802f582d2c52cd82710'
BEFORE_SHA = 'f834d8c2b0f49811ff8930898e01c65b40801d8fbef550a8662457bbbdea02e8'
AFTER_SHA = '36a8bb4a6d77a3b212c88de2f8af66cb1def7fac4a0db9638d1e64167b6e8c5b'
REPORT_NOTE = '''
## Hosted CI inventory follow-up

Hosted checks on the initial delivery
`527e2e58db6d7c1fd84ba88c3131289edea86b1d` found a concrete integration
omission: the embedded distributed native source inventory did not list the
new `pq_release/quorum_preflight_tests.rs`. The existing base inventory was
fresh. This continuation introduced exactly one missing path and no extra or
deleted paths: the expected list has 1,369 entries, compared with the retained
1,368-entry list. The original generator refreshes that one entry without
changing its enumeration rules or the signature implementation.

The previously recorded 31 local command gates did not include this independent
hosted freshness check. Their actual results remain bound to their own tested
sources. A separate frozen 32-command runner preserves every original command
and argument, adding `scripts/refresh_distributed_source_inventory.py --check`
immediately after the initial raw-source guard. The generator itself is now
explicitly source-pinned alongside that runner. The execution record identifies
the corrected source and the actual later validation result.

Hosted results also include an unavailable pinned historical artifact and real
public-service confirmation failures. Those observations remain separate from
the inventory omission and the local cryptographic tests; refreshing a source
inventory does not establish service performance, hosted acceptance or any
production qualification. Original failed runs and reports must remain FAIL.
'''
PLAN_NOTE = '''
### 2026-11-08 — distributed source inventory follow-up

Status: **Draft / HOLD**. Hosted checks found that the PQ quorum-preflight change
omitted its new Rust test file from the embedded distributed source inventory.
Refresh the existing inventory with its unchanged generator and retain the
original failed observation. The separate final validation runner adds the
actual inventory freshness command to the existing 31 gates, for 32 total;
the execution evidence must bind any pass to the corrected source. See the
[authority report](../security/PQ_AUTHORITY_PREFLIGHT_20261108.md) for this
omission and the distinct hosted historical-evidence and business-target
failures. No whole-chain or production claim is promoted by this follow-up.
'''


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def blob(raw: bytes) -> str:
    return hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def main() -> int:
    assert not OUT.exists()
    assert digest(OLD_RUNNER.read_bytes()) == 'f5fc66625c09cfccf5054ec705a49c2a88f234c0620e6e6426aa4b7efcb71b86'
    spec = importlib.util.spec_from_file_location('retained_validation', OLD_RUNNER)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    env = m.environment(ROOT / 'target')
    OUT.mkdir()
    shutil.copyfile(Path(__file__), OUT / 'apply-distributed-inventory-fix.py')
    m.save(OUT / 'environment.json', env)
    receipt = {'schema': 'trnm-distributed-source-inventory-fix-v1', 'result': 'FAIL',
               'parent_commit': PARENT, 'changed_paths': CHANGED, 'commands': [], 'failures': [],
               'expected_red_label': 'inventory-before-check', 'native_validation_executed': False,
               'production_activation': False, 'whole_chain_pq_qualified': False,
               'hosted_ci_passed': False, 'native_signature_implementation_changed': False}

    def git(*args: str) -> bytes:
        return subprocess.check_output(['/usr/bin/git', '-C', str(REPO), *args], env=env, stderr=subprocess.PIPE)

    def command(label: str, argv: list[str], kind: str = 'exit', expected_red: bool = False) -> dict:
        row = m.run_command((label, argv, kind), REPO, OUT, env)
        receipt['commands'].append(row)
        m.save(OUT / 'receipt.json', receipt)
        if not expected_red:
            assert row['passed'], 'command failed: ' + label
        return row

    try:
        initial = m.source_identity(REPO, env)
        assert initial['head'] == PARENT and initial['branch'] == BRANCH and not initial['status']
        m.save(OUT / 'source-before.json', initial)
        command('preflight-before-edit', ['/bin/bash', 'scripts/project-preflight.sh'], 'preflight')
        assert digest((REPO / REFRESH).read_bytes()) == 'c83d9c0b84c21beec6917a86b2a3207c5f3bf6fd26cf432f2ef0990750e16a33'
        old_inventory = (REPO / INVENTORY).read_bytes()
        assert digest(old_inventory) == BEFORE_SHA and blob(old_inventory) == 'dc4914b370d7bd179cf1aa07d9633a2e224dc7bd'
        old = {path: (REPO / path).read_bytes() for path in (INVENTORY, REPORT, PLAN, CORPUS, INDEX)}
        for path, raw in old.items():
            assert raw == git('show', PARENT + ':' + path)
        assert digest(old[INDEX]) == 'f580dbc10d67c6d256cfd3cd051e56117c9e78b6da198470e00f95d405b68c0c'
        (OUT / 'inventory-before.raw').write_bytes(old_inventory)
        red = command('inventory-before-check', [m.PYTHON, '-B', REFRESH, '--check'], expected_red=True)
        assert red['exit_code'] == 1 and red['passed'] is False and not red.get('timed_out')
        assert (OUT / 'inventory-before-check.stdout.log').read_bytes() == b''
        assert (OUT / 'inventory-before-check.stderr.log').read_text() == 'distributed native source inventory differs; refresh before freezing source\n'
        command('refresh-inventory', [m.PYTHON, '-B', REFRESH])
        refreshed = (REPO / INVENTORY).read_bytes()
        assert digest(refreshed) == AFTER_SHA and blob(refreshed) == '280844d69a88b273df670a55011e0c1c753325a7'
        pattern = r'^        "([^"]+)",$'
        before_paths = set(re.findall(pattern, old_inventory.decode(), re.M))
        after_paths = set(re.findall(pattern, refreshed.decode(), re.M))
        assert len(before_paths) == 1368 and len(after_paths) == 1369
        assert after_paths - before_paths == {MISSING} and not before_paths - after_paths
        (OUT / 'inventory-after.raw').write_bytes(refreshed)
        receipt['inventory'] = {'path': INVENTORY, 'before': m.file_record(OUT / 'inventory-before.raw'),
                                'after': m.file_record(OUT / 'inventory-after.raw'),
                                'before_paths': len(before_paths), 'after_paths': len(after_paths),
                                'added_paths': [MISSING], 'removed_paths': []}
        runner_raw = gzip.decompress(base64.b64decode(RUNNER_GZIP_B64, validate=True))
        assert len(runner_raw) == 25774 and digest(runner_raw) == RUNNER_SHA
        assert not (REPO / NEW_RUNNER).exists()
        (REPO / NEW_RUNNER).write_bytes(runner_raw)
        new_spec = importlib.util.spec_from_file_location('final_validation', REPO / NEW_RUNNER)
        new = importlib.util.module_from_spec(new_spec)
        new_spec.loader.exec_module(new)
        old_commands = m.command_list(PARENT, OUT)
        new_commands = new.command_list(PARENT, OUT)
        assert len(new_commands) == 32 and len(old_commands) == 31
        assert [row for row in new_commands if row[0] != 'distributed-source-inventory'] == old_commands
        assert new_commands[2] == ('distributed-source-inventory', [m.PYTHON, '-B', REFRESH, '--check'], 'exit')
        receipt['validation_runner'] = m.file_record(REPO / NEW_RUNNER)
        receipt['original_31_commands_preserved'] = True
        receipt['declared_final_gates'] = 32
        for path, note, heading in [(REPORT, REPORT_NOTE, '## Hosted CI inventory follow-up'),
                                    (PLAN, PLAN_NOTE, '### 2026-11-08 — distributed source inventory follow-up')]:
            text = old[path].decode()
            assert heading not in text
            (REPO / path).write_text(text.rstrip() + '\n' + note, encoding='utf-8')
        corpus = json.loads(old[CORPUS])
        assert len(corpus['pinned_blobs']) == 722 and len(corpus['required_paths']) == 641
        assert len(corpus['assertions']) == 8 and all(v is False for v in corpus['assertions'].values())
        refreshed_pins = []
        for path in (INVENTORY, REPORT, PLAN):
            if path in corpus['pinned_blobs']:
                assert corpus['pinned_blobs'][path] == blob(old[path])
                corpus['pinned_blobs'][path] = blob((REPO / path).read_bytes())
                refreshed_pins.append(path)
        assert INVENTORY in refreshed_pins and REPORT in refreshed_pins
        for path in (NEW_RUNNER, REFRESH):
            assert path not in corpus['pinned_blobs'] and path not in corpus['required_paths']
            corpus['pinned_blobs'][path] = blob((REPO / path).read_bytes())
        corpus['required_paths'] = sorted(set(corpus['required_paths']) | {NEW_RUNNER, REFRESH})
        assert len(corpus['pinned_blobs']) == 724 and len(corpus['required_paths']) == 643
        m.save(REPO / CORPUS, corpus)
        receipt['corpus'] = {'pinned_blobs': 724, 'required_paths': 643,
                             'new_pins': [NEW_RUNNER, REFRESH], 'refreshed_pins': refreshed_pins,
                             'all_eight_assertions_false': True}
        index = json.loads(old[INDEX])
        assert len(index['files']) == 499 and 'authority-final-validation-runner.py' not in index['files']
        index['files']['authority-final-validation-runner.py'] = {'bytes': len(runner_raw), 'sha256': RUNNER_SHA}
        assert len(index['files']) == 500
        m.save(REPO / INDEX, index)
        receipt['artifact_index'] = {'before_files': 499, 'after_files': 500, 'only_new_entry': 'authority-final-validation-runner.py',
                                    'validated_commits_unchanged': index['validated_commits'] == json.loads(old[INDEX])['validated_commits']}
        command('inventory-after-check', [m.PYTHON, '-B', REFRESH, '--check'])
        assert (OUT / 'inventory-after-check.stdout.log').read_text() == 'distributed source inventory: PASS\n'
        assert sorted(git('diff', '--name-only').decode().splitlines()) == sorted(set(CHANGED) - {NEW_RUNNER})
        assert git('ls-files', '--others', '--exclude-standard').decode().splitlines() == [NEW_RUNNER]
        command('ci-contract', [m.PYTHON, '-B', 'scripts/ci/check_ci_contract.py'], 'json')
        command('pq-integration', [m.PYTHON, '-B', 'scripts/ci/check_pq_research_integration.py'], 'hold-no-go')
        command('stage-reviewed-paths', ['/usr/bin/git', 'add', '--', *CHANGED])
        assert sorted(git('diff', '--cached', '--name-only').decode().splitlines()) == CHANGED
        command('staged-diff-check', ['/usr/bin/git', 'diff', '--cached', '--check'])
        command('preflight-before-commit', ['/bin/bash', 'scripts/project-preflight.sh', '--staged'], 'preflight')
        (OUT / 'source-correction.patch').write_bytes(git('diff', '--cached', '--binary', '--full-index', '--no-ext-diff', '--no-textconv'))
        command('commit-inventory-fix', ['/usr/bin/git', 'commit', '-m', 'fix(ci): refresh native source inventory and retain its gate'])
        final = m.source_identity(REPO, env)
        assert not final['status'] and final['branch'] == BRANCH
        assert git('rev-parse', 'HEAD^').decode().strip() == PARENT
        assert sorted(git('diff', '--name-only', PARENT, 'HEAD').decode().splitlines()) == CHANGED
        rust_changed = [x for x in CHANGED if x.endswith('.rs')]
        assert rust_changed == [INVENTORY]
        m.save(OUT / 'source-after.json', final)
        receipt['source_commit'] = final['head']
        receipt['source_tree'] = final['tree']
        receipt['result'] = 'PASS'
    except Exception as error:
        receipt['failures'].append(f'{type(error).__name__}: {error}')
    finally:
        receipt['finished_unix_seconds'] = time.time()
        m.save(OUT / 'receipt.json', receipt)
        print(json.dumps({k: v for k, v in receipt.items() if k != 'commands'}), flush=True)
    return 0 if receipt['result'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())

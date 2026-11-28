"""Fill absent build inputs in this task's source; never invoke Cargo or overwrite."""
import base64
import hashlib
import json
import os
import pathlib
import stat
import subprocess
import zlib

ROOT = pathlib.Path('/tmp/hepta-chain-6523704f97df-real-crate-attempt-1')
SOURCE = ROOT / 'source'
HEAD = '1bd4a71c6efaa6921237fd4612d37cb7ef0e4645'
TREE = 'f00edac77554e3ff3a649cd6159b25d1c193ac13'
OUT = ROOT / 'full-include-closure-materialization'
OUT.mkdir(mode=0o700, exist_ok=False)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def git_sha(kind, data):
    return hashlib.sha1(kind.encode() + b' ' + str(len(data)).encode() + b'\0' + data).hexdigest()


def git(*args):
    result = subprocess.run(['git', *args], cwd=SOURCE, capture_output=True,
                            env=dict(os.environ, GIT_NO_LAZY_FETCH='1'), timeout=15)
    assert result.returncode == 0, result.stderr.decode(errors='replace')
    return result.stdout


def check_tree(entries, expected):
    rows = sorted(entries, key=lambda x: x['path'] + ('/' if x['type'] == 'tree' else ''))
    assert len({x['path'] for x in rows}) == len(rows)
    assert all('/' not in x['path'] for x in rows)
    data = b''.join((x['mode'].lstrip('0') + ' ' + x['path']).encode() + b'\0' + bytes.fromhex(x['sha']) for x in rows)
    assert git_sha('tree', data) == expected


def safe_path(path, allow_missing=False):
    relative = pathlib.PurePosixPath(path)
    assert not relative.is_absolute() and all(p not in ('', '.', '..') for p in relative.parts)
    current = SOURCE
    assert stat.S_ISDIR(current.lstat().st_mode)
    for i, part in enumerate(relative.parts):
        current = current / part
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError:
            assert allow_missing
            continue
        assert not stat.S_ISLNK(mode), path
        assert stat.S_ISREG(mode) if i == len(relative.parts) - 1 else stat.S_ISDIR(mode)
    return current


report = {'schema': 'chain-fixed-include-closure-materialization-v1', 'head': HEAD,
          'whole_tree': TREE, 'result': 'RUNNING', 'new_files': [],
          'existing_source_or_assertion_changed': False, 'cargo_or_test_invoked': False,
          'original_receipts_unchanged': False, 'closure_ready': False,
          'source_sha256': {}, 'target_git_bindings': []}


def save():
    (OUT / 'RESULT.json').write_text(json.dumps(report, sort_keys=True, indent=2))


try:
    assert git('rev-parse', 'HEAD').decode().strip() == HEAD
    assert git('rev-parse', 'HEAD^{tree}').decode().strip() == TREE
    packet_raw = (ROOT / 'FULL_INCLUDE_MATERIALIZATION_PACKET.json.zlib').read_bytes()
    assert sha(packet_raw) == '6435a9d9d06e52f9088f772a52454e89c131c1ce2bf169b604e74350722c57d6'
    decoded = zlib.decompress(packet_raw)
    assert sha(decoded) == '263727e4a7704bbae69226cfc63733b6f227cb9bce5ea47bf540e63d4d85564a'
    packet = json.loads(decoded)
    assert packet['head'] == HEAD and packet['root_tree']['sha'] == TREE
    check_tree(packet['root_tree']['tree'], TREE)
    anchor = {x['path']: x for x in packet['root_tree']['tree']}
    expected = {}
    tree_count = 1
    for prefix, tree in sorted(packet['trees'].items(), key=lambda x: x[0].count('/')):
        assert tree['truncated'] is False and tree['sha'] == anchor[prefix]['sha']
        groups, hashes = {'': []}, {'': tree['sha']}
        for item in tree['tree']:
            parent, _, leaf = item['path'].rpartition('/')
            groups.setdefault(parent, []).append(dict(item, path=leaf))
            full = prefix + '/' + item['path']
            anchor[full] = item
            if item['type'] == 'tree':
                hashes[item['path']] = item['sha']
            elif item['type'] == 'blob':
                expected[full] = {'git_sha': item['sha'], 'size': item['size'], 'mode': item['mode']}
        if tree['recursive']:
            assert set(groups) <= set(hashes)
            for path, digest in hashes.items():
                check_tree(groups.get(path, []), digest)
                tree_count += 1
        else:
            check_tree(tree['tree'], tree['sha'])
            tree_count += 1
    assert tree_count == 368
    external = packet['expected_external_targets']
    assert len(external) == 119
    for item in external:
        assert {k: item[k] for k in ('git_sha', 'size', 'mode')} == expected[item['path']]
    scan_raw = (ROOT / 'FULL_INCLUDE_CLOSURE_SCAN_LINEAR.json').read_bytes()
    assert sha(scan_raw) == 'b5a08e0dcc66f06fa88efb0e543da452cfa00ddcf98c6e1a9f44d2d6b7c56009'
    scan = json.loads(scan_raw)
    assert scan['head'] == HEAD and not scan['lexer_failures'] and not scan['unresolved_expressions']
    assert len(scan['resolved_occurrences']) == 1952 and len(scan['unique_targets']) == 1788
    assert len(scan['missing_targets']) == 72
    assert not [x for x in scan['resolved_occurrences'] if x['macro'] == 'include' and not x['target'].startswith('trillionnium/')]
    for path, digest in scan['verified_source_sha256'].items():
        assert sha(safe_path(path).read_bytes()) == digest
    prior_path = ROOT / 'owner-wrapper-four-controls-attempt-1/GATE.json'
    assert sha(prior_path.read_bytes()) == '7d8a77251a4c49ee64fb2c1ff116de2830c79fcbfa5dce5d6f92db3f6ecff8c2'
    prior = json.loads(prior_path.read_bytes())
    pins = dict(prior['source_sha256'])
    assert len(pins) == 1778 and prior['new_controls_passed'] == 0 and prior['result'] == 'FIRST_GATE_FAILURE'
    receipts = dict(prior['original_receipt_sha256'])
    receipts.update({
        'owner-wrapper-four-controls-attempt-1/GATE.json': '7d8a77251a4c49ee64fb2c1ff116de2830c79fcbfa5dce5d6f92db3f6ecff8c2',
        'OWNER_WRAPPER_FOUR_OUTER.json': '6c3b0aa61872ff2956fb79f72a25893638fa48004c96b6ed8b3ef5a2062f2feb',
        'owner-wrapper-four-controls-attempt-1/owner_wrapper_four_controls.stderr': '57c9c1a1df5952220387552aa8ddb7ef5fceb8ae0105ccdf00b887894afcd704',
    })
    assert all(sha((ROOT / p).read_bytes()) == h for p, h in receipts.items())
    assert all(sha(safe_path(p).read_bytes()) == h for p, h in pins.items())
    preflight = subprocess.run(['bash', 'scripts/project-preflight.sh'], cwd=SOURCE,
                               capture_output=True, timeout=20)
    (OUT / 'preflight.stdout').write_bytes(preflight.stdout)
    (OUT / 'preflight.stderr').write_bytes(preflight.stderr)
    report['preflight'] = {'exit_code': preflight.returncode,
                           'stdout_sha256': sha(preflight.stdout), 'stderr_sha256': sha(preflight.stderr)}
    assert preflight.returncode == 0
    assert sorted(x['path'] for x in packet['missing_files']) == sorted(scan['missing_targets'])
    for item in packet['missing_files']:
        data = base64.b64decode(item['content']) if item['encoding'] == 'base64' else item['content'].encode()
        assert len(data) == item['size'] and git_sha('blob', data) == item['git_sha']
        assert item['mode'] in ('100644', '100755')
        assert {k: item[k] for k in ('git_sha', 'size', 'mode')} == expected[item['path']]
        path = safe_path(item['path'], allow_missing=True)
        assert not path.exists()
        path.parent.mkdir(parents=True, exist_ok=True)
        safe_path(item['path'], allow_missing=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, int(item['mode'], 8) & 0o777)
        with os.fdopen(fd, 'wb') as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        pins[item['path']] = sha(data)
        report['new_files'].append({k: item[k] for k in ('path', 'git_sha', 'size', 'mode')} | {'sha256': sha(data)})
        save()
    rust_blobs = {}
    for entry in git('ls-tree', '-r', '-z', HEAD + ':trillionnium').split(b'\0'):
        if entry:
            attr, name = entry.split(b'\t', 1)
            mode, kind, digest = attr.decode().split()
            assert kind == 'blob'
            rust_blobs['trillionnium/' + name.decode()] = {'git_sha': digest, 'mode': mode}
    assert len(rust_blobs) == 1718
    for target in scan['unique_targets']:
        spec = rust_blobs[target] if target.startswith('trillionnium/') else expected[target]
        assert spec['mode'] in ('100644', '100755')
        path = safe_path(target)
        data = path.read_bytes()
        assert git_sha('blob', data) == spec['git_sha'], target
        assert path.stat().st_mode & 0o111 == int(spec['mode'], 8) & 0o111, target
        report['target_git_bindings'].append({'path': target, **spec, 'size': len(data), 'sha256': sha(data)})
    assert len(pins) == 1850
    assert all(sha(safe_path(p).read_bytes()) == h for p, h in pins.items())
    assert all(sha((ROOT / p).read_bytes()) == h for p, h in receipts.items())
    report.update(result='READY_FOR_SEPARATE_AUTHORIZED_GATE', closure_ready=True,
                  original_receipts_unchanged=True, original_receipt_sha256=receipts,
                  source_sha256=pins, source_pin_count=len(pins), fixed_git_trees_verified=tree_count,
                  rust_subtree_blob_count=1718, rust_source_file_count=1639,
                  include_occurrences=1952, unique_include_targets=1788,
                  missing_targets=[], unresolved_expressions=[], lexer_failures=[],
                  include_rust_targets_outside_scanned_subtree=[],
                  scan_sha256=sha(scan_raw), packet_sha256=sha(packet_raw),
                  scope='all literal/concat-manifest lexical includes in fixed Rust subtree; no macro expansion or build success claim')
except Exception as error:
    report.update(result='MATERIALIZATION_REFUSED', error=repr(error))
finally:
    save()
    print(json.dumps({k: v for k, v in report.items() if k not in ('source_sha256', 'target_git_bindings', 'new_files')}, sort_keys=True))
    print(json.dumps({'report_path': str(OUT / 'RESULT.json'), 'report_sha256': sha((OUT / 'RESULT.json').read_bytes()),
                      'new_files_written': len(report['new_files'])}))
if not report['closure_ready']:
    raise SystemExit(1)


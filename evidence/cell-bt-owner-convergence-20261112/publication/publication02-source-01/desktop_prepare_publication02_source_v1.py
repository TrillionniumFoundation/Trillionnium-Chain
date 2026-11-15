#!/usr/bin/env python3
"""Create one full publication checkout from committed B; preserve the old scene."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import time
import traceback

OLD = Path('/home/qian-qi/work/chain-bt-owner-convergence-20261112-4a0b-publication')
ROOT = Path('/home/qian-qi/work/chain-bt-4a0b-publication02')
CONTROL = Path('/home/qian-qi/chain-bt-owner-convergence-20261112-4a0b-publication-control')
OUT = CONTROL / 'publication02-source-01'
PRESTAGE = CONTROL / 'prestage-source-01'
HEAD = '031d442dd0acb693afcfaf42f9cc4db446ba52cb'
TREE = 'a897ba4c74897a05ceb364f098b1bfe32c850213'
BRANCH = 'fix/chain-bt-owner-convergence-20261112-4a0b'
ORIGIN = 'https://github.com/TrillionniumFoundation/Trillionnium-Chain.git'
ENTRIES = 27686
BYTES = 2552660560
PHYSICAL_SHA = '418dec7ab64a0ef795f7e360ce9e6f311ae7ce6d34dafc0df73bee59ebbe0902'
PRESTAGE_SHA = '32934e747ebf16a23fddaedf5b5bff1cb1a28bf2629b77edbc47fb960a0faf5c'
FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
os.umask(0o077)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path, maximum=64 * 1024 ** 2):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        assert stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= maximum
        raw = stream.read(before.st_size + 1)
        after = os.fstat(stream.fileno())
    identity = {key: getattr(before, key) for key in FIELDS}
    assert len(raw) == before.st_size
    assert identity == {key: getattr(after, key) for key in FIELDS}
    return raw, identity


def metadata(path):
    raw, info = read(path)
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha(raw), 'stat': info}


def write_new(path, raw):
    with Path(path).open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    assert read(path)[0] == raw
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha(raw)}


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def hidden_observation(entry, tree):
    marker, name = entry[:1].decode('ascii'), entry[2:].decode('utf-8')
    relative = Path(name)
    assert not relative.is_absolute() and '..' not in relative.parts
    path = OLD / relative
    expected = tree.get(name)
    row = {'path': name, 'flag': marker, 'head': expected,
           'exists': False, 'matches_head': False}
    try:
        before = path.lstat()
        row.update(exists=True, stat_before={key: getattr(before, key) for key in FIELDS})
        assert path.parent.resolve(strict=True) == path.parent, 'old parent alias; bytes not read'
        if stat.S_ISLNK(before.st_mode):
            raw = os.fsencode(os.readlink(path))
            mode = '120000'
            row.update(actual_bytes=len(raw), actual_sha256=sha(raw),
                       actual_git_blob=hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest())
        elif stat.S_ISREG(before.st_mode):
            mode = '100755' if before.st_mode & 0o111 else '100644'
            row['actual_bytes'] = before.st_size
            # Do not read an unexpectedly large or differently sized old file.
            if expected is None or before.st_size != expected['bytes']:
                row['byte_read_skipped'] = 'not the expected HEAD path/size; old file preserved'
            else:
                assert before.st_size <= BYTES
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
                digest256 = hashlib.sha256()
                digest_git = hashlib.sha1(b'blob ' + str(before.st_size).encode() + b'\0')
                count = 0
                with os.fdopen(fd, 'rb') as stream:
                    opened = os.fstat(stream.fileno())
                    assert {key: getattr(opened, key) for key in FIELDS} == row['stat_before']
                    while block := stream.read(1024 * 1024):
                        count += len(block)
                        assert count <= before.st_size
                        digest256.update(block)
                        digest_git.update(block)
                    after_fd = os.fstat(stream.fileno())
                    assert count == before.st_size
                    assert {key: getattr(after_fd, key) for key in FIELDS} == row['stat_before']
                row.update(actual_sha256=digest256.hexdigest(), actual_git_blob=digest_git.hexdigest())
        else:
            mode = 'non-regular'
            row['byte_read_skipped'] = 'nonregular old entry preserved'
        after = path.lstat()
        row['stat_after'] = {key: getattr(after, key) for key in FIELDS}
        assert row['stat_after'] == row['stat_before']
        row['actual_git_mode'] = mode
        row['matches_head'] = bool(expected and mode == expected['mode'] and
                                   row.get('actual_bytes') == expected['bytes'] and
                                   row.get('actual_git_blob') == expected['blob'])
    except (OSError, AssertionError) as error:
        row.update(error_type=type(error).__name__, error=str(error), matches_head=False)
    return row


def main():
    assert not ROOT.exists() and not ROOT.is_symlink()
    assert not OUT.exists() and not OUT.is_symlink()
    assert CONTROL.is_dir() and not CONTROL.is_symlink()
    OUT.mkdir(mode=0o700)
    sync_directory(CONTROL)
    environment = {**os.environ, 'GIT_OPTIONAL_LOCKS': '0', 'GIT_TERMINAL_PROMPT': '0',
                   'GIT_PAGER': 'cat', 'PYTHONDONTWRITEBYTECODE': '1'}
    for name in ('GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_COMMON_DIR',
                 'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES'):
        assert not environment.get(name), ('unexpected repository override', name)
    new_config = {'core.ignoreStat': 'false', 'core.sparseCheckout': 'false',
                  'core.sparseCheckoutCone': 'false', 'index.sparse': 'false',
                  'core.splitIndex': 'false', 'core.fsmonitor': 'false'}
    report = {'schema': 'trnm.bt-independent-publication02-source-preparation.v1',
              'source': HEAD, 'tree': TREE, 'old_root': str(OLD), 'root': str(ROOT),
              'observer_sha256': sha(read(Path(__file__))[0]),
              'commands': [], 'completed': False, 'passed': False,
              'old_worktree_or_index_modified_by_this_helper': False,
              'new_local_configuration': new_config, 'github_write_performed': False,
              'branch_pushed': False, 'production_activation': False,
              'source_guard_modified': False,
              'configuration_scope': 'Fresh independent checkout only; original full source guard remains mandatory'}

    def save():
        pending = OUT / 'summary.pending.json'
        with pending.open('wb') as stream:
            stream.write(encoded(report))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(pending, OUT / 'summary.json')
        sync_directory(OUT)

    def run(name, argv, cwd, limit=60, allowed=(0,)):
        item = {'name': name, 'argv': argv, 'cwd': str(cwd), 'timeout_seconds': limit,
                'status': 'running', 'timed_out': False, 'started_unix_ns': time.time_ns()}
        report['commands'].append(item)
        save()
        stdout, stderr = OUT / (name + '.stdout'), OUT / (name + '.stderr')
        started = time.monotonic()
        with stdout.open('xb') as out, stderr.open('xb') as err:
            try:
                result = subprocess.run(argv, cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
                                        stdout=out, stderr=err, timeout=limit)
                code = result.returncode
            except subprocess.TimeoutExpired:
                code = None
                item['timed_out'] = True
        item.update(status='completed', exit_code=code, elapsed_seconds=time.monotonic() - started,
                    stdout=metadata(stdout), stderr=metadata(stderr))
        save()
        print(json.dumps({'stage': name, 'exit_code': code, 'timed_out': item['timed_out']}, sort_keys=True), flush=True)
        assert code in allowed and not item['timed_out'], item
        return read(stdout)[0]

    old_index = old_index_pin = old_refs = old_flags = None
    hidden_before = head_tree = None
    prior_pins = []
    save()
    try:
        # Copy the five original failed-prestage files exactly, without rewriting them.
        prior_raw, _ = read(PRESTAGE / 'report.json')
        assert len(prior_raw) == 1926 and sha(prior_raw) == PRESTAGE_SHA
        prior = json.loads(prior_raw)
        assert prior['source'] == HEAD and prior['tree'] == TREE and prior['completed'] is True
        assert prior['passed'] is False and prior['github_write_performed'] is False
        prior_out = OUT / 'prior-prestage'
        prior_out.mkdir(mode=0o700)
        for path, checksum, size in [(PRESTAGE / 'report.json', PRESTAGE_SHA, 1926)] + [
                (Path(c[channel]['path']), c[channel]['sha256'], c[channel]['bytes'])
                for c in prior['commands'] for channel in ('stdout', 'stderr')]:
            assert path.parent == PRESTAGE
            raw, _ = read(path)
            assert len(raw) == size and sha(raw) == checksum
            copied = write_new(prior_out / path.name, raw)
            prior_pins.append({'original_path': str(path), 'bytes': size, 'sha256': checksum,
                               'copy': copied})
        assert len(prior_pins) == 5
        report['preserved_prestage_failure'] = prior_pins
        assert run('old-head', ['/usr/bin/git', 'rev-parse', 'HEAD'], OLD).decode().strip() == HEAD
        assert run('old-tree', ['/usr/bin/git', 'rev-parse', 'HEAD^{tree}'], OLD).decode().strip() == TREE
        assert run('old-task-ref', ['/usr/bin/git', 'rev-parse', 'refs/heads/' + BRANCH], OLD).decode().strip() == HEAD
        run('old-status-observation', ['/usr/bin/git', 'status', '--porcelain=v1', '--untracked-files=all'], OLD)
        old_refs = run('old-refs-before', ['/usr/bin/git', 'for-each-ref', '--format=%(refname) %(objectname)'], OLD)
        index_name = run('old-index-path', ['/usr/bin/git', 'rev-parse', '--git-path', 'index'], OLD).decode().strip()
        old_index = Path(index_name) if Path(index_name).is_absolute() else OLD / index_name
        old_index_pin = metadata(old_index)
        report['old_index_before'] = old_index_pin
        report['old_index_snapshot_before'] = write_new(OUT / 'old-index.before', read(old_index)[0])
        old_flags = run('old-index-flags-before', ['/usr/bin/git', 'ls-files', '-v', '-z'], OLD)
        run('old-relevant-config', ['/usr/bin/git', 'config', '--show-origin', '--show-scope',
             '--get-regexp', r'^(core\.(ignorestat|ignorecase|trustctime|checkstat|fsmonitor|splitindex|sparsecheckout|untrackedcache)|index\.sparse|extensions\.)'], OLD, allowed=(0, 1))
        tree_raw = run('old-head-tree-inventory', ['/usr/bin/git', 'ls-tree', '-r', '-l', '-z', HEAD], OLD)
        head_tree = {}
        for line in tree_raw.split(b'\0'):
            if not line:
                continue
            left, path_raw = line.split(b'\t', 1)
            mode, kind, blob, size = left.split()
            assert kind == b'blob' and size.isdigit()
            name = path_raw.decode('utf-8')
            assert name not in head_tree
            head_tree[name] = {'mode': mode.decode(), 'blob': blob.decode(), 'bytes': int(size)}
        assert len(head_tree) == ENTRIES and sum(row['bytes'] for row in head_tree.values()) == BYTES
        hidden_entries = [line for line in old_flags.split(b'\0') if line and (line[:1] == b'S' or line[:1].islower())]
        hidden_before = [hidden_observation(line, head_tree) for line in hidden_entries]
        report['old_hidden_before'] = write_new(OUT / 'old-hidden-observations.before.json', encoded(hidden_before))
        report['old_hidden_entry_count'] = len(hidden_before)
        report['old_hidden_missing_count'] = sum(row.get('error_type') == 'FileNotFoundError' for row in hidden_before)
        report['old_hidden_present_count'] = sum(row['exists'] for row in hidden_before)
        report['old_hidden_matching_head_count'] = sum(row['matches_head'] for row in hidden_before)
        report['old_hidden_cause_or_writer_identified'] = False
        save()

        # Capacity is checked before allocating the new checkout. Nothing is deleted.
        object_name = run('old-object-directory', ['/usr/bin/git', 'rev-parse', '--git-path', 'objects'], OLD).decode().strip()
        objects = Path(object_name) if Path(object_name).is_absolute() else OLD / object_name
        assert not (objects / 'info/alternates').exists() and not (objects / 'info/http-alternates').exists()
        count_raw = run('old-object-storage', ['/usr/bin/git', 'count-objects', '-v'], OLD)
        counts = dict(line.split(': ', 1) for line in count_raw.decode().splitlines() if ': ' in line)
        object_bytes = (int(counts['size']) + int(counts['size-pack'])) * 1024
        free = shutil.disk_usage(ROOT.parent).free
        required = BYTES + 2 * object_bytes + 1024 ** 3
        report['disk_admission'] = {'target_parent': str(ROOT.parent), 'free_bytes': free,
                                    'expected_checkout_bytes': BYTES, 'old_object_storage_bytes': object_bytes,
                                    'required_free_bytes': required,
                                    'estimate': 'full checkout plus two source-object storage copies plus 1GiB reserve',
                                    'old_files_deleted': False}
        save()
        assert free >= required, report['disk_admission']

        clone = ['/usr/bin/git', 'clone', '--no-local', '--no-hardlinks', '--no-checkout',
                 '--single-branch', '--no-tags', '--branch', BRANCH]
        for key, value in new_config.items():
            clone.extend(['--config', key + '=' + value])
        clone.extend([str(OLD), str(ROOT)])
        run('independent-object-clone', clone, ROOT.parent, 1200)
        assert not (ROOT / '.git/objects/info/alternates').exists()
        assert not (ROOT / '.git/objects/info/http-alternates').exists()
        assert not (ROOT / '.git/commondir').exists()
        assert run('new-git-directory', ['/usr/bin/git', 'rev-parse', '--absolute-git-dir'], ROOT).decode().strip() == str(ROOT / '.git')
        assert run('new-shared-index-before', ['/usr/bin/git', 'rev-parse', '--shared-index-path'], ROOT).strip() == b''
        assert run('new-task-ref', ['/usr/bin/git', 'rev-parse', 'refs/heads/' + BRANCH], ROOT).decode().strip() == HEAD
        assert run('new-tree-before-checkout', ['/usr/bin/git', 'rev-parse', HEAD + '^{tree}'], ROOT).decode().strip() == TREE
        run('canonical-origin', ['/usr/bin/git', 'remote', 'set-url', 'origin', ORIGIN], ROOT)
        run('full-checkout', ['/usr/bin/git', 'checkout', BRANCH], ROOT, 300)
        assert run('new-head', ['/usr/bin/git', 'rev-parse', 'HEAD'], ROOT).decode().strip() == HEAD
        assert run('new-branch', ['/usr/bin/git', 'branch', '--show-current'], ROOT).decode().strip() == BRANCH
        assert run('new-origin', ['/usr/bin/git', 'remote', 'get-url', 'origin'], ROOT).decode().strip() == ORIGIN
        assert run('new-push-urls', ['/usr/bin/git', 'remote', 'get-url', '--push', '--all', 'origin'], ROOT).decode().splitlines() == [ORIGIN]
        for ordinal, (key, value) in enumerate(new_config.items()):
            assert run('new-local-config-' + str(ordinal), ['/usr/bin/git', 'config', '--local', '--get', key], ROOT).decode().strip() == value
        flags = run('new-index-flags', ['/usr/bin/git', 'ls-files', '-v', '-z'], ROOT)
        entries = [line for line in flags.split(b'\0') if line]
        assert len(entries) == ENTRIES and all(line[:1] == b'H' for line in entries)
        verifier = ROOT / 'scripts/ci/verify_ci_source.py'
        assert sha(read(verifier)[0]) == '0ddfd07719eae98913348c82b06d3e4522d721c353d9b01d6deac0dfda619946'
        run('project-preflight', ['/bin/bash', 'scripts/project-preflight.sh'], ROOT)
        physical = run('full-physical-source', ['/usr/bin/python3', '-B', 'scripts/ci/verify_ci_source.py',
                       '--kind', 'head', '--expected-head', HEAD], ROOT, 300)
        assert len(physical) == 423 and sha(physical) == PHYSICAL_SHA
        parsed = json.loads(physical)
        assert parsed['tracked_worktree_verified'] is True and parsed['tested_tree'] == TREE
        assert parsed['tracked_entries'] == ENTRIES and parsed['tracked_bytes'] == BYTES
        assert run('new-status-after', ['/usr/bin/git', 'status', '--porcelain=v1', '--untracked-files=all'], ROOT) == b''
        assert run('new-index-flags-after', ['/usr/bin/git', 'ls-files', '-v', '-z'], ROOT) == flags
        assert run('new-shared-index-after', ['/usr/bin/git', 'rev-parse', '--shared-index-path'], ROOT).strip() == b''
        assert not list((ROOT / '.git').glob('sharedindex.*'))
        report['full_physical_source'] = parsed
        report['passed'] = True
    except BaseException as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
        report['traceback'] = traceback.format_exc()
    finally:
        # Preserve and reconcile the old scene even if clone/checkout/gates fail.
        try:
            if old_index is not None and old_index_pin is not None:
                report['old_index_after'] = metadata(old_index)
                assert report['old_index_after'] == old_index_pin
                report['old_index_snapshot_after'] = write_new(OUT / 'old-index.after', read(old_index)[0])
            if old_refs is not None:
                assert run('old-refs-after', ['/usr/bin/git', 'for-each-ref', '--format=%(refname) %(objectname)'], OLD) == old_refs
                assert run('old-head-after', ['/usr/bin/git', 'rev-parse', 'HEAD'], OLD).decode().strip() == HEAD
            if old_flags is not None:
                assert run('old-index-flags-after', ['/usr/bin/git', 'ls-files', '-v', '-z'], OLD) == old_flags
            if hidden_before is not None:
                observed_after = [hidden_observation(line, head_tree) for line in old_flags.split(b'\0')
                                  if line and (line[:1] == b'S' or line[:1].islower())]
                report['old_hidden_after'] = write_new(OUT / 'old-hidden-observations.after.json', encoded(observed_after))
                assert observed_after == hidden_before
            for pin in prior_pins:
                raw, _ = read(pin['original_path'])
                assert len(raw) == pin['bytes'] and sha(raw) == pin['sha256']
            report['old_head_refs_index_flags_hidden_observations_and_failure_originals_unchanged'] = (
                all(value is not None for value in (old_index, old_index_pin, old_refs,
                                                    old_flags, hidden_before, head_tree))
                and len(prior_pins) == 5)
        except BaseException as error:
            report['end_error'] = type(error).__name__ + ': ' + str(error)
            report['passed'] = False
        report['completed'] = True
        report['completed_unix_ns'] = time.time_ns()
        save()
        print(json.dumps({'completed': True, 'passed': report['passed'], 'output': str(OUT),
                          'root': str(ROOT), 'source': HEAD,
                          'github_write_performed': False}, sort_keys=True), flush=True)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())

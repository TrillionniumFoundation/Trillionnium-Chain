#!/usr/bin/env python3
"""Package immutable test observations without rewriting bytes or link targets."""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
import time

HERE = Path(__file__).resolve().parent


def inventory(root):
    rows = []
    for path in [root, *sorted(root.rglob('*'))]:
        info = path.lstat()
        row = {'member': str(path.relative_to(HERE)), 'mode': oct(stat.S_IMODE(info.st_mode)),
               'raw_mode': info.st_mode, 'uid': info.st_uid, 'gid': info.st_gid,
               'mtime_ns': info.st_mtime_ns, 'ctime_ns': info.st_ctime_ns,
               'filesystem_size': info.st_size, 'device': info.st_dev,
               'inode': info.st_ino, 'observed_nlink': info.st_nlink}
        if stat.S_ISREG(info.st_mode):
            row.update(kind='file', bytes=info.st_size,
                       sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        elif stat.S_ISDIR(info.st_mode):
            row.update(kind='directory', bytes=0)
        elif stat.S_ISLNK(info.st_mode):
            target = os.readlink(path)
            row.update(kind='symlink', bytes=len(os.fsencode(target)), target=target,
                       sha256=hashlib.sha256(os.fsencode(target)).hexdigest())
        else:
            raise ValueError('unsupported evidence file type: ' + str(path))
        rows.append(row)
    return rows


def main(name, label):
    assert name in ['native-01', 'native-02', 'native-03', 'native-initial',
                    'isolated-final-synced', 'settled-success']
    root = HERE / ('native-03' if name == 'settled-success' else name)
    archive = HERE / (label + '.tar.gz')
    manifest = HERE / (label + '-members.json')
    assert not archive.exists() and not manifest.exists()
    before_all = inventory(root)
    before = before_all
    scoped = name == 'settled-success'
    if scoped:
        summary = json.loads((HERE / 'epoch-window-summary.json').read_text())
        assert summary['passed'] and not summary['full_native_suite_passed']
        cases = [row['case'] for row in summary['cases']]
        assert len(cases) == 7 and len(set(cases)) == 7
        prefixes = ['native-03/artifacts/' + case for case in cases]
        before = [row for row in before_all if row['member'] in ['native-03', 'native-03/artifacts']
                  or any(row['member'] == prefix or row['member'].startswith(prefix + '/')
                         for prefix in prefixes)]
    with tarfile.open(archive, 'w:gz', format=tarfile.PAX_FORMAT, dereference=False) as tar:
        for row in before:
            path = HERE / row['member']
            info = tar.gettarinfo(str(path), arcname=row['member'])
            seconds, remainder = divmod(row['mtime_ns'], 1_000_000_000)
            info.pax_headers['mtime'] = f'{seconds}.{remainder:09d}'
            if info.isfile():
                with path.open('rb') as stream:
                    tar.addfile(info, stream)
            else:
                tar.addfile(info)
    after = inventory(root)
    assert before_all == after, 'evidence changed during archival'
    with tarfile.open(archive, 'r:gz') as tar:
        members = {member.name: member for member in tar}
        for row in before:
            member = members[row['member']]
            assert member.mode == int(row['mode'], 8)
            assert member.uid == row['uid'] and member.gid == row['gid']
            if row['kind'] == 'file':
                with tar.extractfile(member) as stream:
                    assert hashlib.file_digest(stream, 'sha256').hexdigest() == row['sha256']
            if row['kind'] == 'symlink':
                assert member.issym() and member.linkname == row['target']
    result = {'schema': 'history-native-raw-archive-members-v1', 'source_directory': str(root),
              'archive': archive.name, 'archive_bytes': archive.stat().st_size,
              'archive_sha256': hashlib.sha256(archive.read_bytes()).hexdigest(),
              'captured_unix': time.time(), 'raw_bytes_rewritten': False,
              'permissions_ownership_mtime_and_link_targets_preserved': True,
              'member_readback_verified': True, 'source_unchanged_during_archive': True,
              'fixture_data_only': True, 'production_credentials': False,
              'scope': ('seven new recovery cases in native-03 only; full native-03 batch failed'
                        if scoped else 'entire original observation directory, including failures'),
              'full_native_suite_passed': False,
              'members': before}
    manifest.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps({k: v for k, v in result.items() if k != 'members'}))


if __name__ == '__main__':
    main(*sys.argv[1:])

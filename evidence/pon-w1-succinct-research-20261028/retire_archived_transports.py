#!/usr/bin/env python3
"""Retire only five byte-verified, remotely archived transport copies."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import time

ROOT = Path('/workspace/scratch/bb9b841c1d43')
READBACK = ROOT / 'publication/w1-complete-remote-byte-readback.json'
TARGETS = {
    'assembly-original.zip': ROOT / 'w1-observation/a54-run-40608715148/assembly.zip',
    'shard0-original.zip': ROOT / 'w1-observation/a54-run-40608715148/shard0.zip',
    'shard1-original.zip': ROOT / 'w1-observation/a54-run-40608715148/shard1.zip',
    'solver-v3-x86_64-original.zip': ROOT / 'solver-v3-readback/x86_64.zip',
    'solver-v3-aarch64-original.zip': ROOT / 'solver-v3-readback/aarch64.zip',
}
HEAD = '303afe7a4581e67117bff135eed5892232aabb70'

def material(path):
    before = path.lstat()
    assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1
    h = hashlib.sha256()
    with path.open('rb') as stream:
        while chunk := stream.read(1024 * 1024):
            h.update(chunk)
    after = path.lstat()
    assert (before.st_ino, before.st_dev, before.st_size, before.st_mtime_ns, before.st_ctime_ns) == (
        after.st_ino, after.st_dev, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
    return {'path': str(path), 'bytes': before.st_size, 'sha256': h.hexdigest(),
            'device': before.st_dev, 'inode': before.st_ino,
            'mtime_ns': before.st_mtime_ns, 'ctime_ns': before.st_ctime_ns,
            'allocated_bytes': before.st_blocks * 512}

def pid_start(pid):
    return (Path('/proc') / str(pid) / 'stat').read_text().rsplit(')', 1)[1].split()[19]

def scan():
    before = sorted(int(p.name) for p in Path('/proc').iterdir() if p.name.isdecimal())
    paths = set(map(str, TARGETS.values()))
    hits, errors, identities = [], [], {}
    fds = maps = 0
    for pid in before:
        proc = Path('/proc') / str(pid)
        try:
            identities[pid] = pid_start(pid)
            with os.scandir(proc / 'fd') as entries:
                for fd in entries:
                    name = os.readlink(fd.path)
                    fds += 1
                    if name.removesuffix(' (deleted)') in paths:
                        hits.append({'pid': pid, 'kind': 'fd', 'path': name})
            for line in (proc / 'maps').read_text().splitlines():
                fields = line.split(maxsplit=5)
                if len(fields) == 6 and fields[5].removesuffix(' (deleted)') in paths:
                    hits.append({'pid': pid, 'kind': 'maps', 'path': fields[5]})
            maps += 1
            if pid_start(pid) != identities[pid]:
                errors.append({'pid': pid, 'kind': 'identity-changed'})
        except OSError as error:
            errors.append({'pid': pid, 'kind': type(error).__name__, 'errno': error.errno})
    after = sorted(int(p.name) for p in Path('/proc').iterdir() if p.name.isdecimal())
    if before != after:
        errors.append({'kind': 'process-set-changed', 'before': before, 'after': after})
    for pid in sorted(set(before) & set(after)):
        try:
            if str(identities.get(pid)) != pid_start(pid):
                errors.append({'pid': pid, 'kind': 'final-identity-changed'})
        except OSError as error:
            errors.append({'pid': pid, 'kind': type(error).__name__, 'errno': error.errno})
    return {'identities': identities, 'processes': len(before), 'fds': fds,
            'maps': maps, 'hits': hits, 'errors': errors, 'strict_ok': not hits and not errors}

def save(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')

def main():
    p = argparse.ArgumentParser()
    p.add_argument('mode', choices=('audit', 'retire'))
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--audit', type=Path)
    args = p.parse_args()
    raw = READBACK.read_bytes()
    remote = json.loads(raw)
    assert remote['status'] == 'PASS' and remote['head'] == HEAD
    objects = {x['name']: x for x in remote['objects']}
    record = {'schema': 'w1-archived-transport-retirement-v1', 'mode': args.mode,
              'remote_head': HEAD, 'remote_readback_sha256': hashlib.sha256(raw).hexdigest(),
              'remote_readback': str(READBACK), 'wall_time_unix': time.time(),
              'removed': [], 'receipt_and_unique_extracted_files_preserved': True,
              'strict_febf_unpublished_artifacts_preserved': True,
              'recovery': 'Fetch every listed part from the exact remote commit in listed order; '
                          'check each part SHA-256 and Git blob SHA-1, concatenate, '
                          'then verify whole object byte length and SHA-256.'}
    materials = []
    for name, path in TARGETS.items():
        item = material(path)
        expected = objects[name]
        assert item['bytes'] == expected['bytes'] and item['sha256'] == expected['sha256']
        item['remote_name'] = name
        item['remote_parts'] = expected['parts']
        materials.append(item)
    record['materials'] = materials
    if args.mode == 'audit':
        record['proc_audit'] = scan()
        save(args.out, record)
        print(json.dumps({'mode': 'audit', **record['proc_audit']}))
        return 0 if record['proc_audit']['strict_ok'] else 1
    audited = json.loads(args.audit.read_text())
    assert audited['mode'] == 'audit' and audited['proc_audit']['strict_ok'] is True
    assert audited['materials'] == materials
    assert audited['remote_readback_sha256'] == record['remote_readback_sha256']
    assert 0 <= time.time() - audited['wall_time_unix'] < 120
    record['read_only_audit'] = str(args.audit)
    record['read_only_audit_sha256'] = hashlib.sha256(args.audit.read_bytes()).hexdigest()
    before = os.statvfs(ROOT)
    record['available_bytes_before'] = before.f_bavail * before.f_frsize
    for item in materials:
        path = Path(item['path'])
        assert material(path) == {k: v for k, v in item.items() if k not in ('remote_name', 'remote_parts')}
        path.unlink()
        assert not path.exists()
        record['removed'].append(item['path'])
    after = os.statvfs(ROOT)
    record['available_bytes_after'] = after.f_bavail * after.f_frsize
    record['observed_net_free_bytes'] = record['available_bytes_after'] - record['available_bytes_before']
    record['retired_logical_bytes'] = sum(x['bytes'] for x in materials)
    record['retired_allocated_bytes'] = sum(x['allocated_bytes'] for x in materials)
    save(args.out, record)
    print(json.dumps({k: v for k, v in record.items() if k not in ('materials',)}))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())

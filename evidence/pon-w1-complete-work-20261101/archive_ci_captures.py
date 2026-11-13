#!/usr/bin/env python3
"""Preserve all extracted CI artifact bytes; original ZIP identity stays explicit."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import tarfile
import zipfile

def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('workspace', type=Path)
    parser.add_argument('run', type=int)
    parser.add_argument('metadata', type=Path)
    parser.add_argument('destination', type=Path)
    args = parser.parse_args()
    meta = json.loads(args.metadata.read_text())
    artifacts = meta['artifacts']
    args.destination.mkdir(parents=True, exist_ok=True)
    def archive(a):
        original = args.workspace / 'ci-downloads' / f"run-{args.run}-artifact-{a['id']}.zip"
        actual = digest(original)
        assert actual == a['digest'].removeprefix('sha256:')
        capture = args.workspace / 'ci-captures' / f'run-{args.run}' / str(a['id'])
        members = []
        with zipfile.ZipFile(original) as z:
            for member in z.infolist():
                if member.is_dir():
                    continue
                rel = Path(member.filename)
                assert not rel.is_absolute() and '..' not in rel.parts
                path = capture / rel
                assert path.is_file() and not path.is_symlink()
                h = hashlib.sha256(z.read(member)).hexdigest()
                assert h == digest(path) and path.stat().st_size == member.file_size
                members.append({'path': rel.as_posix(), 'bytes': member.file_size, 'sha256': h})
        destination = args.destination / f"artifact-{a['id']}-contents.tar.xz"
        with tarfile.open(destination, 'w:xz', preset=6) as tar:
            for member in sorted(members, key=lambda m: m['path']):
                path = capture / member['path']
                info = tar.gettarinfo(str(path), arcname=member['path'])
                info.uid = info.gid = info.mtime = 0
                info.uname = info.gname = ''
                with path.open('rb') as stream:
                    tar.addfile(info, stream)
        # Independently read each archived byte before permitting publication.
        with tarfile.open(destination, 'r:xz') as tar:
            names = set(tar.getnames())
            assert names == {m['path'] for m in members}
            for member in members:
                assert hashlib.sha256(tar.extractfile(member['path']).read()).hexdigest() == member['sha256']
        report = dict(artifact_id=a['id'], name=a['name'], original_zip_sha256=actual,
            original_zip_bytes=original.stat().st_size, capture_archive=destination.name,
            capture_archive_sha256=digest(destination), capture_archive_bytes=destination.stat().st_size,
            complete_extracted_contents=True, original_zip_container_included=False, members=members)
        print(json.dumps({'artifact': a['id'], 'members': len(members), 'archive_bytes': destination.stat().st_size}), flush=True)
        return report
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(archive, artifacts))
    report = {'schema': 'pon-complete-ci-artifact-contents-v1', 'run_id': args.run,
        'all_original_zip_digests_verified': True, 'all_extracted_and_rearchived_bytes_verified': True,
        'artifacts': results}
    (args.destination / 'CAPTURE_INDEX.json').write_text(json.dumps(report, indent=2) + '\n')

if __name__ == '__main__':
    main()

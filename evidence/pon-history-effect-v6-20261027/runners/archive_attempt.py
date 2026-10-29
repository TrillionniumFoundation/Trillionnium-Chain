#!/usr/bin/env python3
"""Retain completed raw observations without embedding reproducible executables."""
import gzip
import hashlib
import io
import json
from pathlib import Path
import shutil
import sys
import tarfile

SOURCE = Path(__file__).resolve().parent
OUT = SOURCE.parent / 'history-v6/evidence/pon-history-effect-v6-20261027/raw'
OUT.mkdir(parents=True, exist_ok=True)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


for name in sys.argv[1:]:
    directory = SOURCE / name
    assert directory.is_dir() and directory.parent == SOURCE
    target = OUT / (name + '.tar.gz')
    manifest = OUT / (name + '.manifest.json')
    assert not target.exists() and not manifest.exists(), 'immutable evidence already retained'
    rows = []
    binaries = []
    with target.open('xb') as file:
        with gzip.GzipFile(filename='', mode='wb', fileobj=file, mtime=0) as zipped:
            with tarfile.open(fileobj=zipped, mode='w|') as archive:
                for path in sorted(directory.rglob('*')):
                    assert not path.is_symlink(), f'unexpected symlink {path}'
                    if not path.is_file():
                        continue
                    raw = path.read_bytes()
                    row = {'path':str(path.relative_to(directory)), 'bytes':len(raw),
                           'sha256':digest(raw)}
                    if path.name == 'native-test-snapshot.bin':
                        row.update(retained_outside_repository=str(path),
                                   reason='unique executed binary retained locally; archive binds its digest')
                        binaries.append(row)
                        continue
                    info = tarfile.TarInfo(row['path'])
                    info.size = len(raw)
                    info.mode = path.stat().st_mode & 0o777
                    info.mtime = 0
                    archive.addfile(info, io.BytesIO(raw))
                    rows.append(row)
    with tarfile.open(target, 'r:gz') as archive:
        for row in rows:
            raw = archive.extractfile(row['path']).read()
            assert len(raw) == row['bytes'] and digest(raw) == row['sha256']
    record = {'schema':'history-v6-completed-observation-archive-v1',
              'source_directory':str(directory), 'archive':target.name,
              'archive_bytes':target.stat().st_size, 'archive_sha256':digest(target.read_bytes()),
              'raw_files':rows, 'executed_binaries_retained_outside_repository':binaries,
              'all_archived_raw_bytes_read_back_verified':True,
              'failed_observations_reclassified':False}
    manifest.write_text(json.dumps(record, sort_keys=True, indent=2) + '\n')
    print(json.dumps({'name':name, 'archive_bytes':record['archive_bytes'],
                      'raw_files':len(rows), 'unique_binaries':len(binaries)}), flush=True)

#!/usr/bin/env python3
"""Seal diagnostic source, executables and retained measurement receipts."""
import hashlib
import json
from pathlib import Path
import tarfile

OUT = Path(__file__).resolve().parent

def sha(data):
    return hashlib.sha256(data).hexdigest()

def main():
    manifest = json.loads((OUT / 'build-manifest.json').read_text())
    archive = OUT / 'selected-source-and-executables.tar.xz'
    with tarfile.open(archive, 'w:xz', preset=6) as tar:
        for variant, entry in manifest['variants'].items():
            harness = Path(entry['harness'])
            for path in sorted((harness / 'src').rglob('*')):
                if path.is_file():
                    tar.add(path, arcname=variant + '/' + str(path.relative_to(harness)), recursive=False)
            for filename in ['Cargo.toml', 'Cargo.lock']:
                tar.add(harness / filename, arcname=variant + '/' + filename, recursive=False)
            elf = Path(entry['elf'])
            assert sha(elf.read_bytes()) == entry['elf_sha256']
            tar.add(elf, arcname=variant + '/pon-cache-benchmark.elf', recursive=False)
    commands = []
    for path in sorted(OUT.glob('*.receipt.json')):
        receipt = json.loads(path.read_text())
        serialized = json.dumps(receipt['command'], separators=(',', ':'), ensure_ascii=False).encode()
        commands.append({'receipt': path.name, 'command': receipt['command'],
                         'command_encoding': 'UTF-8 JSON array; compact separators; unescaped Unicode',
                         'command_sha256': sha(serialized), 'exit_code': receipt['exit_code']})
    members = []
    with tarfile.open(archive, 'r:xz') as tar:
        for info in tar.getmembers():
            assert info.isfile() and not info.name.startswith('/') and '..' not in Path(info.name).parts
            data = tar.extractfile(info).read()
            members.append({'path': info.name, 'bytes': len(data), 'sha256': sha(data)})
    index = {'schema': 'pon-cache-diagnostic-file-index-v1', 'commands': commands,
             'archive': {'path': archive.name, 'bytes': archive.stat().st_size,
                         'sha256': sha(archive.read_bytes()), 'members': members},
             'files': []}
    for path in sorted(OUT.iterdir()):
        if path.is_file() and path.name != 'INDEX.json':
            data = path.read_bytes()
            index['files'].append({'path': path.name, 'bytes': len(data), 'sha256': sha(data)})
    (OUT / 'INDEX.json').write_text(json.dumps(index, indent=2) + '\n')
    print(json.dumps({'files': len(index['files']), 'archive_members': len(members),
                      'archive_bytes': archive.stat().st_size, 'archive_sha256': index['archive']['sha256']}))

if __name__ == '__main__':
    main()

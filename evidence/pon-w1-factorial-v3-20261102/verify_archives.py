#!/usr/bin/env python3
"""Verify retained archive parts and every member without extracting or executing."""
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile


def require(value, message):
    if not value:
        raise ValueError(message)


def main():
    root = Path(__file__).resolve().parent
    index = json.loads((root / 'archive-index.json').read_text())
    require(index['schema'] == 'pon-w1-factorial-archive-index-v1', 'index schema')
    for archive in index['archives']:
        whole = hashlib.sha256()
        total = 0
        with tempfile.TemporaryFile() as assembled:
            for part in archive['parts']:
                name = part['name']
                require(Path(name).name == name and name not in ('.', '..'), 'part path')
                h = hashlib.sha256()
                blob = hashlib.sha1(f"blob {part['bytes']}\0".encode())
                count = 0
                with (root / name).open('rb') as source:
                    for block in iter(lambda: source.read(1024 * 1024), b''):
                        count += len(block)
                        h.update(block)
                        blob.update(block)
                        whole.update(block)
                        assembled.write(block)
                require(count == part['bytes'] and h.hexdigest() == part['sha256'], name)
                require(blob.hexdigest() == part['git_blob'], name + ': Git blob')
                total += count
            require(total == archive['archive_bytes'], 'archive length')
            require(whole.hexdigest() == archive['sha256'], 'archive digest')
            assembled.seek(0)
            process = subprocess.Popen(['zstd', '-q', '-dc'], stdin=assembled,
                                       stdout=subprocess.PIPE)
            seen = set()
            try:
                with tarfile.open(fileobj=process.stdout, mode='r|') as contents:
                    for member in contents:
                        require(member.isfile() and member.name in archive['entries'], 'member identity')
                        require(member.name not in seen, 'duplicate member')
                        expected = archive['entries'][member.name]
                        h = hashlib.sha256()
                        count = 0
                        stream = contents.extractfile(member)
                        for block in iter(lambda: stream.read(1024 * 1024), b''):
                            h.update(block)
                            count += len(block)
                        require(count == expected['bytes'] and h.hexdigest() == expected['sha256'],
                                member.name + ': retained bytes')
                        seen.add(member.name)
                # Consume the tar padding so a decoder cannot block on its pipe.
                while process.stdout.read(1024 * 1024):
                    pass
                require(process.wait() == 0, 'zstd decode')
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.wait()
                process.stdout.close()
            require(seen == set(archive['entries']), 'complete member set')
        print(json.dumps({'archive': archive['archive'], 'members': len(seen),
                          'bytes': total, 'byte_integrity': 'PASS'}, sort_keys=True))
    print('Byte checks only: no W1 replay, clock authentication, cost lower bound or qualification.')


if __name__ == '__main__':
    main()

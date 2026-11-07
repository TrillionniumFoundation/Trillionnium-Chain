"""Create-only evidence archive with unchanged member bytes and full readback."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import stat
import tarfile


def capture(source, destination, prefix):
    source, destination = Path(source).resolve(), Path(destination).resolve()
    if source == destination or source in destination.parents:
        raise ValueError('ARCHIVE_MUST_BE_OUTSIDE_INPUT')
    if not prefix or '/' in prefix or prefix in ('.', '..'):
        raise ValueError('SINGLE_COMPONENT_PREFIX_REQUIRED')
    destination.parent.mkdir(parents=True, exist_ok=True)
    members = []
    with destination.open('xb') as stream:
        with gzip.GzipFile(filename='', mode='wb', fileobj=stream, mtime=0, compresslevel=9) as zipped:
            with tarfile.open(fileobj=zipped, mode='w|', format=tarfile.PAX_FORMAT) as archive:
                for path in sorted(source.rglob('*')):
                    if path.is_dir() and not path.is_symlink():
                        continue
                    before = path.lstat()
                    if not stat.S_ISREG(before.st_mode):
                        raise ValueError('ONLY_REGULAR_CAPTURE_MEMBERS: ' + str(path))
                    raw = path.read_bytes()
                    after = path.lstat()
                    attributes = ('st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_ino', 'st_dev')
                    if any(getattr(before, key) != getattr(after, key) for key in attributes):
                        raise ValueError('MEMBER_CHANGED: ' + str(path))
                    name = prefix + '/' + path.relative_to(source).as_posix()
                    entry = tarfile.TarInfo(name)
                    entry.size, entry.mode = len(raw), stat.S_IMODE(before.st_mode)
                    entry.mtime = entry.uid = entry.gid = 0
                    entry.uname = entry.gname = ''
                    archive.addfile(entry, io.BytesIO(raw))
                    members.append(dict(path=name, bytes=len(raw),
                        sha256=hashlib.sha256(raw).hexdigest(), mode=oct(entry.mode)))
    with tarfile.open(destination, 'r:gz') as archive:
        entries = archive.getmembers()
        if len(entries) != len(members):
            raise ValueError('MEMBER_COUNT')
        for entry, expected in zip(entries, members):
            raw = archive.extractfile(entry).read()
            if (entry.name != expected['path'] or len(raw) != expected['bytes']
                    or hashlib.sha256(raw).hexdigest() != expected['sha256']
                    or oct(entry.mode) != expected['mode']):
                raise ValueError('MEMBER_READBACK: ' + entry.name)
    receipt = dict(schema='pon-evidence-archive-members-v0', archive=destination.name,
        archive_sha256=hashlib.sha256(destination.read_bytes()).hexdigest(),
        archive_bytes=destination.stat().st_size, members=members,
        member_count=len(members), payload_bytes=sum(row['bytes'] for row in members),
        readback_verified=True, container_metadata_normalized=True, member_bytes_unchanged=True)
    with destination.with_name(destination.name + '.members.json').open('x') as stream:
        json.dump(receipt, stream, sort_keys=True, indent=2)
        stream.write('\n')
    print(json.dumps({key: value for key, value in receipt.items() if key != 'members'}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('destination', type=Path)
    parser.add_argument('prefix')
    args = parser.parse_args()
    capture(args.source, args.destination, args.prefix)

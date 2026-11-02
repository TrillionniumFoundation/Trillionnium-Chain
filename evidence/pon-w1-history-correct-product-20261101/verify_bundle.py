#!/usr/bin/env python3
"""Verify retained bytes with the Python standard library, without extraction.

PASS means package consistency, not execution, work hardness or public service.
Pin manifest.json's SHA256 from an external source when checking authenticity.
"""
import argparse
import hashlib
import io
import json
import lzma
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tarfile

SCHEMA = 'pon-history-correct-product-evidence-v1'
FALSE_FLAGS = ('qualified', 'production_activation', 'public_service_accepted',
               'whole_chain_pq_accepted', 'work_hardness_accepted')
CHUNK = 1024 * 1024
MAX_METADATA = 16 * 1024 * 1024
MAX_MEMBERS = 100000
MAX_MEMBER_BYTES = 512 * 1024 * 1024
MAX_TOTAL_BYTES = 8 * 1024 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, 'duplicate JSON key: ' + key)
        result[key] = value
    return result


def integer(value, label, maximum=MAX_TOTAL_BYTES):
    require(type(value) is int and 0 <= value <= maximum, label + ': bounded integer required')
    return value


def path_name(value):
    require(type(value) is str and 0 < len(value.encode('utf-8')) <= 4096
            and '\\' not in value and '\0' not in value
            and not PurePosixPath(value).is_absolute()
            and all(p not in ('', '.', '..') for p in value.split('/')),
            'invalid relative path: ' + repr(value))
    return value


def sha_value(value):
    require(type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None,
            'canonical SHA256 required')
    return value


def metadata(value, label):
    require(type(value) is dict and set(value) == {'bytes', 'sha256'}, label + ': exact byte/hash fields required')
    integer(value['bytes'], label + '.bytes')
    sha_value(value['sha256'])
    return value


def read_json(path):
    require(path.stat().st_size <= MAX_METADATA, 'metadata byte bound exceeded')
    return json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=pairs,
        parse_constant=lambda value: (_ for _ in ()).throw(ValueError('non-finite JSON: ' + value)))


def regular(path):
    require(stat.S_ISREG(path.lstat().st_mode), 'regular non-symlink file required: ' + str(path))


def file_metadata(path):
    regular(path)
    before = path.stat()
    digest, size = hashlib.sha256(), 0
    with path.open('rb') as source:
        while chunk := source.read(CHUNK):
            size += len(chunk)
            require(size <= MAX_TOTAL_BYTES, 'file byte bound exceeded')
            digest.update(chunk)
    after = path.stat()
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
            'file changed during verification: ' + str(path))
    require(size == before.st_size, 'file size changed')
    return {'bytes': size, 'sha256': digest.hexdigest()}


class Parts(io.RawIOBase):
    """Read the declared concatenation; never create an archive or extracted file."""
    def __init__(self, paths):
        self.paths = iter(paths)
        self.current = None

    def readable(self):
        return True

    def readinto(self, buffer):
        view, count = memoryview(buffer), 0
        while count < len(view):
            if self.current is None:
                try:
                    path = next(self.paths)
                except StopIteration:
                    break
                regular(path)
                self.current = path.open('rb')
            n = self.current.readinto(view[count:])
            if n:
                count += n
            else:
                self.current.close()
                self.current = None
        return count

    def close(self):
        if self.current is not None:
            self.current.close()
            self.current = None
        super().close()


class Bounded(io.RawIOBase):
    def __init__(self, source, limit):
        self.source, self.limit, self.observed = source, limit, 0

    def readable(self):
        return True

    def readinto(self, buffer):
        data = self.source.read(min(len(buffer), self.limit - self.observed + 1))
        self.observed += len(data)
        require(self.observed <= self.limit, 'uncompressed tar byte bound exceeded')
        buffer[:len(data)] = data
        return len(data)


def verify_archive(root, archive, files):
    require(set(archive) == {'name', 'format', 'bytes', 'sha256', 'inventory',
                            'members', 'uncompressed_member_bytes', 'parts'},
            'exact archive fields required')
    name = path_name(archive['name'])
    require('/' not in name and archive['format'] == 'tar.xz', 'fixed tar.xz archive required')
    inventory_path = path_name(archive['inventory'])
    require(inventory_path == 'inventories/' + name + '.json' and inventory_path in files,
            'archive inventory identity mismatch')
    inventory = read_json(root / inventory_path)
    require(type(inventory) is dict and 0 < len(inventory) <= MAX_MEMBERS, 'bounded nonempty member inventory required')
    total = 0
    for member, item in inventory.items():
        path_name(member)
        metadata(item, member)
        require(item['bytes'] <= MAX_MEMBER_BYTES, 'member byte bound exceeded')
        total += item['bytes']
        require(total <= MAX_TOTAL_BYTES, 'archive member total exceeds bound')
    require(integer(archive['members'], 'archive.members', MAX_MEMBERS) == len(inventory), 'member count mismatch')
    require(integer(archive['uncompressed_member_bytes'], 'archive member bytes') == total, 'member byte total mismatch')
    require(type(archive['parts']) is list and archive['parts'], 'ordered nonempty parts required')
    digest, compressed_bytes, paths = hashlib.sha256(), 0, []
    for index, part in enumerate(archive['parts']):
        require(type(part) is dict and set(part) == {'path', 'bytes', 'sha256'}, 'exact part fields required')
        path = path_name(part['path'])
        require(path == f'archives/{name}.part-{index:04d}' and path in files, 'ordered part identity mismatch')
        expected = metadata({'bytes': part['bytes'], 'sha256': part['sha256']}, path)
        require(files[path] == expected, 'part metadata conflicts with top-level inventory')
        paths.append(root / path)
        with (root / path).open('rb') as source:
            while chunk := source.read(CHUNK):
                digest.update(chunk)
                compressed_bytes += len(chunk)
    require(compressed_bytes == integer(archive['bytes'], 'compressed archive bytes')
            and digest.hexdigest() == sha_value(archive['sha256']), 'concatenated archive byte/hash mismatch')
    seen, observed_bytes = set(), 0
    with Parts(paths) as parts:
        with lzma.LZMAFile(parts, 'rb') as decoded:
            bounded = Bounded(decoded, total + (len(inventory) + 1) * 16384)
            with tarfile.open(fileobj=bounded, mode='r|') as tar:
                for member in tar:
                    member_name = path_name(member.name)
                    require(member.type in (tarfile.REGTYPE, tarfile.AREGTYPE)
                            and not member.sparse, 'only ordinary regular tar members are allowed')
                    require(member_name in inventory, 'unknown archive member: ' + member_name)
                    require(member_name not in seen, 'duplicate archive member: ' + member_name)
                    seen.add(member_name)
                    expected = inventory[member_name]
                    require(member.size == expected['bytes'], 'member declared byte length mismatch: ' + member_name)
                    actual_hash, size = hashlib.sha256(), 0
                    stream = tar.extractfile(member)
                    require(stream is not None, 'missing member data stream')
                    with stream:
                        while chunk := stream.read(CHUNK):
                            size += len(chunk)
                            require(size <= expected['bytes'], 'member exceeds byte bound')
                            actual_hash.update(chunk)
                    require(size == expected['bytes'] and actual_hash.hexdigest() == expected['sha256'],
                            'member byte/hash mismatch: ' + member_name)
                    observed_bytes += size
                # Force XZ checksum/EOF validation and reject hidden second tar
                # streams or nonzero data after the tar end marker. No extraction.
                padding = 0
                while chunk := tar.fileobj.read(CHUNK):
                    padding += len(chunk)
                    require(padding <= tarfile.RECORDSIZE and not any(chunk), 'noncanonical or nonzero trailing tar data')
                require(padding >= tarfile.BLOCKSIZE, 'two complete tar end blocks required')
    require(seen == set(inventory), 'missing archive members')
    require(observed_bytes == total, 'observed archive member bytes mismatch')
    return {'name': name, 'members': len(seen), 'member_bytes': observed_bytes,
            'compressed_bytes': compressed_bytes, 'parts': len(paths)}


def verify(root, expected_manifest_sha256=None):
    root = Path(root).resolve()
    manifest_path = root / 'manifest.json'
    regular(manifest_path)
    manifest_meta = file_metadata(manifest_path)
    if expected_manifest_sha256 is not None:
        require(manifest_meta['sha256'] == sha_value(expected_manifest_sha256), 'external manifest SHA256 mismatch')
    manifest = read_json(manifest_path)
    require(type(manifest) is dict and manifest.get('schema') == SCHEMA, 'explicit evidence schema required')
    for flag in FALSE_FLAGS:
        require(manifest.get(flag) is False, 'consistency cannot acquire qualification: ' + flag)
    files = manifest.get('files')
    require(type(files) is dict and files and len(files) <= MAX_MEMBERS, 'bounded top-level file inventory required')
    for name, expected in files.items():
        path_name(name)
        require(name != 'manifest.json', 'manifest cannot hash itself')
        metadata(expected, name)
    actual = {}
    for path in root.rglob('*'):
        require(not path.is_symlink(), 'symlinks are not allowed in the bundle')
        if path.is_dir():
            relative = str(path.relative_to(root)) + '/'
            require(any(name.startswith(relative) for name in files), 'unknown bundle directory')
        else:
            regular(path)
            name = path.relative_to(root).as_posix()
            if name != 'manifest.json':
                require(name in files, 'unknown bundle file: ' + name)
                actual[name] = file_metadata(path)
    require(actual == files, 'missing file or top-level byte/hash mismatch')
    archives = manifest.get('archives')
    require(type(archives) is list and 0 < len(archives) <= 128, 'bounded archive list required')
    names, part_names, inventories, results = set(), set(), set(), []
    for archive in archives:
        require(archive['name'] not in names, 'duplicate archive name')
        names.add(archive['name'])
        require(archive['inventory'] not in inventories, 'duplicate archive inventory')
        inventories.add(archive['inventory'])
        for part in archive['parts']:
            require(part['path'] not in part_names, 'duplicate archive part')
            part_names.add(part['path'])
        results.append(verify_archive(root, archive, files))
    require({p for p in files if p.startswith('archives/')} == part_names, 'unknown or missing declared archive part')
    require({p for p in files if p.startswith('inventories/')} == inventories, 'unknown or missing archive inventory')
    return {'schema': 'pon-evidence-bundle-byte-verification-v1', 'consistency': 'PASS',
        'manifest_sha256': manifest_meta['sha256'], 'files': len(files),
        'archives': len(results), 'parts': sum(r['parts'] for r in results),
        'original_archive_members': sum(r['members'] for r in results),
        'uncompressed_member_bytes': sum(r['member_bytes'] for r in results),
        'archive_bytes': sum(r['compressed_bytes'] for r in results),
        'archive_results': results, 'archive_extraction_performed': False,
        'native_tests_executed': False, 'custody_authenticated': False,
        **dict.fromkeys(FALSE_FLAGS, False)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument('--manifest-sha256', help='optional externally pinned manifest SHA256')
    args = parser.parse_args()
    try:
        result = verify(args.root, args.manifest_sha256)
    except (OSError, EOFError, ValueError, TypeError, KeyError, UnicodeError, lzma.LZMAError, tarfile.TarError) as error:
        print(json.dumps({'schema': 'pon-evidence-bundle-byte-verification-v1', 'consistency': 'FAIL',
            'error': str(error), **dict.fromkeys(FALSE_FLAGS, False)}, sort_keys=True))
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

"""Offline metadata and artifact preservation; never executes downloaded code."""
import argparse
import datetime
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tempfile
import zipfile


def require(ok, why):
    if not ok:
        raise ValueError(why)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def load(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    return json.loads(Path(path).read_bytes(), object_pairs_hook=unique)


def write_new(path, value, compressed=False):
    path = Path(path)
    require(not path.exists(), 'preserve prior observations; output already exists')
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode()
    data = gzip.compress(raw, mtime=0) if compressed else raw
    fd, tmp = tempfile.mkstemp(prefix=path.name + '.tmp-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(tmp, path)
    finally:
        os.unlink(tmp)
    return {'file': str(path), 'bytes': len(data), 'sha256': sha(data)}


def metadata(args):
    source = load(args.input)
    rows = source.get(args.kind)
    require(isinstance(rows, list), 'expected complete normalized API collection')
    selected, excluded = [], []
    for row in rows:
        if args.kind == 'workflow_runs':
            matches = row.get('head_sha') == args.candidate
        elif args.kind == 'jobs':
            require(source.get('run_id') == args.run_id, 'bound run ID missing')
            require(source.get('event_head') == args.candidate, 'bound run source missing')
            matches = row.get('run_id') == args.run_id and row.get('head_sha') == args.candidate
        else:
            run = row.get('workflow_run', {})
            matches = run.get('head_sha') == args.candidate and run.get('id') == args.run_id
        (selected if matches else excluded).append(row)
    total = source.get('total_count')
    result = {
        'schema': 'exact-candidate-metadata-only-v1',
        'observed_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'candidate': args.candidate, 'kind': args.kind, 'run_id': args.run_id,
        'input': str(Path(args.input).resolve()), 'input_sha256': sha(Path(args.input).read_bytes()),
        'reported_total': total, 'retrieved_count': len(rows),
        'collection_complete': isinstance(total, int) and total == len(rows),
        'matching_rows': selected, 'excluded_source_or_run_rows': excluded,
        'native_verdict': 'NOT_ESTABLISHED_BY_METADATA',
        'scope': 'Pending, cancelled, skipped, failed and successful workflow states are metadata only. Native execution requires separate exact-source raw records.',
    }
    return write_new(args.output, result)


def artifact(args):
    meta = load(args.metadata)
    run = meta.get('workflow_run', {})
    require(run.get('head_sha') == args.candidate and run.get('id') == args.run_id,
            'artifact is from a different candidate or run')
    path = Path(args.zip)
    require(stat.S_ISREG(path.lstat().st_mode), 'artifact must be a regular file')
    require(path.stat().st_size == meta['size_in_bytes'], 'artifact size mismatch')
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    require(meta.get('digest') == 'sha256:' + digest.hexdigest(), 'artifact digest mismatch')
    requested = load(args.members) if args.members else []
    require(isinstance(requested, list) and len(requested) == len(set(requested)), 'unique explicit members required')
    total_selected = 0
    records, index = [], []
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        require(len(names) == len(set(names)), 'duplicate ZIP entries')
        require(set(requested) <= set(names), 'requested original member missing')
        for entry in archive.infolist():
            name = PurePosixPath(entry.filename)
            require(not name.is_absolute() and '..' not in name.parts and '\\' not in entry.filename,
                    'unsafe ZIP entry path')
            require(not stat.S_ISLNK(entry.external_attr >> 16), 'ZIP symlink rejected')
            index.append({'member': entry.filename, 'bytes': entry.file_size,
                          'compressed_bytes': entry.compress_size, 'crc32': f'{entry.CRC:08x}'})
            if entry.filename not in requested:
                continue
            require(not entry.is_dir() and entry.file_size <= 64 * 1024 * 1024, 'selected member exceeds bound')
            total_selected += entry.file_size
            require(total_selected <= 128 * 1024 * 1024, 'selected record bundle exceeds bound')
            with archive.open(entry) as stream:
                raw = stream.read(entry.file_size + 1)
            require(len(raw) == entry.file_size, 'ZIP member size mismatch')
            records.append({'member': entry.filename, 'bytes': len(raw),
                            'sha256': sha(raw), 'text': raw.decode('utf-8')})
    result = {
        'schema': 'exact-candidate-artifact-selected-originals-v1',
        'observed_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'candidate': args.candidate, 'run_id': args.run_id, 'artifact_metadata': meta,
        'artifact_file': str(path.resolve()), 'artifact_bytes': path.stat().st_size,
        'artifact_sha256': digest.hexdigest(), 'archive_index': index,
        'selected_records': records, 'selected_original_bytes': total_selected,
        'native_verdict': 'REQUIRES_DOMAIN_READER', 'executes_native_code': False,
        'scope': 'Bytes and provenance only. Exact source, ELF, profile, commands, named results, Host limits and original business gates require domain readback.',
    }
    return write_new(args.output, result, compressed=args.gzip)


parser = argparse.ArgumentParser(description=__doc__)
sub = parser.add_subparsers(dest='command', required=True)
for command in ('metadata', 'artifact'):
    p = sub.add_parser(command)
    p.add_argument('--candidate', required=True)
    p.add_argument('--run-id', type=int)
    p.add_argument('--output', required=True)
p = sub.choices['metadata']
p.add_argument('--kind', choices=('workflow_runs', 'jobs', 'artifacts'), required=True)
p.add_argument('--input', required=True)
p = sub.choices['artifact']
p.add_argument('--metadata', required=True)
p.add_argument('--zip', required=True)
p.add_argument('--members')
p.add_argument('--gzip', action='store_true')
args = parser.parse_args()
require(re.fullmatch(r'[0-9a-f]{40}', args.candidate), 'exact full SHA required')
require(args.candidate != 'b28098c092dca72165c0d26054fce95a8636d777', 'old candidate excluded from new monitoring')
if args.command == 'artifact' or args.kind != 'workflow_runs':
    require(type(args.run_id) is int and args.run_id > 0, 'exact run ID required')
print(json.dumps(metadata(args) if args.command == 'metadata' else artifact(args), indent=2))

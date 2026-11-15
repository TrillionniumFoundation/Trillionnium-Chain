#!/usr/bin/env python3
"""Copy frozen source records byte-for-byte; verify data only, never run native."""
import collections
import datetime
import gc
import gzip
import hashlib
import json
import pathlib
import struct
import zlib

BASE = pathlib.Path('/workspace/scratch/b5a148b09b11')
OUT = pathlib.Path(__file__).resolve().parent
C1 = BASE / 'next-hosted/c5dd7c-review'
C2 = BASE / 'next-hosted/b4bdf-review'
DIAG = BASE / 'next-validation/c5dd-diagnostic-observability-readback'
SERVICE = BASE / 'next-validation/service-path-review'
HOST = BASE / 'next-validation/host-checkpoint-cost-review'
FOLDERS = {
    DIAG: 'diagnostics',
    SERVICE / 'c5dd-baseline-critical-path': 'service-path/c5dd-baseline-critical-path',
    SERVICE / 'c5dd-graph-scope-review': 'service-path/c5dd-graph-scope-review',
    SERVICE / 'c5dd-graph-internal-review': 'service-path/c5dd-graph-internal-review',
    HOST: 'service-path/host-checkpoint-cost-review',
}
HANDOFFS = [
    (C1 / 'current-business-terminal-handoff.json', 'b811562aabceb2712acd7d0dd3f48ea038d0d5a624f58003b844c1c9ef1652c0'),
    (C1 / 'current-terminal-supplement-handoff.json', '18feb1be44c3d85624d149151c22de4522781824c296935163c8591267250e45'),
    (C2 / 'current-terminal-small-records-handoff.json', '6791432d16cb348666a75c6a31f09ab7e39188f03f246bdcdc18b974233e3b63'),
    (C1 / 'pq-original-node-four-lane-handoff.json', '8bd22f09bc4a7f78b77da231e9ab41454405cfedbd57f2f3117355fe1d25a223'),
    (C2 / 'w1-history-small-handoff.json', '0a7ed96d02a31be258c6d43c959ba553ffceb75695bc01658f93f3cc9f77abb8'),
]
specs = {}
failures = []
required_edges = []
folder_checks = []


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()


def write(name, value):
    (OUT / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')


def target_for(source):
    for root, target in [(C1, 'c5dd'), (C2, 'b4bdf'), *FOLDERS.items()]:
        if source.is_relative_to(root):
            return str(pathlib.PurePosixPath(target) / source.relative_to(root).as_posix())
    raise ValueError(f'outside selected frozen roots: {source}')


def add(path, reason, expected_sha=None, expected_bytes=None):
    path = pathlib.Path(path)
    if not path.is_file() or path.is_symlink():
        failures.append({'source_path': str(path), 'reason': 'missing or symlink', 'required_by': reason})
        return
    raw = path.read_bytes()
    actual = sha(raw)
    if (expected_sha is not None and actual != expected_sha) or (expected_bytes is not None and len(raw) != expected_bytes):
        failures.append({'source_path': str(path), 'reason': 'frozen digest/size mismatch; not copied',
                         'required_by': reason, 'expected_sha256': expected_sha,
                         'actual_sha256': actual, 'expected_bytes': expected_bytes, 'actual_bytes': len(raw)})
        return
    assert path.suffix not in ('.zip', '.sqlite', '.db', '.elf')
    assert not raw.startswith(b'\x7fELF') and not raw.startswith(b'SQLite format 3\x00')
    if path in specs:
        assert specs[path]['sha256'] == actual
        specs[path]['required_by'].add(reason)
        return
    specs[path] = {'source_path': str(path), 'relative_path': target_for(path), 'bytes': len(raw),
                   'sha256': actual, 'required_by': {reason}}


def add_ref(record, reason):
    add(record['path'], reason, record['sha256'], record['bytes'])
    required_edges.append({'from': reason, 'source_path': record['path'],
                           'bytes': record['bytes'], 'sha256': record['sha256']})


def prepare_sources():
    for path, digest in HANDOFFS:
        add(path, 'frozen handoff itself', digest)
        data = json.loads(path.read_text())
        for field in ('records', 'reader_refusal_records'):
            for record in data.get(field, []):
                add_ref(record, f'{path.name}/{field}')
        for field in ('aggregate', 'metadata', 'prior_frozen_handoff'):
            if isinstance(data.get(field), dict) and {'path', 'bytes', 'sha256'} <= data[field].keys():
                add_ref(data[field], f'{path.name}/{field}')
    add(C1 / 'protocol-merge-packager-recovery.json', 'preserved original packager refusal/recovery',
        '7e38e14132af6fdcbedc1f19e1290b50882f754d0ce0326bef1833c99710dd1b', 3553)
    for folder, mapped in FOLDERS.items():
        index_file = folder / 'artifact-index.json'
        index = json.loads(index_file.read_text())
        expected = set(index['files']) | {'artifact-index.json'}
        actual = {f.relative_to(folder).as_posix() for f in folder.rglob('*') if f.is_file()}
        assert actual == expected, (str(folder), sorted(actual - expected), sorted(expected - actual))
        if folder == DIAG:
            assert len(actual) == 18
            assert sha(index_file.read_bytes()) == 'd9e1e77d6bd234db3ffdf3c69e944ba670d43916bedd3bdbfd8771293b440fe6'
        add(index_file, 'complete frozen directory index')
        for relative, item in index['files'].items():
            add(folder / relative, f'{folder.name}/artifact-index.json', item['sha256'], item['bytes'])
        folder_checks.append({'source_directory': str(folder), 'destination_directory': mapped,
                              'all_files': len(actual), 'complete_current_index_verified': True})
    # Preserve small, hash-bound collector scripts referenced by these records.
    # Do not follow arbitrary paths, archive links, running job logs or repo source.
    initial = list(specs)
    for path in initial:
        if path.suffix != '.json' or not (path.is_relative_to(C1) or path.is_relative_to(C2)):
            continue
        data = json.loads(path.read_text())
        reader = data.get('reader')
        if isinstance(reader, dict) and 'path' in reader and 'sha256' in reader:
            source = pathlib.Path(reader['path'])
            if source.suffix == '.py' and (source.is_relative_to(C1) or source.is_relative_to(C2)):
                add(source, f'hash-bound reader for {path.name}', reader['sha256'], reader.get('bytes'))


def copy_sources():
    copied = []
    for path, item in sorted(specs.items(), key=lambda pair: pair[1]['relative_path']):
        original = path.read_bytes()
        assert len(original) == item['bytes'] and sha(original) == item['sha256'], str(path)
        target = OUT / item['relative_path']
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            assert target.read_bytes() == original, f'will not overwrite a different staged snapshot: {target}'
        else:
            target.write_bytes(original)
        assert target.read_bytes() == original
        assert path.read_bytes() == original, f'source changed during copy: {path}'
        copied.append({**item, 'required_by': sorted(item['required_by']), 'byte_equal_verified': True})
    return copied


def verify_gzip_records(copied):
    bundles = []
    embedded = []
    diagnostic = json.loads((OUT / 'diagnostics/readback.json').read_text())
    samples = json.loads(gzip.decompress((OUT / 'diagnostics/selected-original-rows.json.gz').read_bytes()))['examples']
    assert len(samples) == 89
    sample_bundles = {scope['bundle']['path']: scope for scope in diagnostic['scopes']}
    verified_samples = 0
    for item in copied:
        if not item['relative_path'].endswith('.gz'):
            continue
        path = OUT / item['relative_path']
        packed = path.read_bytes()
        raw = gzip.decompress(packed)
        data = json.loads(raw)
        result = {'relative_path': item['relative_path'], 'packed_sha256': sha(packed),
                  'uncompressed_bytes': len(raw), 'uncompressed_sha256': sha(raw),
                  'gzip_mtime': struct.unpack('<I', packed[4:8])[0], 'schema': data.get('schema')}
        del raw
        records = data.get('selected_records', data.get('records'))
        if records is not None and all(isinstance(row, dict) and 'text' in row for row in records):
            names = []
            byte_count = 0
            archive_index = {row['member']: row for row in data.get('archive_index', [])}
            for record in records:
                body = record['text'].encode('utf-8')
                assert len(body) == record['bytes'] and sha(body) == record['sha256']
                name = record['member']
                assert name not in names
                names.append(name)
                byte_count += len(body)
                if name in archive_index:
                    expected = archive_index[name]
                    assert expected['bytes'] == len(body)
                    if isinstance(expected.get('crc32'), int):
                        assert zlib.crc32(body) == expected['crc32']
                embedded.append({'bundle': item['relative_path'], 'member': name,
                                 'bytes': len(body), 'sha256': sha(body), 'lossless_utf8_verified': True})
            if 'selected_original_bytes' in data:
                assert data['selected_original_bytes'] == byte_count
            result.update(original_records=len(records), original_bytes=byte_count,
                          every_original_record_length_and_sha256_verified=True,
                          complete_report_members=[n for n in names if n.endswith('/report.json') or n == 'report.json'])
            if item['source_path'] in sample_bundles:
                scope = sample_bundles[item['source_path']]
                assert item['sha256'] == scope['bundle']['sha256']
                selected = [sample for sample in samples if sample['source_id'] == scope['id']]
                original_records = {record['member']: record for record in records}
                for member in sorted({sample['report_member'] for sample in selected}):
                    original_report = json.loads(original_records[member]['text'])
                    for sample in selected:
                        if sample['report_member'] != member:
                            continue
                        value = original_report
                        for part in sample['json_pointer'].lstrip('/').split('/'):
                            part = part.replace('~1', '/').replace('~0', '~')
                            value = value[int(part)] if isinstance(value, list) else value[part]
                        assert value == sample['row'] and sha(canonical(value)) == sample['row_canonical_sha256']
                        verified_samples += 1
                    del original_report
                result['diagnostic_rows_relocated_in_complete_original_reports'] = len(selected)
        elif records is not None and all('complete_decoded_github_job_log' in row for row in records):
            assert len(records) == 4 and len({row['lane'] for row in records}) == 4
            for record in records:
                text = record['complete_decoded_github_job_log']
                assert text and 'test result: ok. 25 passed; 0 failed; 1 ignored;' in text
                body = text.encode('utf-8')
                embedded.append({'bundle': item['relative_path'], 'member': record['lane'],
                                 'job_id': record['job_id'], 'bytes': len(body), 'sha256': sha(body),
                                 'kind': 'entire collector-retained decoded GitHub job log; no original per-log hash field'})
            result.update(complete_original_job_logs=4,
                          qualification_scope='Copied existing complete decoded logs. No new job, native run, large grid ZIP verification or ELF qualification.')
        elif 'examples' in data:
            for example in data['examples']:
                assert sha(canonical(example['row'])) == example['row_canonical_sha256']
            result.update(diagnostic_examples=len(data['examples']),
                          complete_reports_provided_separately=True, examples_are_not_report_replacements=True)
        else:
            raise AssertionError(f'unknown compressed evidence shape: {item["relative_path"]}')
        bundles.append(result)
        del data, records
        gc.collect()
    assert verified_samples == 89
    for source in sample_bundles:
        assert sum(item['source_path'] == source for item in copied) == 1
    return bundles, embedded, verified_samples


def reference_check(copied, embedded):
    by_path = {item['source_path']: item for item in copied}
    by_hash = collections.defaultdict(list)
    for item in copied:
        by_hash[item['sha256']].append(item['relative_path'])
    embedded_by_hash = collections.defaultdict(list)
    for item in embedded:
        embedded_by_hash[item['sha256']].append({'bundle': item['bundle'], 'member': item['member']})
    direct = []
    for edge in required_edges:
        item = by_path.get(edge['source_path'])
        assert item and item['sha256'] == edge['sha256'] and item['bytes'] == edge['bytes']
        direct.append({**edge, 'resolved_to': item['relative_path']})
    references = []
    def walk(value, origin, pointer=''):
        if isinstance(value, dict):
            if isinstance(value.get('path'), str) and isinstance(value.get('sha256'), str):
                source, digest = value['path'], value['sha256']
                row = {'from': origin, 'pointer': pointer, 'source_path': source, 'sha256': digest}
                exact = by_path.get(source)
                if exact and exact['sha256'] == digest:
                    row.update(status='staged_exact_source_path', resolved_to=exact['relative_path'])
                elif digest in by_hash:
                    row.update(status='staged_same_bytes_or_historical_renamed_snapshot', resolved_to=by_hash[digest])
                elif digest in embedded_by_hash:
                    row.update(status='original_record_content_preserved_inside_bundle', resolved_to=embedded_by_hash[digest])
                elif source.endswith(('.zip', '.sqlite', '.db')) or 'target/' in source:
                    row['status'] = 'intentionally_external_binary_database_or_archive_identity'
                else:
                    row['status'] = 'external_provenance_reference_not_a_required_bundle_record'
                references.append(row)
            for key, child in value.items():
                if key not in ('text', 'complete_decoded_github_job_log'):
                    walk(child, origin, pointer + '/' + key)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, origin, pointer + '/' + str(index))
    for item in copied:
        if item['relative_path'].endswith('.json'):
            walk(json.loads((OUT / item['relative_path']).read_text()), item['relative_path'])
    return {'required_handoff_edges': direct, 'required_handoff_edges_resolved': len(direct),
            'structured_provenance_references': references,
            'scope': 'Original source path strings are preserved, not rewritten. This manifest maps frozen files and embedded raw content. External code/archive/database identities are not fabricated as local staged artifacts.'}


def main():
    prepare_sources()
    copied = copy_sources()
    assert len({item['relative_path'] for item in copied}) == len(copied)
    bundles, embedded, samples = verify_gzip_records(copied)
    refs = reference_check(copied, embedded)
    write('embedded-records-index.json', {'schema': 'lossless-embedded-originals-index-v1', 'records': embedded})
    write('reference-check.json', refs)
    totals = collections.defaultdict(lambda: {'files': 0, 'bytes': 0})
    for item in copied:
        key = item['relative_path'].split('/')[0]
        totals[key]['files'] += 1
        totals[key]['bytes'] += item['bytes']
    verification = {'schema': 'hosted-terminal-stage-data-verification-v1',
                    'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    'status': 'COMPLETE_FOR_REQUESTED_FROZEN_SCOPE' if not failures else 'INCOMPLETE',
                    'scope': 'File/data verification only; no native execution or new native PASS.',
                    'source_files': len(copied), 'source_bytes': sum(item['bytes'] for item in copied),
                    'by_directory': dict(totals), 'source_and_copy_bytes_sha256_match': True,
                    'directory_index_checks': folder_checks, 'required_handoff_edges_resolved': len(required_edges),
                    'gzip_bundles': bundles, 'embedded_original_records': len(embedded),
                    'diagnostic_samples_relocated_in_complete_reports': samples,
                    'four_original_diagnostic_source_gzip_files_each_staged_once': True,
                    'skipped_missing_changed_or_unfrozen': failures,
                    'explicitly_not_in_this_snapshot': ['Later runtime terminal evidence',
                        'Current independent dependency-proof source review', 'Large ZIP archives, SQLite databases and ELF binaries'],
                    'diagnostic_reader_scope': 'Both retained formal reader attempts exited0. draft-v1 is an earlier successful wording/scope draft, not a refusal. An earlier tool-only exploratory IndexError has no fabricated file or hash.',
                    'native_executions': 0, 'native_tests_rerun': False,
                    'repository_sole_plan_or_PR_modified': False}
    write('verification.json', verification)
    manifest = {'schema': 'frozen-hosted-terminal-bundle-manifest-v1',
                'created_utc': verification['created_utc'], 'status': verification['status'],
                'scope': 'Immutable dated handoffs and frozen source records copied without re-encoding. Later terminal records are appended in a new snapshot, never substituted for this one.',
                'original_files': copied, 'source_files': len(copied), 'source_bytes': verification['source_bytes'],
                'by_directory': dict(totals), 'skipped_missing_changed_or_unfrozen': failures,
                'native_executions': 0, 'data_integrity_check_is_not_native_PASS': True,
                'generated_records': []}
    for name in ('assemble_stage.py', 'preflight.json', 'embedded-records-index.json', 'reference-check.json', 'verification.json'):
        path = OUT / name
        if path.is_file():
            body = path.read_bytes()
            manifest['generated_records'].append({'relative_path': name, 'bytes': len(body), 'sha256': sha(body)})
    write('manifest.json', manifest)
    for item in copied:
        staged = (OUT / item['relative_path']).read_bytes()
        source = pathlib.Path(item['source_path']).read_bytes()
        assert source == staged and sha(staged) == item['sha256']
    actual_files = [path for path in OUT.rglob('*') if path.is_file()]
    print(json.dumps({'status': verification['status'], 'source_files': len(copied),
                      'source_bytes': verification['source_bytes'], 'stage_files': len(actual_files),
                      'stage_bytes': sum(path.stat().st_size for path in actual_files),
                      'required_handoff_edges': len(required_edges), 'embedded_original_records': len(embedded),
                      'samples_relocated': samples, 'missing': failures,
                      'manifest_sha256': sha((OUT / 'manifest.json').read_bytes()),
                      'verification_sha256': sha((OUT / 'verification.json').read_bytes())}))


if __name__ == '__main__':
    main()

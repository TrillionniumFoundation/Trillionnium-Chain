#!/usr/bin/env python3
"""Verify every transport chunk, archive member, and deterministic rebuild."""
import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import tarfile

ROOT = Path(__file__).resolve().parent
TRANSPORT = ROOT / 'transport-chunks.json'
ARCHIVE = 'continuation-resource-evidence-5633c55.tar.gz'
EXPECTED_ARCHIVE = 'e1366a88a79dab02ea2deaa5af8915bba913e97f3c02d21eb06badf3fa2f82dc'
EXPECTED_MANIFEST = '2b9fb133b7301fc1fa674f61baa7d89946a0333ac2e9d509941e4aea9c0b83b9'

def require(value, message):
    if not value:
        raise ValueError(message)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(data)

def main():
    supplied = json.loads(TRANSPORT.read_bytes())
    recovered = {}
    chunk_records = []
    for file in supplied['files']:
        selected = sorted((x for x in supplied['chunks'] if x['request']['path'] == file['path']),
                          key=lambda x: x['request']['offset'])
        offset = 0
        parts = []
        for item in selected:
            request, response = item['request'], item['response']
            require(request['expected_version'] == file['version'] == response['version'], 'chunk version mismatch')
            require(request['path'] == response['path'] == file['path'], 'chunk path mismatch')
            require(request['offset'] == response['offset'] == offset, 'chunk gap, overlap, or reordering')
            data = base64.b64decode(response['data_base64'], validate=True)
            require(sha(data) == response['chunk_sha256'], 'chunk SHA mismatch')
            require(response['size'] == file['size'] and response['next_offset'] == offset + len(data), 'chunk range mismatch')
            require(bool(data) and len(data) <= request['limit'], 'invalid bounded chunk')
            offset += len(data)
            require(response['eof'] is (offset == file['size']), 'incorrect eof')
            parts.append(data)
            chunk_records.append({'path':file['path'],'offset':response['offset'],'bytes':len(data),'sha256':sha(data)})
        raw = b''.join(parts)
        require(offset == len(raw) == file['size'] and sha(raw) == file['sha256'], 'full file SHA/size mismatch')
        name = Path(file['path']).name
        require(name not in recovered, 'duplicate output basename')
        require((ROOT/name).read_bytes() == raw, 'previously decoded file differs from exact transport')
        recovered[name] = raw
    require(sha(recovered[ARCHIVE]) == EXPECTED_ARCHIVE, 'archive pin mismatch')
    require(sha(recovered['manifest.json']) == EXPECTED_MANIFEST, 'manifest pin mismatch')
    manifest = json.loads(recovered['manifest.json'])
    result = json.loads(recovered['collection-result.json'])
    require(manifest['schema'] == 'trnm-continuation-resource-evidence-archive-v1', 'wrong manifest')
    require(result['status'] == 'ARCHIVED_VERIFIED' and result['archive']['sha256'] == EXPECTED_ARCHIVE and
            result['manifest']['sha256'] == EXPECTED_MANIFEST, 'collector result mismatch')
    expected = {item['path']:item for item in manifest['source_files']+manifest['additional_members']}
    require(len(expected) == 189 and manifest['source_regular_files'] == 187, 'unexpected inventory counts')
    require(sum(item['bytes'] for item in manifest['source_files']) == manifest['source_regular_bytes'], 'source byte count mismatch')
    expected['ARCHIVE-MANIFEST.json'] = {'bytes':len(recovered['manifest.json']),'sha256':EXPECTED_MANIFEST}
    payloads = {}
    with tarfile.open(fileobj=io.BytesIO(recovered[ARCHIVE]),mode='r:gz') as archive:
        members = archive.getmembers()
        require([m.name for m in members] == sorted(expected), 'member roster/order mismatch')
        for member in members:
            path = PurePosixPath(member.name)
            require(member.isfile() and not path.is_absolute() and '..' not in path.parts, 'unsafe archive member')
            require(member.mode == 0o644 and member.uid == member.gid == member.mtime == 0 and
                    member.uname == member.gname == '', 'noncanonical member metadata')
            data = archive.extractfile(member).read()
            row = expected[member.name]
            require(len(data) == member.size == row['bytes'] and sha(data) == row['sha256'], 'member bytes differ')
            payloads[member.name] = data
    require(payloads['ARCHIVE-MANIFEST.json'] == recovered['manifest.json'], 'embedded manifest differs')
    require(sha(payloads['collection/collector.py']) == 'f4be91a732c4fef5f36f32721dcd1004d23dd2c98ee666fe66065ba200a3233f', 'collector pin differs')
    require(set(manifest['evidence_roots']) == {'native-continuation-5633c55','owned-resource-repair-5633c55'}, 'scope roots differ')
    excluded_name = 'native-continuation-5633c55/native-target'
    require(manifest['exclusion_policy']['exact_excluded_cache_subtrees'] == [excluded_name], 'declared target exclusion policy differs')
    target_rows = [r for r in manifest['source_inventory'] if r['path'] == excluded_name]
    require(target_rows == manifest['excluded_subtrees'], 'actual target inventory/exclusion mismatch')
    require(len(target_rows) <= 1 and all(r['kind'] == 'excluded_cache_directory' for r in target_rows), 'unexpected target entry type')
    require(not any(p == excluded_name or p.startswith(excluded_name + '/') for p in payloads), 'excluded target bytes included')
    require(not any('/native-target/' in path or '/isolated-source/' in path or '/.git/' in path for path in payloads), 'source or target bytes included')
    target = io.BytesIO()
    with gzip.GzipFile(fileobj=target,filename='',mode='wb',compresslevel=9,mtime=0) as packed:
        with tarfile.open(fileobj=packed,mode='w',format=tarfile.PAX_FORMAT) as archive:
            for path in sorted(payloads):
                info = tarfile.TarInfo(path)
                info.size = len(payloads[path]);info.mode = 0o644
                info.uid = info.gid = info.mtime = 0;info.uname = info.gname = ''
                archive.addfile(info,io.BytesIO(payloads[path]))
    require(target.getvalue() == recovered[ARCHIVE], 'independent deterministic rebuild differs')
    require(manifest['native_test_cases_executed_in_continuation'] == 0 and
            manifest['continuation_result'] == 'FAILED_OR_BLOCKED' and
            manifest['cleanup_result'] == 'PASS_WHITELIST_REPAIR' and
            manifest['after_cleanup_native_started'] is False and manifest['whole_chain_pq_qualified'] is False,
            'scope interpretation changed')
    extraction = ROOT/'raw'
    extraction.mkdir()
    for path, data in payloads.items():
        write(extraction/path,data)
        os.chmod(extraction/path,0o644)
    report = {'schema':'trnm-continuation-resource-local-verification-v1','status':'VERIFIED','prior_verifier_attempt_retained':'verification-attempt-1.json',
              'archive':{'bytes':len(recovered[ARCHIVE]),'sha256':EXPECTED_ARCHIVE},
              'manifest':{'bytes':len(recovered['manifest.json']),'sha256':EXPECTED_MANIFEST},
              'transport_chunks_verified':len(chunk_records),'chunks':chunk_records,
              'members_verified':len(payloads),'source_regular_files':187,'source_regular_bytes':manifest['source_regular_bytes'],
              'every_member_sha_size_verified':True,'archive_paths_and_types_verified':True,
              'deterministic_rebuild_identical':True,'collector_source_inventory_and_bytes_equal':True,
              'original_blocked_result_retained':True,'cleanup_result_retained':True,'native_tests_executed':False,
              'whole_chain_pq_qualified':False}
    write(ROOT/'local-verification-v2.json',(json.dumps(report,sort_keys=True,indent=2)+'\n').encode())
    print(json.dumps({key:report[key] for key in ('status','archive','manifest','transport_chunks_verified','members_verified','source_regular_files','source_regular_bytes','deterministic_rebuild_identical')}))

if __name__=='__main__':
    main()

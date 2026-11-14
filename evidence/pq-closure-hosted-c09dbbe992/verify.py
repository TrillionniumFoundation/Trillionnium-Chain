#!/usr/bin/env python3
"""Offline, portable C1 evidence verifier. Reads files only; runs no tests.

The original large ZIPs are hash references in this compact distribution. Their
complete byte verification is recorded in the retained collector receipts.
This verifier independently checks the distributed bytes, nested manifests,
original small ZIPs, source receipts, and the preserved failure boundaries.
It does not turn those checks into native, release, or PQ qualification.
"""
from collections import Counter
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parent
HEAD = 'c09dbbe9921da12db8bf7240a8a95a0e9a789e50'
MERGE = '61589dddd13e7495369aaecad9212668049417c1'
TREE = 'f15a7ee4a0f5455eaf965db01dcd49e02a5f22b6'
NATIVE_SHA = '90f8da399cda835849001e5c65a49d0d8cc2a4b09e191e6c8b73dddbfb275456'
BOUNDED_SHA = '9f7f152885e9eb54725a5fe8909ce90ee5ac23a62facff20f39d0702d2fd22a8'
API_SHA = 'd95c5b9cfff7ca64a29d2bed6a8d621c3f64b06d02bf2ae7e428e9435ac22fd3'
API_OLD_INDEX_SHA = '84dbae497200db31eb1476cfba34e34b3c63c3969392d8ce4d9601959deecf5e'
EXPORT_ZIP_SHA = '3c6df0231bc96cd417bf3c482b714e5178f5350eaca4f446f60bc7ff28756fbc'


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def pairs(rows):
    result = {}
    for key, value in rows:
        require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def parse(raw):
    return json.loads(raw, object_pairs_hook=pairs)


def safe(name):
    p = PurePosixPath(name)
    require(bool(name) and str(p) == name and not p.is_absolute()
            and '..' not in p.parts and '\\' not in name and '\x00' not in name, 'unsafe member path')
    require('download-transport-private' not in name, 'private download transport must not be distributed')


def scan(raw):
    # Search text payloads, not arbitrary binary digests. A literal explanation
    # of a signed URL does not count as a URL value.
    for url in re.findall(rb'https?://[^\s\x00"<>]+', raw):
        lower = url.lower()
        require(not any(key in lower for key in (b'x-amz-signature=', b'x-amz-credential=',
                    b'x-goog-signature=', b'&sig=', b'?sig=')), 'temporary signed URL found')


def tar_bytes(raw):
    result = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:xz') as archive:
        for m in archive.getmembers():
            safe(m.name)
            require(m.isfile() and m.name not in result, 'nonregular or duplicate tar member')
            data = archive.extractfile(m).read()
            require(len(data) == m.size, 'tar member length')
            scan(data)
            result[m.name] = data
    return result


def zip_bytes(raw):
    result = {}
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        for m in archive.infolist():
            safe(m.filename)
            require(not m.is_dir() and m.filename not in result, 'nonregular or duplicate ZIP member')
            mode = (m.external_attr >> 16) & 0o170000
            require(mode in (0, 0o100000), 'ZIP link or special member')
            data = archive.read(m)
            require(len(data) == m.file_size, 'ZIP member length')
            scan(data)
            result[m.filename] = data
    return result


def indexed(files, index_name, sums_name):
    rows = parse(files[index_name])
    require(isinstance(rows, list), 'index must be a list')
    expected = {row['path'] for row in rows}
    require(len(expected) == len(rows), 'duplicate index row')
    require(set(files) == expected | {index_name, sums_name}, 'index coverage')
    for row in rows:
        safe(row['path'])
        data = files[row['path']]
        require(len(data) == row['bytes'] and digest(data) == row['sha256'], 'indexed bytes changed: ' + row['path'])
    sums = ''.join(f"{row['sha256']}  {row['path']}\n" for row in rows).encode()
    require(files[sums_name] == sums, 'SHA256SUMS differs from index')
    return len(rows)


def verify():
    outer = {}
    for p in ROOT.rglob('*'):
        require(not p.is_symlink(), 'stage contains symlink')
        if p.is_file():
            name = str(p.relative_to(ROOT)); safe(name)
            raw = p.read_bytes();scan(raw);outer[name] = raw
    outer_count = indexed(outer, 'FILES.json', 'SHA256SUMS')
    scope = parse(outer['SCOPE.json'])
    require((scope['head'], scope['prospective_merge'], scope['tree']) == (HEAD, MERGE, TREE), 'scope source mismatch')
    for key in ('C2_or_later_commits_qualified', 'old315_results_cover_C1', 'original_native_30s_qualified',
                'original_from_zero_4s_qualified', 'fresh_challenge_4s_6depth_qualified',
                'whole_chain_pq_qualified', 'production_activation', 'temporary_download_urls_retained'):
        require(scope[key] is False, 'scope promoted: ' + key)
    raw = outer['native/readback-1.tar.xz']
    require(len(raw) == 1850508 and digest(raw) == NATIVE_SHA, 'frozen native packet changed')
    native = tar_bytes(raw)
    native_count = indexed(native, 'packet-files.json', 'SHA256SUMS')
    require(native_count == 1838, 'native inventory count changed')
    results = parse(native['campaign/raw/results.json'])
    require(results == parse(outer['native/original-campaign-result-from-log.json']), 'job log and artifact result disagree')
    require(results['expected_head'] == HEAD and results['expected_tree'] == TREE, 'native source mismatch')
    require([a['step']['returncode'] for a in results['attempts']] == [101, 101, 101], 'original native failures changed')
    require(results['build']['returncode'] == 0 and results['finalization_failures'] == [], 'native setup/finalization classification changed')
    for run in (1, 2, 3):
        projection = parse(native[f'campaign/projections/run-{run}-report.json'])
        require(projection['source_sha256'] == results['attempts'][run - 1]['report_sha256'], 'original report binding')
        phases = [p['retained_original_field_values'] for p in projection['phases']]
        require([p['mode'] for p in phases] == ['baseline', 'from-zero', 'late-product'], 'phase roster')
        require(all(p['duration_seconds'] == 30 and p['finite_phase_criteria_met'] is False for p in phases), 'original window/verdict changed')
        require(phases[0]['verifier_errors'] == [], 'baseline error distribution changed')
        require(all(p['verifier_errors'] == ['PUBLIC_REQUEST_DEADLINE'] for p in phases[1:]), 'attack deadline distribution changed')
    for arch in ('arm64', 'x64'):
        m = parse(native[f'cost-{arch}/raw/from-zero-native/manifest.json'])
        require(m['format_passed'] and m['all_named_tests_passed'] and m['passed'] is False, 'cross-arch outcomes changed')
        require(m['failures'] == ['CONFIRMATION_TARGET'], 'cross-arch failure changed')
    raw = outer['bounded/bounded-readback-c09dbbe992.tar.xz']
    require(len(raw) == 719180 and digest(raw) == BOUNDED_SHA, 'bounded packet changed')
    bounded = tar_bytes(raw)
    bounded_count = indexed(bounded, 'FILES.json', 'SHA256SUMS')
    require(bounded_count == 108, 'bounded inventory count changed')
    codeql = parse(bounded['local-codeql-summary.json'])
    cells = set();sarif_counts = {};python_findings = []
    for cell in codeql['cells']:
        a = cell['artifact'];zraw = bounded[f"local-codeql/artifact-{a['id']}.zip"]
        require(len(zraw) == a['size_in_bytes'] and 'sha256:' + digest(zraw) == a['digest'], 'local CodeQL artifact identity')
        z = zip_bytes(zraw)
        step_name = next(n for n in z if n.endswith('/step-outcomes.json'))
        step = parse(z[step_name]);prefix = step_name[:-len('step-outcomes.json')]
        before = parse(z[prefix + 'source-before.json']);after = parse(z[prefix + 'source-after.json'])
        expected = HEAD if step['source_kind'] == 'head' else MERGE
        require(before == after and before['tested_commit'] == expected and before['tested_tree'] == TREE, 'local CodeQL actual source')
        require(step['expected_source_commit'] == expected and step['code_scanning_upload'] == 'never', 'local CodeQL upload/source boundary')
        require(all(v == 'success' for v in step['outcomes'].values()), 'local CodeQL execution incomplete')
        pair = (step['language'], step['source_kind']);require(pair not in cells, 'duplicate CodeQL cell');cells.add(pair)
        results_count = 0
        for name, data in z.items():
            if name.endswith('.sarif'):
                sarif = parse(data);require(sarif['version'] == '2.1.0' and sarif['runs'], 'invalid retained SARIF')
                for run in sarif['runs']:
                    rows = run.get('results', []);results_count += len(rows)
                    if pair[0] == 'python':
                        python_findings.append((pair[1], [(r['ruleId'], r['locations'], r['message']) for r in rows]))
        require(results_count == {'actions': 0, 'python': 2, 'rust': 857}[pair[0]], 'SARIF result count changed')
        sarif_counts['/'.join(pair)] = results_count
    require(cells == {(l, k) for l in ('actions', 'python', 'rust') for k in ('head', 'prospective-merge')}, 'incomplete CodeQL matrix')
    require(len(python_findings) == 2 and python_findings[0][1] == python_findings[1][1], 'Python findings source duplication changed')
    for lane, expected in (('head', HEAD), ('prospective-merge', MERGE)):
        prefix = 'fresh-service/' + lane
        manifest = parse(bounded[prefix + '/raw/fresh-service/manifest.json'])
        require(manifest['source_before'] == manifest['source_after'], 'fresh source changed')
        require(manifest['source_expected'] == expected and manifest['source_before']['commit'] == expected, 'fresh wrong source')
        require(manifest['source_before']['tree'] == TREE and manifest['binary_sha256_before'] == manifest['binary_sha256_after'], 'fresh tree/binary changed')
        require([r['process']['exit_code'] for r in manifest['runs']] == [0, 101], 'fresh original/native exit distinction')
        require(all(r['process']['timed_out'] is False for r in manifest['runs']), 'fresh timeout classification')
        log = bounded[prefix + '/raw/fresh-service/fresh.log']
        require(b'fresh challenges failed the original four-second/six-depth business target' in log, 'fresh actual assertion missing')
        for variant in ('original', 'fresh'):
            projection = parse(bounded[prefix + '/projections/' + variant + '.json'])
            require(projection['sha256'] == manifest['files'][variant + '/report.json'], 'fresh report hash binding')
            p = [v['retained_original_fields'] for v in projection['phases']]
            require([v['requested_window_ns'] for v in p] == [4000000000, 4000000000], 'fresh window changed')
            require([v['client_confirmed_transactions'] for v in p] == [1, 0], 'fresh baseline/pressure outcome changed')
            require(p[1]['verification_errors'] == ['PUBLIC_REQUEST_DEADLINE'], 'fresh pressure error changed')
    raw = outer['api-and-readiness/api-and-readiness-c09dbbe992.tar.xz']
    require(len(raw) == 257600 and digest(raw) == API_SHA, 'frozen API/readiness archive changed')
    api = tar_bytes(raw);require(len(api) == 47 and sum(map(len, api.values())) == 4406411, 'API/readiness original file totals')
    require(digest(api['SHA256SUMS']) == API_OLD_INDEX_SHA, 'API/readiness original checksum list changed')
    listed = set()
    for line in api['SHA256SUMS'].decode().splitlines():
        expected, name = line.split('  ', 1);safe(name)
        require(digest(api[name]) == expected and name not in listed, 'API/readiness member hash');listed.add(name)
    require(set(api) == listed | {'SHA256SUMS'}, 'API/readiness manifest coverage')
    zraw = api['c1-codeql-export-42955582970.zip']
    require(len(zraw) == 208483 and digest(zraw) == EXPORT_ZIP_SHA, 'CodeQL API export ZIP changed')
    exported = zip_bytes(zraw);require(len(exported) == 205, 'export member count')
    for name, prefix, missing in (('sha256.json', '', {'sha256.json', 'analysis/sha256.json'}),
                                   ('analysis/sha256.json', 'analysis/', {'analysis/sha256.json'})):
        manifest = parse(exported[name]);listed = set()
        for relative, expected in manifest.items():
            member = prefix + relative;require(digest(exported[member]) == expected, 'export manifest hash');listed.add(member)
        require({n for n in exported if n.startswith(prefix)} == listed | missing, 'export manifest coverage')
    result = parse(exported['analysis/result.json'])
    require(result['complete'] is False and result['target_pr_gate_authenticated'] is False, 'API gap promoted')
    require(result['target']['head'] == HEAD and result['target']['merge'] == MERGE, 'export source target')
    for n in range(1, 40):
        prefix = f'analysis/poll-{n:03}/'
        require(parse(exported[prefix + 'analyses-1.json']) == [], 'nonempty analysis response')
        for source in (HEAD, MERGE):
            checks = parse(exported[prefix + 'checks-' + source + '-1.json'])
            require(checks['total_count'] == 0 and checks['check_runs'] == [], 'nonempty exact-source CodeQL checks')
    polls = {n.split('/')[1] for n in exported if n.startswith('analysis/poll-')}
    require(len(polls) == 39, 'API poll count changed')
    review = outer['reviews/py-redos-bounded-review.json']
    require(len(review) == 2367 and digest(review) == '411f6aa6f924ed2b8e089c2387fe76ec7f3a8b4d33376e2723e97a0210602bcf', 'Python bounded review changed')
    return {'schema': 'c1-hosted-offline-verification-v1', 'distributed_bytes_verified': True,
        'outer_indexed_files': outer_count, 'native_packet_indexed_files': native_count,
        'bounded_packet_indexed_files': bounded_count, 'api_readiness_original_files': len(api),
        'local_codeql_cells': len(cells), 'sarif_results_per_cell': sarif_counts, 'api_export_polls': len(polls),
        'native_test_executions': 0, 'network_calls': 0, 'source_changes': False,
        'original_large_zip_bytes_reverified_by_this_portable_run': False,
        'original_large_zip_full_hash_verification_preserved_as_collector_receipts': True,
        'business_failures_preserved': True, 'C2_or_PQ_qualification_inferred': False}


if __name__ == '__main__':
    print(json.dumps(verify(), indent=2, sort_keys=True))

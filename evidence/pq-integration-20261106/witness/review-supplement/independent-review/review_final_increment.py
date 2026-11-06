#!/usr/bin/env python3
"""Independently hash and parse the frozen evidence increment, never its code."""
import collections
import csv
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import tarfile
import zstandard

ROOT = Path('/workspace/scratch/chain-pq-root-recovery-20261106-v1')
PUB = ROOT / 'final-witness-increment-v1/publication'
OUT = ROOT / 'integration-review/final-increment-independent-review-v1'
INDEX_SHA = '88d098f87c21e7e5170aa7f2440d0f73ec48f11b66081b9e67dca765825969ad'
PLAN_SHA = '2357bb2951cd794e2e84ceeb3a7b2b285e72ecbbd022aac1ab45d4f7ba200850'
ARCHIVE_SHA = '9f84ba375daa13b11650e173133bb042183bc4ed8570ff040aacc93c8e23027a'
HEAD = 'c07e8b9cce4621c5ef6f61256482bfe94e5a622f'
TREE = '35125592c14098385eab8693bbf05df0506d3610'
P = 'quantum-current-c07-terminal-v1/payload/'
N = P + 'native-witness-release-c07e8b9c-v2/'
V6 = {
    'final-evidence-delivery-v6/README.md': (65179, 'e26bd2977d8d61f6709338b73bb63527e5cfe9b31aec536d503d86205ed1de97'),
    'final-evidence-delivery-v6/qualification.json': (73250, '3b9568451dc3273cbd30a95d9869c4a85050249c880b12a86a931657204f23c4'),
    'final-evidence-delivery-v6/source-publication-map.json': (13234, 'ae5aa7f763bfb679f4de26064d06da31889add63b2de076623e3eefd7ddd0635'),
}

def require(value, message):
    if not value:
        raise ValueError(message)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def stable_read(path):
    before = path.stat()
    require(path.is_file() and not path.is_symlink(), 'non-regular input: ' + str(path))
    data = path.read_bytes()
    after = path.stat()
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
            'input changed while reading: ' + str(path))
    return data

def safe_relative(name):
    path = PurePosixPath(name)
    require(not path.is_absolute() and '..' not in path.parts and str(path) == name,
            'unsafe or noncanonical relative path: ' + name)
    return path

def main():
    require(not (OUT / 'review.json').exists(), 'create-only independent report already exists')
    index_bytes = stable_read(PUB / 'archive-index.json')
    plan_path = ROOT / 'integration-review/final-increment-selection-v1/frozen-selection.json'
    plan_bytes = stable_read(plan_path)
    require(sha(index_bytes) == INDEX_SHA and sha(plan_bytes) == PLAN_SHA, 'frozen index/plan mismatch')
    index, plan = json.loads(index_bytes), json.loads(plan_bytes)
    require(index['candidate'] == plan['candidate'] == HEAD and index['tree'] == plan['tree'] == TREE,
            'current code identity mismatch')
    require(index['schema'] == 'trnm-curated-evidence-archive-v1' and len(index['parts']) == 1,
            'unexpected archive schema/parts')
    part = index['parts'][0]
    require(part['number'] == 0 and part['file'] == 'raw-evidence.tar.zst.part-000'
            and part['bytes'] == index['archive_bytes'] == 1121155
            and part['sha256'] == index['archive_sha256'] == ARCHIVE_SHA, 'part identity mismatch')
    compressed = stable_read(PUB / part['file'])
    require(len(compressed) == part['bytes'] and sha(compressed) == ARCHIVE_SHA, 'part/whole-archive hash mismatch')
    with zstandard.ZstdDecompressor().stream_reader(io.BytesIO(compressed), read_across_frames=True) as reader:
        tar_bytes = reader.read()
    declared = {row['path']: row for row in index['members']}
    require(len(declared) == len(index['members']) == 971, 'index member count or uniqueness differs')
    data = {}
    member_identities = []
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode='r:') as archive:
        members = archive.getmembers()
        require(len(members) == 971, 'actual archive member count differs')
        require([item.name for item in members] == sorted(declared), 'actual member order/coverage differs')
        for member in members:
            safe_relative(member.name)
            require(member.isfile() and not member.issym() and not member.islnk()
                    and member.mode == 0o644 and member.uid == member.gid == 0
                    and member.mtime == 0 and member.uname == member.gname == '', 'unexpected tar metadata')
            raw = archive.extractfile(member).read()
            expected = declared[member.name]
            require(len(raw) == member.size == expected['bytes'] and sha(raw) == expected['sha256']
                    and expected['mode'] == 0o644, 'member bytes/mode mismatch: ' + member.name)
            raw.decode('utf-8')
            require(not raw.startswith((b'\x7fELF', b'\x1f\x8b', b'\x28\xb5\x2f\xfd')),
                    'binary or nested compressed payload found')
            data[member.name] = raw
            member_identities.append({'path': member.name, 'bytes': len(raw), 'sha256': sha(raw)})
        last = members[-1]
        end = last.offset_data + ((last.size + 511) // 512) * 512
        require(len(tar_bytes) - end >= 1024 and not tar_bytes[end:].strip(b'\0'), 'nonzero data after final tar member')
    require(sum(map(len, data.values())) == 21817264, 'aggregate member byte total differs')
    require(data['selection-plan.json'] == plan_bytes, 'embedded frozen selection differs')
    originals = {row['path']: row for row in plan['files']}
    generated = {'FILES.tsv', 'README.md', 'collection-status.json', 'file-manifest.json', 'selection-plan.json'}
    require(len(originals) == len(plan['files']) == 966 and set(data) == set(originals) | generated,
            'original/generated coverage differs')
    require(sum(row['bytes'] for row in originals.values()) == 20785236, 'original byte total differs')
    for path, row in originals.items():
        safe_relative(row['source'])
        require(len(data[path]) == row['bytes'] and sha(data[path]) == row['sha256'], 'frozen original differs')
        require(stable_read(ROOT / row['source']) == data[path], 'live frozen original changed: ' + row['source'])
    get = lambda path: json.loads(data[path])
    require(get('file-manifest.json')['files'] == plan['files'], 'generated manifest differs from frozen originals')
    tsv = list(csv.DictReader(io.StringIO(data['FILES.tsv'].decode()), delimiter='\t'))
    require(len(tsv) == 966 and len({row['path'] for row in tsv}) == 966, 'TSV coverage differs')
    for row in tsv:
        expected = originals[row['path']]
        require(row['sha256'] == expected['sha256'] and int(row['bytes']) == expected['bytes']
                and row['category'] == expected['category'], 'TSV identity differs')
    bindings = []
    binding_manifests = []
    for check in plan['checks']:
        require(check['kind'] == 'flat_manifest', 'unreviewed binding-check kind')
        rows = get(check['path'])[check['files_key']]
        for row in rows:
            relative = str(safe_relative(row[check['path_key']]))
            path = str(safe_relative(check['base'] + '/' + relative))
            require(path in data and len(data[path]) == row['bytes'] and sha(data[path]) == row['sha256'],
                    'raw manifest binding mismatch: ' + path)
            bindings.append({'manifest': check['path'], 'member': path, 'bytes': row['bytes'], 'sha256': row['sha256']})
        binding_manifests.append({'path': check['path'], 'sha256': sha(data[check['path']]), 'verified_entries': len(rows)})
    require(len(binding_manifests) == 9 and len(bindings) == 855, 'raw binding-check total differs')
    collection = get('collection-status.json')
    require(collection['copied_files'] == 966 and collection['copied_bytes'] == 20785236
            and collection['selection_plan_sha256'] == PLAN_SHA
            and collection['native_tests_executed_by_collector'] == 0
            and collection['archive_checks_are_native_test_results'] is False, 'collector scope differs')
    require([(x['path'], x['verified_entries']) for x in collection['declared_raw_binding_checks']]
            == [(x['path'], x['verified_entries']) for x in binding_manifests], 'collector declared binding counts differ')
    for path, (length, digest) in V6.items():
        require(len(data[path]) == length and sha(data[path]) == digest and stable_read(ROOT / path) == data[path],
                'actual frozen V6 file identity differs')
    qualification = get('final-evidence-delivery-v6/qualification.json')
    source_map = get('final-evidence-delivery-v6/source-publication-map.json')
    native = get(N + 'summary.json')
    require(qualification['current_phase']['native_original_summary'] == native, 'V6 changed raw native summary')
    require(native['tested_commit'] == HEAD and native['tested_tree'] == TREE and native['command_observations'] == 77
            and native['status_counts'] == {'succeeded': 74, 'failed': 1, 'blocked': 2}
            and native['success'] is False and native['source_before'] == native['source_after']
            and native['tls_witness_execution_readback_succeeded'] is False, 'original native failure/counts differ')
    rows = {}
    for path, raw in data.items():
        if path.startswith(N) and PurePosixPath(path).parent.as_posix() == N.rstrip('/') and path.endswith('.json'):
            obj = json.loads(raw)
            if isinstance(obj, dict) and obj.get('schema') == 'trnm-fixed-candidate-command-v2':
                require(obj['label'] not in rows and obj['tested_commit'] == HEAD, 'duplicate/wrong-source native receipt')
                rows[obj['label']] = obj
                log = data[N + obj['label'] + '.log']
                require(len(log) == obj['log_bytes'] and sha(log) == obj['log_sha256'], 'native original log binding differs')
    require(len(rows) == 77 and dict(collections.Counter(row['status'] for row in rows.values())) == native['status_counts'],
            'actual 77 receipt status counts differ')
    rosters = get(N + 'required-rosters.json')
    scopes = {**rosters['tls']['scopes'], 'witness-cli': rosters['witness']['scopes']['cli']}
    expected_counts = {'lib': 13, 'cli': 4, 'witness-cli': 5, 'feature-off': 1}
    node_observations = []
    for scope, count in expected_counts.items():
        require(len(scopes[scope]) == count, 'Node roster differs')
        for number, selector in enumerate(scopes[scope]):
            label = f'tls-{scope}-{number:02d}'
            row, reader = rows[label], rows[label + '-readback']
            text = data[N + label + '.log'].decode()
            failed = label == 'tls-witness-cli-00'
            require(selector in row['argv'], 'exact selector missing from native argv')
            require(row['status'] == ('failed' if failed else 'succeeded')
                    and row['exit_code'] == (101 if failed else 0)
                    and reader['status'] == ('blocked' if failed else 'succeeded'), 'Node outcome/reader differs')
            mark = 'FAILED' if failed else 'ok'
            require(len(re.findall(r'^test ' + re.escape(selector) + r' \.\.\. ' + mark + r'$', text, re.M)) == 1,
                    'literal original named test line differs')
            summary_pattern = r'^test result: FAILED\. 0 passed; 1 failed; 0 ignored;' if failed else r'^test result: ok\. 1 passed; 0 failed; 0 ignored;'
            require(len(re.findall(summary_pattern, text, re.M)) == 1, 'original one-case summary differs')
            node_observations.append({'label': label, 'selector': selector, 'status': row['status'], 'exit_code': row['exit_code']})
    require(collections.Counter(row['status'] for row in node_observations) == {'succeeded': 22, 'failed': 1}
            and rows['required-controls-readback']['status'] == 'blocked', '22+1/blocked boundary differs')
    failure_log = data[N + 'tls-witness-cli-00.log']
    require(sha(failure_log) == 'f7ccec6999a36da0202d0a17438d8a9882621957af0c7b6055fa62bfafdd5c39'
            and b'pq_tls_witness_cli.rs:71:14' in failure_log
            and b'Connection reset by peer (os error 104)' in failure_log, 'original panic not preserved')
    failure_report = get('integration-review/tls-audit-recovery-v2/first-witness-failure/failure-stage-readback.json')
    failure = failure_report['observed_failures'][0]
    semantic = qualification['current_phase']['native_semantic_readback']
    semantic_failure = semantic['observed_failures'][0]
    require(len(failure['assertions_not_reached']) == 6
            and semantic_failure['assertions_not_reached'] == failure['assertions_not_reached']
            and failure['root_cause_established'] is False and semantic_failure['root_cause_established'] is False
            and failure['later_reopen_or_rollback_claim_qualified_by_this_failed_control'] is False
            and semantic_failure['later_reopen_or_rollback_claim_qualified_by_this_failed_control'] is False,
            'unreached assertions/root-cause limits were rewritten')
    require(sum(row['passed'] for row in semantic['node_groups']) == 22
            and sum(row['failed'] for row in semantic['node_groups']) == 1, 'V6 Node counts differ')
    require(semantic['complete_release']['passed'] == 43 and semantic['initial_root_exact_repeats']['passed'] == 6
            and semantic['additional_unique_release_controls_from_repeats'] == 0
            and qualification['counting_policy']['additional_unique_release_names_from_repeats'] == 0,
            'release43/six overlap policy changed')
    require(rows['strict-workspace-clippy']['status'] == 'succeeded'
            and semantic['strict_workspace_clippy']['exit_code'] == 0, 'Clippy original observation differs')
    d6 = get(P + 'source-gates-d6ec50bb-v2/summary.json')
    d6_pass = [row for row in d6['commands'] if row.get('validation_passed') is True]
    d6_fail = [row for row in d6['commands'] if row.get('validation_passed') is not True]
    require(len(d6_pass) == 16 and len(d6_fail) == 4 and d6['all_commands_succeeded'] is False
            and d6['native_rust_tests_executed'] == 0, 'historical d6 failure reclassified')
    require(qualification['historical_d6']['passed'] == 16 and qualification['historical_d6']['failed'] == 4
            and qualification['historical_d6']['native_tests_executed'] == 0, 'V6 historical d6 classification differs')
    merge = get('initial-root-composition-5bb/merge-readback/original_summary.json')
    bad = [row for row in merge['commands'] if row['status'] != 'succeeded']
    require(merge['success'] is False and len(bad) == 1 and bad[0]['label'] == 'staged-diff-check'
            and bad[0]['exit_code'] == 2 and merge['native_tests_executed'] == 0
            and b'trailing whitespace' in data['initial-root-composition-5bb/merge-readback/original_diff.log'],
            'original merge rejection lost')
    require(qualification['historical_ca4_phase'] == get('recovered-controller/ca4-phase-qualification.json')
            and qualification['historical_ca4_phase_is_not_current_qualification'] is True,
            'old failed native history changed/requalified')
    require(source_map['historical_ca4_source_map'] == get('recovered-controller/ca4-phase-source_map.json'),
            'historical source map changed')
    for document in (qualification, source_map):
        require(document['whole_chain_pq_qualified'] is False
                and document['publication']['old_retained_and_terminal_archives_repacked'] is False
                and document['publication']['native_tests_on_containing_publication_claimed'] is False
                and document['publication']['required_direct_parent'] == HEAD, 'publication scope changed')
    require(qualification['disposition'] == 'HOLD_NO_GO' and qualification['archive_integrity_implies_product_qualification'] is False,
            'archive integrity promoted to qualification')
    exclusions = get(plan['exclusions'])
    require('Earlier retained and terminal archives, already preserved unchanged in c07 ancestry'
            in exclusions['also_excluded_categories'], 'old-package exclusion statement missing')
    require(not any(name.endswith(('.tar.gz', '.tar.zst', '.zip', '.elf')) or re.search(r'\.part-\d+$', name)
                    for name in data), 'old/nested archive or ELF body included')
    readme = data['final-evidence-delivery-v6/README.md'].decode()
    require('77 个命令/reader 观察 = 74 succeeded + 1 failed + 2 blocked' in readme
            and '不能宣称其后续重开与整目录回滚断言通过' in readme, 'current prose failed-control boundary missing')
    for label, job, expected_exit in [('native', '1a1b1114b10-fc05-757f', 1),
                                      ('d6', '1a1b0e5ac1f-fc05-73c8', 1)]:
        runtime = get(P + 'runtime-jobs/' + job + '/exit.json')
        require(runtime['exit_code'] == expected_exit and runtime['output_complete'] and runtime['output_durable']
                and qualification['current_phase']['runtime_terminals'][label]['exit_code'] == expected_exit,
                'original failed durable runtime changed')
    report = {'schema': 'trnm-final-increment-independent-integrity-review-v1',
              'state': 'ARCHIVE_INTEGRITY_AND_FAILURE_PRESERVATION_VERIFIED',
              'tested_code': HEAD, 'tested_tree': TREE,
              'index': {'path': str(PUB / 'archive-index.json'), 'bytes': len(index_bytes), 'sha256': INDEX_SHA},
              'selection': {'path': str(plan_path), 'bytes': len(plan_bytes), 'sha256': PLAN_SHA},
              'archive': {'parts': 1, 'bytes': len(compressed), 'sha256': ARCHIVE_SHA},
              'actual_members': 971, 'actual_member_bytes': 21817264,
              'original_members': 966, 'original_bytes': 20785236, 'generated_members': sorted(generated),
              'all_966_live_frozen_originals_equal_archived_bytes': True,
              'all_member_hashes_and_deterministic_metadata_verified': True,
              'member_identity_list_sha256': sha(json.dumps(member_identities, sort_keys=True).encode()),
              'manifest_binding_checks': binding_manifests, 'manifest_bindings_checked': len(bindings),
              'binding_list_sha256': sha(json.dumps(bindings, sort_keys=True).encode()),
              'v6_actual_three_files': [{'path': path, 'bytes': pair[0], 'sha256': pair[1]} for path, pair in V6.items()],
              'native_original_result': {'command_observations': 77, 'status_counts': native['status_counts'],
                                         'success': False, 'durable_exit_code': 1},
              'node_actual_named_observations': node_observations,
              'node_passed': 22, 'node_failed': 1,
              'failed_control_panic_preserved': 'pq_tls_witness_cli.rs:71:14: Connection reset by peer (os error 104)',
              'assertions_not_reached': failure['assertions_not_reached'], 'root_cause_established': False,
              'later_reopen_or_rollback_qualified': False,
              'historical_d6_source_only': {'passed': 16, 'failed': 4, 'native_executed': 0,
                                           'failed_labels': [row['label'] for row in d6_fail]},
              'original_merge_format_failure': {'label': bad[0]['label'], 'exit_code': 2, 'preserved': True},
              'historical_ca4_f85_ebd_qualification_object_preserved': True,
              'old_retained_and_terminal_archives_repacked': False,
              'archive_integrity_is_native_pass': False, 'publication_native_results_transferred': False,
              'archive_code_executed': False, 'project_or_native_commands_executed': 0,
              'source_verifiers_executed': 0, 'archive_elf_or_provider_bodies_rehashed_locally': False,
              'whole_chain_pq_qualified': False, 'production_activated': False,
              'method_sha256': sha(Path(__file__).read_bytes())}
    destination = OUT / 'review.json'
    with destination.open('x') as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write('\n')
    print(json.dumps({'review': str(destination), 'bytes': destination.stat().st_size,
                      'sha256': sha(destination.read_bytes()), 'members': 971, 'bindings': 855,
                      'native_result_remains_failed': True}, sort_keys=True))

if __name__ == '__main__':
    main()

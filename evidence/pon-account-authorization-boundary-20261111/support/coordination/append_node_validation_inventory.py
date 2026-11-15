#!/usr/bin/env python3
"""Append two independent Node evidence cohorts only after complete recovery.

The original empty result is preserved as incomplete and never gains a return
code. Existing 58 terminal record objects remain unchanged, and both previous
inventory byte snapshots remain available.
"""
from pathlib import Path, PurePosixPath
import collections
import datetime
import hashlib
import io
import json
import os
import re
import tarfile

BASE = Path('/workspace/scratch/a4188f5c86b5')
COORD = BASE / 'coordination'
HEAD = 'cdd984808a088e6c2e13b1e1ae6630a94d500c89'
TREE = '1ed39b6ebe55cb00c238f26f6bfc9361ab93faec'
DESKTOP = BASE / 'desktop-evidence' / HEAD
OLD_PINS = {'json': '91c7762d7918111a2276c059dae78da1e455a2f82036ab8edfaf1e3c2b626947',
            'md': 'a666177dee8f12b14c97065abdd23df194414be5126756cc69c26f36171f481e'}
DATA_IDS = ['node-retained-data-preflight', 'node-retained-data-source-before',
            'node-retained-data-all-targets', 'node-retained-data-source-after']


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def require(condition, text):
    if not condition:
        raise RuntimeError(text)


def read_json(path):
    return json.loads(path.read_bytes())


def verify_bundle(stem, transfer_name, archive_name):
    root = DESKTOP / stem
    transfer_path = DESKTOP / transfer_name
    transfer = read_json(transfer_path)
    archive = DESKTOP / archive_name
    raw = archive.read_bytes()
    require(len(raw) == transfer['archive_bytes'] and sha(raw) == transfer['archive_sha256'], 'archive pin differs')
    manifest_path = root / 'export-manifest.json'
    manifest_bytes = manifest_path.read_bytes()
    require(sha(manifest_bytes) == transfer['manifest_sha256'], 'manifest pin differs')
    manifest = json.loads(manifest_bytes)
    require(manifest['source_commit'] == HEAD and manifest['host'] == 'desktop', 'bundle cohort differs')
    require(manifest['acceptance_granted'] is False, 'bundle grants qualification')
    entries = {row['archive_member']: row for row in manifest['entries']}
    require(len(entries) == len(manifest['entries']), 'duplicate manifest members')
    expected = set(entries) | {'export-manifest.json'}
    actual = set()
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as tar:
        for member in tar:
            p = PurePosixPath(member.name)
            require(member.isfile() and not member.issym() and not member.islnk(), 'special member')
            require(not p.is_absolute() and '..' not in p.parts and p.as_posix() == member.name, 'unsafe member')
            require(member.name in expected and member.name not in actual, 'unexpected/duplicate member')
            data = tar.extractfile(member).read()
            require(len(data) == member.size and (root / member.name).read_bytes() == data, 'member bytes differ')
            if member.name in entries:
                row = entries[member.name]
                require(len(data) == row['bytes'] and sha(data) == row['sha256'], 'manifest member pin differs')
            actual.add(member.name)
    require(actual == expected, 'missing archive member')
    require({p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()} == expected,
            'unexpected extracted files')
    return root, manifest, {
        'archive': str(archive), 'archive_bytes': len(raw), 'archive_sha256': sha(raw),
        'extracted_directory': str(root), 'manifest_path': str(manifest_path),
        'manifest_sha256': sha(manifest_bytes), 'transfer_report': str(transfer_path),
        'transfer_report_sha256': sha(transfer_path.read_bytes()), 'member_count': len(expected),
        'archive_to_manifest_to_extracted_members_reverified': True,
        'acceptance_granted': False,
    }


def terminal_record(root, record_id):
    directory = root / 'primary' / 'validation' / HEAD / record_id
    raw = {name: (directory / name).read_bytes() for name in ('context.json', 'result.json', 'stdout.log', 'stderr.log')}
    context, result = json.loads(raw['context.json']), json.loads(raw['result.json'])
    hashes = {name: sha(data) for name, data in raw.items()}
    require(context['argv'] == result['argv'], 'context/result command argv differs')
    require(context['source_commit'] == result['source_head_before'] == result['source_head_after'] == HEAD,
            'terminal record source differs')
    require(context['source_tree'] == TREE and result['source_status_after'] == '', 'terminal source not exact/clean')
    require(result['id'] == record_id and bool(result['finished_utc']) and isinstance(result['pass'], bool),
            'terminal result malformed')
    computed_pass = result['returncode'] == 0 and result['launch_error'] is None
    require(result['pass'] is computed_pass and result['qualification_granted'] is False, 'terminal status contradicts facts')
    require(all(hashes[stream + '.log'] == result[stream + '_sha256'] for stream in ('stdout', 'stderr')),
            'log hash differs from original receipt')
    stdout, stderr = raw['stdout.log'].decode(), raw['stderr.log'].decode()
    text = stderr + '\n' + stdout
    return {
        'host': 'desktop', 'source_commit': HEAD, 'source_tree': TREE, 'id': record_id,
        'classification': 'PASS' if computed_pass else 'FAIL', 'recorded_pass': result['pass'],
        'computed_pass': computed_pass,
        'record_directory': str(Path(context['environment']['TRNM_CI_RECEIPT_DIR']).parent),
        'local_record_directory': str(directory), 'source_identity_consistent': True,
        'source_clean_after': True, 'raw_log_hashes_match_receipt': True,
        'full_local_receipts_reverified': True, 'receipt_hashes': hashes, 'raw_result': result,
        'test_summary_lines': re.findall(r'^test result:.*$', text, re.M),
        'running_binary_lines': re.findall(r'^\s*Running .+$', stderr, re.M),
        'failure_excerpts': [line for line in text.splitlines()
                             if '... FAILED' in line or line.startswith(('error:', 'FAIL:', 'ERROR:', 'test result: FAILED'))],
    }


def main():
    snapshots = []
    for ext, expected in OLD_PINS.items():
        path = COORD / ('final-validation-inventory.' + ext)
        raw = path.read_bytes()
        require(sha(raw) == expected, 'current inventory is not the reviewed 58-record snapshot')
        snapshot = COORD / ('final-validation-inventory-before-node-queues.' + ext)
        require(snapshot.read_bytes() == raw, 'preserved previous snapshot differs')
        snapshots.append({'path': str(snapshot), 'bytes': len(raw), 'sha256': sha(raw)})
    report = read_json(COORD / 'final-validation-inventory.json')
    old_records = json.loads(json.dumps(report['records']))
    require(len(old_records) == report['result_count'] == 58, 'unexpected original record count')
    old_root, old_manifest, old_bundle = verify_bundle('node-retained-evidence-v1',
        'node-retained-transfer-verification.json', 'desktop-node-retained-evidence-v1.tar.gz')
    require(old_manifest['schema'] == 'desktop-node-incomplete-evidence-export-v1', 'old Node schema differs')
    require(old_manifest['origin_job_id'] == '1a1c8980187-135c4-111', 'old Node job differs')
    require(old_manifest['complete_command_ids'] == ['node-retained-preflight'], 'old Node terminal declaration differs')
    require(old_manifest['incomplete_command_ids'] == ['node-retained-all-targets'], 'old Node incomplete declaration differs')
    require(old_manifest['absent_command_ids'] == ['node-retained-source-after'], 'old Node absence differs')
    data_root, data_manifest, data_bundle = verify_bundle('node-retained-data-evidence-v1',
        'node-retained-data-transfer-verification.json', 'desktop-node-retained-data-evidence-v1.tar.gz')
    require(data_manifest['schema'] == 'desktop-primary-evidence-export-v1', 'DATA schema differs')
    require(data_manifest['origin_job_id'] == '1a1c8ba754b-135c4-1d3', 'DATA job differs')
    require(data_manifest['complete_command_ids'] == DATA_IDS, 'DATA IDs differ')
    added = [terminal_record(old_root, 'node-retained-preflight')]
    added += [terminal_record(data_root, name) for name in DATA_IDS]
    existing_keys = {(r['host'], r['source_commit'], r.get('id', r['raw_result']['id'])) for r in old_records}
    require(not any((r['host'], r['source_commit'], r['id']) in existing_keys for r in added), 'new record already present')
    report['records'].extend(added)
    require(report['records'][:58] == old_records and len(report['records']) == 63, 'old record objects changed')
    pending_dir = old_root / 'primary' / 'validation' / HEAD / 'node-retained-all-targets'
    pending_files = {}
    expected_pending = {
        'context.json': (4332, '326711c660b4386e1b8a96e5e47eb42e75c8f300fb6b810264681063a530e879'),
        'result.json': (0, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'),
        'stdout.log': (0, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'),
        'stderr.log': (4193, '493e9415cd00edae5285702fc2c319b647549964a9a79bd7aa24f339424a23f0'),
    }
    for name, (size, expected) in expected_pending.items():
        raw = (pending_dir / name).read_bytes()
        require((len(raw), sha(raw)) == (size, expected), 'original incomplete bytes differ')
        pending_files[name] = {'bytes': size, 'sha256': expected, 'path': str(pending_dir / name)}
    incomplete = {
        'host': 'desktop', 'source_commit': HEAD, 'source_tree': TREE,
        'id': 'node-retained-all-targets', 'origin_job_id': '1a1c8980187-135c4-111',
        'classification': 'INCOMPLETE_EMPTY_RESULT', 'local_record_directory': str(pending_dir),
        'original_files': pending_files, 'included_in_completed_record_totals': False,
        'terminal_return_code_reconstructed': False, 'test_execution_established': False,
        'observations': old_manifest['observations'],
    }
    require(report['incomplete_context_directories'] == [], 'unreviewed incomplete records already present')
    report['incomplete_context_directories'] = [incomplete]
    report['incomplete_result_count'] = 1
    report['result_count'] = len(report['records'])
    grouped = {}
    for host in sorted({r['host'] for r in report['records']}):
        grouped[host] = {}
        for source in sorted({r['source_commit'] for r in report['records'] if r['host'] == host}):
            selected = [r for r in report['records'] if r['host'] == host and r['source_commit'] == source]
            grouped[host][source] = {
                'host': host, 'label': 'Z-current' if source == HEAD else 'Y-retained',
                'record_count': len(selected), 'status_counts': dict(collections.Counter(r['classification'] for r in selected)),
                'pass_ids': [r.get('id', r['raw_result']['id']) for r in selected if r['classification'] == 'PASS'],
                'fail_ids': [r.get('id', r['raw_result']['id']) for r in selected if r['classification'] == 'FAIL'],
            }
    report['by_host_and_source_commit'] = grouped
    report['generated_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    report['scope'] = ('All previously captured local-cloud and desktop primary/repository-truth/full-rust terminal records, '
                       'the original Node preflight, and the four independent DATA Node terminal records. '
                       'The original Node empty result is archived separately as incomplete, never PASS or FAIL.')
    report['prior_snapshot_before_node_queues_original_bytes'] = snapshots
    report['desktop_node_original_incomplete_receipt_archive'] = old_bundle
    report['desktop_node_data_receipt_archive'] = data_bundle
    report['desktop_node_original_incomplete_receipt_archive']['observations'] = old_manifest['observations']
    report['desktop_node_data_receipt_archive']['record_results'] = data_manifest['record_results']
    report['desktop_node_data_receipt_archive']['directory_inventory'] = data_manifest['directory_inventory']
    report['pending_remote_validation']['captured_archive_available'] = True
    report['pending_remote_validation']['classification'] = 'INCOMPLETE_EMPTY_RESULT'
    report['pending_remote_validation']['not_replaced_by_data_retry'] = True
    data_test = next(r for r in added if r['id'] == 'node-retained-data-all-targets')
    report['desktop_node_data_execution_observation'] = {
        'host': 'desktop', 'source_commit': HEAD, 'origin_job_id': '1a1c8ba754b-135c4-1d3',
        'record_id': data_test['id'], 'classification': data_test['classification'],
        'actual_running_headers': data_test['running_binary_lines'],
        'actual_summary_lines': data_test['test_summary_lines'],
        'actual_failure_lines': data_test['failure_excerpts'],
        'test_summary_lines_are_verbatim_including_nested_subprocesses': True,
        'nested_summaries_not_added_to_parent_totals': True,
        'compiled_targets_not_treated_as_executed': True, 'full_ci_acceptance_granted': False,
    }
    report['historical_old_target_presence'] = {
        'old_binary_identity_record_retained_unchanged': True,
        'subsequent_target_absence_observed': True, 'disappearance_cause': 'unknown',
        'original_binary_post_run_hash_is_not_current_presence_proof': True,
        'incident_directory': str(COORD / 'node-runtime-incident'),
    }
    require(report['interpretation']['full_ci_acceptance_granted'] is False and
            report['interpretation']['original_failures_reclassified_as_pass'] is False,
            'historical acceptance changed')
    counts = collections.Counter(r['classification'] for r in report['records'])
    lines = [
        '# Validation inventory', '',
        'Generated ' + report['generated_utc'] + '. Exact current source: `' + HEAD + '`; tree `' + TREE + '`.', '',
        str(len(report['records'])) + ' original terminal records are preserved by host and source: ' +
        str(counts['PASS']) + ' PASS and ' + str(counts['FAIL']) + ' FAIL. One separate original empty result is '
        '`INCOMPLETE_EMPTY_RESULT`; it has no fabricated return code and is counted as neither PASS nor FAIL.', '',
        '| Host | Source commit | Terminal records | PASS | FAIL |',
        '|---|---|---:|---:|---:|',
    ]
    for host, cohorts in grouped.items():
        for source, cohort in cohorts.items():
            lines.append('| ' + host + ' | ' + source + ' | ' + str(cohort['record_count']) + ' | ' +
                         str(cohort['status_counts'].get('PASS', 0)) + ' | ' + str(cohort['status_counts'].get('FAIL', 0)) + ' |')
    lines += ['', '## Preserved validation results', '',
        'The local M06 run executed 18 actual test binaries: 272 passed, 0 failed, and 9 ignored. '
        'The five new account development scope tests all passed. Their actual Running paths, post-run '
        'SHA256 values, sizes and stable-stat observations remain unchanged in the JSON inventory.', '',
        'The desktop primary queue retains five PASS records, including the four new Node tests and strict '
        'workspace Clippy with all targets and all features under -D warnings. Earlier local SIGKILL and '
        'tool/environment failures remain original FAIL records and are not retroactively replaced.', '',
        'The original full rust-baseline is FAIL, return code 101. The actual data-availability library '
        'reported 713 passed, 2 failed, 0 ignored. Its retained TCP shared-quota test returned Unavailable; '
        'the retained RS46 shard-plan test returned RS46 provider deadline. Complete panic text and logs '
        'remain in the frozen full Rust archive. Its supply-chain subgate independently passed all seven '
        'original subprocess observations, with qualification still false. The later feature-off record '
        'passed one test, and the original queue source-after verified clean exact Z.', '',
        '## Two independent Node follow-up queues', '',
        'The original Node scoped queue has a PASS preflight and an empty result for all-targets. '
        'Its original stderr records LLVM ENOSPC, its stdout is empty, and source-after was absent. '
        'The runtime outcome was unknown without a confirmed terminal receipt. The old dedicated target '
        'was subsequently absent; the disappearance cause remains unknown. No target cleanup or actor '
        'is inferred. All original bytes and incident observations are preserved in a separate archive.', '',
        'The DATA-volume queue uses different record IDs and a different target directory. '
        'Its four captured terminal records are:', '',
        '| Record | Result | Return code |', '|---|---|---:|']
    for record in added[1:]:
        lines.append('| ' + record['id'] + ' | ' + record['classification'] + ' | ' + str(record['raw_result']['returncode']) + ' |')
    lines += ['', 'Actual Cargo Running headers from the DATA all-targets stderr:', '']
    lines += ['- `' + row.strip() + '`' for row in data_test['running_binary_lines']]
    lines += ['', 'Original test summary lines, including nested subprocess output; these are not added together:', '']
    lines += ['- `' + row + '`' for row in data_test['test_summary_lines']]
    lines += ['', 'Target compilation is not counted as target execution. This queue does not replace '
        'the original incomplete attempt or the original full Rust failure.', '',
        '## Evidence and interpretation', '',
        'The JSON inventory records the complete result objects, original context/stdout/stderr hashes, '
        'frozen archive and transfer hashes, and all actual observed test totals. Archive members, manifests, '
        'and extracted bytes were reverified before this update. The previous 58 record objects are unchanged.', '',
        'The original before-additional-desktop snapshots and the exact before-node-queues snapshots '
        'remain separately preserved. The historical old-target Node ELF hash remains a post-run observation '
        'from that time, not a claim that the disappeared target currently exists.', '',
        'No full CI, production-node or PQ-network qualification is granted. Ignored tests, missing tools, '
        'incomplete receipts, and compiled-only targets are not promoted to PASS. Y and Z source cohorts '
        'and local-cloud/desktop hosts remain separate.', '']
    json_bytes = (json.dumps(report, indent=2, sort_keys=True) + '\n').encode()
    md_bytes = '\n'.join(lines).encode()
    for ext, raw in (('json', json_bytes), ('md', md_bytes)):
        temp = COORD / ('final-validation-inventory.next-node-queues.' + ext)
        with temp.open('xb') as output:
            output.write(raw)
        os.replace(temp, COORD / ('final-validation-inventory.' + ext))
    print(json.dumps({'terminal_records': len(report['records']), 'status_counts': dict(counts),
                      'incomplete_records': 1, 'json_sha256': sha(json_bytes), 'md_sha256': sha(md_bytes),
                      'new_record_ids': [r['id'] for r in added], 'old_record_objects_unchanged': True}, sort_keys=True))


if __name__ == '__main__':
    main()

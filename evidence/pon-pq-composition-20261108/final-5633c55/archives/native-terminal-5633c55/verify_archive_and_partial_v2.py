#!/usr/bin/env python3
"""Read archived evidence and independently count only retained outer records."""
from pathlib import Path
import collections
import gzip
import hashlib
import io
import json
import re
import tarfile

ROOT = Path(__file__).absolute().parent
PINS = {
    'native-terminal-evidence-5633c55.tar.gz': (602969, '53e0aef8dd10960f5dd5147df5bdd27ad1235fc481f152609c488cc0edb5a62e'),
    'manifest.json': (119873, '17af88252f270578b4f78a036a243c56fd762b206988437567b1ac87ee28ab0d'),
    'collection-result.json': (783, 'd75e3c57bd303bcdffb89fa8e543916defffe92fb7040aee64e3710ba558ede9'),
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    for name, (size, digest) in PINS.items():
        data = (ROOT / name).read_bytes()
        assert len(data) == size and sha(data) == digest, name
    raw = gzip.decompress((ROOT / 'native-terminal-evidence-5633c55.tar.gz').read_bytes())
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        members = archive.getmembers()
        names = [member.name for member in members]
        assert names == sorted(set(names))
        assert all(member.isfile() and not member.name.startswith('/')
                   and '..' not in Path(member.name).parts
                   and member.uid == member.gid == member.mtime == 0
                   and member.mode == 0o644 and not member.uname and not member.gname
                   for member in members)
        payloads = {member.name: archive.extractfile(member).read() for member in members}
    manifest = json.loads((ROOT / 'manifest.json').read_bytes())
    assert payloads['ARCHIVE-MANIFEST.json'] == (ROOT / 'manifest.json').read_bytes()
    records = manifest['source_files'] + manifest['additional_members']
    assert set(payloads) == {row['path'] for row in records} | {'ARCHIVE-MANIFEST.json'}
    for row in records:
        data = payloads[row['path']]
        assert len(data) == row['bytes'] and sha(data) == row['sha256'], row['path']

    roster_path = 'final-native-5633c55/node-default-lib.roster.json'
    roster = json.loads(payloads[roster_path])
    assert len(roster) == 1
    executable, item = next(iter(roster.items()))
    roster_names = item['names']
    assert len(roster_names) == len(set(roster_names))
    execution_prefix = 'final-native-5633c55/node-default-lib-execution-harnesses/'
    logs = [name for name in payloads if name.startswith(execution_prefix) and name.endswith('.libtest.log')]
    assert len(logs) == 1
    rows = []
    for line in payloads[logs[0]].decode().splitlines():
        if line.startswith('ignored: '):
            reason, name = line[len('ignored: '):].rsplit(' ', 1)
            assert reason and name in roster_names
            rows.append({'status': 'ignored', 'name': name, 'reason': reason})
        else:
            match = re.fullmatch(r'(ok|failed|ignored) (\S+)', line)
            assert match and match.group(2) in roster_names, 'unknown outer record'
            rows.append({'status': match.group(1), 'name': match.group(2)})
    by_name = {row['name']: row for row in rows}
    assert len(by_name) == len(rows), 'duplicate outer completion record'
    counts = dict(collections.Counter(row['status'] for row in rows))
    missing = sorted(set(roster_names) - set(by_name))
    actual_group = [dict(by_name.get(name, {'name': name, 'status': 'missing'}))
                    for name in roster_names if name.startswith('release_owner::execution_environment::tests::')]
    wrong_group = [name for name in roster_names if name.startswith('release_owner::execution_environment_tests::')]
    finish = [name for name in payloads if name.startswith(execution_prefix) and name.endswith('.finish.json')]
    assert not finish, 'this analysis is scoped to the known incomplete outer harness'
    receipt_path = 'final-native-5633c55/node-default-lib-run.receipt.json'
    receipt = json.loads(payloads[receipt_path])
    result = {
        'schema': 'trnm-independent-archived-node-partial-count-v2',
        'artifact_pins': {name: {'bytes': size, 'sha256': digest} for name, (size, digest) in PINS.items()},
        'all_archive_members_and_payload_sha256_verified': True,
        'archive_member_count': len(members), 'original_regular_files': len(manifest['source_files']),
        'roster_file': roster_path, 'roster_sha256': sha(payloads[roster_path]),
        'retained_outer_log': logs[0], 'retained_outer_log_sha256': sha(payloads[logs[0]]),
        'original_executable': executable, 'original_binary_identity': item['binary'],
        'discovered_roster_names': len(roster_names), 'partial_outer_records': len(rows),
        'partial_passed': counts.get('ok', 0), 'partial_failed': counts.get('failed', 0),
        'partial_ignored': counts.get('ignored', 0), 'missing_outer_completion_records': len(missing),
        'failed_names': [row['name'] for row in rows if row['status'] == 'failed'],
        'ignored_names_and_reasons': [row for row in rows if row['status'] == 'ignored'],
        'missing_names': missing,
        'original_harness_finish_present': bool(finish),
        'original_node_run_receipt': receipt,
        'actual_execution_environment_group': actual_group,
        'old_runner_execution_environment_tests_prefix_matches': wrong_group,
        'corrected_group_is_not_a_requalification_of_old_runner': True,
        'group_query_revision': 'v1 omitted the release_owner namespace; v2 uses exact prefixes read from the retained roster and original runner. Counts were unaffected; the v1 readback remains retained.',
        'previous_readback_sha256': '34f38bcb337df4b0d1b513c549b84cf7913c4c2756eb9d2191965baa3b226c22',
        'full_suite_counts_or_completion_claimed': False,
        'missing_names_are_not_classified_as_pass_fail_or_ignored': True,
        'raw_stdout_nested_test_summaries_used_for_counting': False,
        'original_evidence_modified': False, 'native_tests_executed': False,
        'whole_chain_pq_qualified': False,
        'parser_note': 'Outer libtest ignored: REASON NAME records are counted as ignored; the final whitespace-free name must match exactly one discovered roster name.',
    }
    with (ROOT / 'independent-partial-readback-v2.json').open('x') as stream:
        json.dump(result, stream, sort_keys=True, indent=2)
        stream.write('\n')
    print(json.dumps({key: result[key] for key in (
        'archive_member_count', 'original_regular_files', 'discovered_roster_names',
        'partial_outer_records', 'partial_passed', 'partial_failed', 'partial_ignored',
        'missing_outer_completion_records', 'original_harness_finish_present',
        'failed_names', 'actual_execution_environment_group',
        'old_runner_execution_environment_tests_prefix_matches',
        'full_suite_counts_or_completion_claimed')}, sort_keys=True, indent=2))
    print(json.dumps({'readback_sha256': sha((ROOT / 'independent-partial-readback-v2.json').read_bytes()),
                      'reader_sha256': sha(Path(__file__).read_bytes()),
                      'original_node_run_receipt': receipt}, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()

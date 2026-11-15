#!/usr/bin/env python3
"""Verify C2 failed cloud evidence without rerunning workloads."""
from pathlib import Path, PurePosixPath
import hashlib
import json
import re
import tarfile

SOURCE = {'commit': '0e554f36ffdde3053a5eb1756eb5e526b1935032',
          'tree': '753cdbad6714f00d8ccb9ddbb47f0fd71280ee62'}
PREFIX = 'python-validation-0e554f36ff/'


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def decode(data):
    return json.loads(data, object_pairs_hook=unique)


def main():
    root = Path(__file__).resolve().parent
    expected = {}
    for line in (root / 'CLOUD_SHA256SUMS').read_text().splitlines():
        digest, name = line.split('  ', 1)
        require(name == Path(name).name and name not in expected, 'checksum path')
        require(sha((root / name).read_bytes()) == digest, 'outer checksum: ' + name)
        expected[name] = digest
    actual = {p.name for p in root.iterdir() if p.is_file() and p.name != 'CLOUD_SHA256SUMS'}
    require(actual == set(expected), 'unexpected or missing package file')
    index = decode((root / 'cloud-raw-index.json').read_bytes())
    require(len(index) == len({r['path'] for r in index}), 'duplicate raw index path')
    raw = {}
    with tarfile.open(root / 'cloud-raw-0e554f36ff.tar.xz', 'r:xz') as archive:
        for member in archive.getmembers():
            name = PurePosixPath(member.name)
            require(member.isfile() and not name.is_absolute() and '..' not in name.parts
                    and member.name not in raw, 'nonregular/unsafe/duplicate archive member')
            raw[member.name] = archive.extractfile(member).read()
    require(set(raw) == {r['path'] for r in index}, 'raw member set')
    for row in index:
        data = raw[row['path']]
        require(len(data) == row['bytes'] and sha(data) == row['sha256'], 'raw content mismatch')
    def doc(name):
        return decode(raw[PREFIX + name])
    summary = doc('summary.json')
    require(summary['source'] == SOURCE and summary['source_unchanged'] is True
            and summary['all_selected_commands_passed'] is False, 'failed result upgraded')
    require(summary['status'] == 'HOLD_NO_GO' and all(summary[k] is False for k in
            ('whole_chain_pq_qualified', 'production_activation', 'hosted_ci_observed')), 'qualification upgraded')
    require(raw[PREFIX + 'source-before.json'] == raw[PREFIX + 'source-after.json'], 'source changed')
    snap = doc('source-before.json')
    require({k: snap[k] for k in SOURCE} == SOURCE and snap['full_checkout_materialized'] is False,
            'snapshot source or scope')
    require(len(snap['files']) == 5135 and len(snap['unmaterialized_sparse_paths']) == 22777,
            'sparse partition count')
    require(len({r['path'] for r in snap['files']}) == 5135
            and len(set(snap['unmaterialized_sparse_paths'])) == 22777
            and not {r['path'] for r in snap['files']}.intersection(snap['unmaterialized_sparse_paths']),
            'sparse partition duplicate or overlap')
    names = ['test_public_readiness_evidence', 'test_pq_research_integration',
             'hash_use_contract', 'pq_lifetime_budget', 'pq_authority_effect_register',
             'pq_root_dependency_register', 'check_ci_contract',
             'check_pq_research_integration', 'pq_chain_claim_guard']
    require([r['name'] for r in summary['commands']] == names, 'command roster')
    for row in summary['commands']:
        name = row['name']
        require(row == doc(name + '.receipt.json'), 'receipt/summary mismatch')
        require(row['argv'] == ['python3', '-B', 'scripts/ci/' + name + '.py'], 'argv changed')
        require(row['source_before'] == SOURCE and row['source_after'] == SOURCE
                and row['timed_out'] is False and row['timeout_seconds'] == 900, 'command source/budget')
        failed = name == names[0]
        require(type(row['exit_code']) is int and row['exit_code'] == int(failed)
                and row['passed'] is (not failed), 'command result')
        for stream in ('stdout', 'stderr'):
            ref = row[stream]
            require(ref['name'] == name + '.' + stream + '.log', 'stream path')
            data = raw[PREFIX + ref['name']]
            require(len(data) == ref['bytes'] and sha(data) == ref['sha256'], 'stream hash')
    failure = raw[PREFIX + names[0] + '.stderr.log'].decode()
    require(re.search(r'\nRan 71 tests in [0-9.]+s\n\nFAILED \(errors=3\)\n\Z', failure),
            'failed readiness completion')
    errors = re.findall(r'^ERROR: (.*)$', failure, re.M)
    require(len(errors) == 3 and not re.findall(r'^FAIL:', failure, re.M), 'actual errors')
    require(failure.count("FileNotFoundError: [Errno 2] No such file or directory: '/usr/bin/time'") == 3,
            'actual missing observer cause')
    corpus = raw[PREFIX + names[1] + '.stderr.log'].decode()
    require(re.search(r'\nRan 60 tests in [0-9.]+s\n\nOK\n\Z', corpus), 'corpus completion')
    observation = decode((root / 'cloud-observation.json').read_bytes())
    require(observation['source'] == SOURCE and observation['readiness_passed'] is False
            and observation['readiness_errors'] == errors and observation['readiness_terminal_exit'] == 1
            and observation['readiness_tests_run'] == 71 and observation['readiness_tests_completed_ok'] == 68
            and observation['corpus_tests_passed'] == 60 and observation['source_checker_commands_passed'] == 7
            and observation['materialized_bytes'] == sum(r['bytes'] for r in snap['files'])
            and observation['snapshot_sha256'] == sha(raw[PREFIX + 'source-before.json']), 'projection changed')
    print(json.dumps({'verified': True, 'raw_files': len(raw), 'source': SOURCE,
                      'readiness_result': 'FAILED (errors=3)', 'corpus_passed': 60,
                      'source_checkers_passed': 7, 'whole_chain_pq_qualified': False}, sort_keys=True))


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Verify preserved alert/graph evidence offline; do not rerun a GitHub request."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import tomllib

C1 = 'c09dbbe9921da12db8bf7240a8a95a0e9a789e50'
C2 = '0e554f36ffdde3053a5eb1756eb5e526b1935032'
ARCHIVE_SHA = '3e95e8d69ed76d6bcd11ab1a992e51ff703def2fa50ba7d50824a9e0a37038e4'
INDEX_SHA = 'bed1ad3ff7da527a47cae87a00d93401b544ba0516b316fc89aa34f8ffb7aea0'


def check(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def affected(version, spec):
    value = tuple(map(int, version.split('.')))
    results = []
    for clause in spec.split(','):
        match = re.fullmatch(r'(<=|>=|<|>|=)\s*(\d+\.\d+\.\d+)', clause.strip())
        check(match is not None, 'unsupported advisory version comparator')
        other = tuple(map(int, match[2].split('.')))
        results.append({'<': value < other, '>': value > other, '<=': value <= other, '>=': value >= other, '=': value == other}[match[1]])
    return all(results)


def verify(folder, repo=None):
    report = json.loads((folder / 'readback.json').read_bytes())
    path = folder / 'dependency-readback-originals.tar.xz'
    data = path.read_bytes()
    check(len(data) == 92960 and sha(data) == ARCHIVE_SHA, 'fixed archive identity')
    check(report['archive']['sha256'] == ARCHIVE_SHA and report['archive']['bytes'] == len(data), 'report/archive identity')
    with tarfile.open(path, 'r:xz') as archive:
        members = archive.getmembers()
        check(len(members) == 24 and len({m.name for m in members}) == 24, 'exact unique archive members')
        for m in members:
            p = PurePosixPath(m.name)
            check(m.isfile() and not p.is_absolute() and '..' not in p.parts, 'safe archive member')
        raw = {m.name: archive.extractfile(m).read() for m in members}
    check(sha(raw['archive-index.json']) == INDEX_SHA, 'fixed archive index identity')
    index = json.loads(raw['archive-index.json'])
    check(index['raw_files'] == 23 and index['raw_bytes'] == 2749202, 'raw totals')
    check(len(index['files']) == 23 and {x['path'] for x in index['files']} == set(raw) - {'archive-index.json'}, 'exact raw inventory')
    for item in index['files']:
        b = raw[item['path']]
        check(len(b) == item['bytes'] and sha(b) == item['sha256'], 'raw member hash: ' + item['path'])

    status = json.loads(raw['original-job/status.json'])
    check(status['job_id'] == '1a1c8c38b88-135c4-218' and status['state'] == 'succeeded' and status['exit_code'] == 0, 'known job terminal outcome')
    check(status['output_complete'] is True and status['output_durable'] is True and not any(status['log_truncated'].values()), 'complete original output')
    check(len(raw['original-job/stdout.log']) == status['log_bytes']['stdout']['stored'] == 24370, 'complete stdout extent')
    check(raw['original-job/stderr.log'] == b'' and status['log_bytes']['stderr']['stored'] == 0, 'complete stderr extent')
    cursors = json.loads(raw['original-job/read-cursors.json'])
    check([(x['stdout']['offset'], x['stdout']['next_offset']) for x in cursors] == [(0, 16384), (16384, 24370)], 'lossless read cursors')
    observation = json.loads(raw['original-job/stdout.log'])
    alerts_raw = raw['original-job/dependabot-alerts.raw.json']
    check(observation['raw_json'].encode() == alerts_raw, 'original raw API bytes')
    check(len(alerts_raw) == observation['raw_bytes'] == 22148 and sha(alerts_raw) == observation['raw_sha256'] == 'd1bab106d32091dfb5eecbd39a7f17c8b86c9052dba2146738250b61b4d889a9', 'original API byte identity')
    alerts = json.loads(alerts_raw)
    check(len(alerts) == observation['alert_count'] == 7 and observation['single_page_complete'] is True, 'complete seven-alert original observation')
    check(observation['authenticated_login'] == 'ProfHepta' and observation['method'] == 'GET', 'original API actor/method')
    check({level: sum(a['security_advisory']['severity'] == level for a in alerts) for level in ['high', 'medium', 'low']} == {'high': 4, 'medium': 2, 'low': 1}, 'severity counts')

    identities = json.loads(raw['source-review/c2-source-identities.json'])
    check(identities == report['c2_exact_source_identities'] and len(identities) == 8, 'source input inventory')
    for item in identities:
        b = raw['c2-source/' + item['path']]
        check(item['source_revision'] == C2 and len(b) == item['bytes'] and sha(b) == item['sha256'], 'C2 input bytes')
        blob = hashlib.sha1(b'blob ' + str(len(b)).encode() + b'\0' + b).hexdigest()
        check(item['git_ls_tree'].split()[1:3] == ['blob', blob], 'Git blob identity')
        if repo is not None:
            actual = subprocess.check_output(['git', '--no-replace-objects', '--no-optional-locks', '-C', str(repo), 'show', C2 + ':' + item['path']])
            check(actual == b, 'exact C2 repository object')
    pin = re.findall(r'^cryptography==([0-9.]+)$', raw['c2-source/formal/pon-nakamoto-v1/requirements.txt'].decode(), re.M)
    check(pin == ['50.0.2'], 'C2 exact requirements pin')
    for alert, mapping in zip(alerts, report['version_mapping'], strict=True):
        dep, vuln = alert['dependency'], alert['security_vulnerability']
        check(dep['package'] == {'ecosystem': 'pip', 'name': 'cryptography'} and dep['version_requirement'] == '= 41.0.7', 'reported package identity')
        check(dep['manifest_path'] == 'formal/pon-nakamoto-v1/requirements.txt', 'reported manifest')
        check(mapping['alert_number'] == alert['number'] and mapping['ghsa'] == alert['security_advisory']['ghsa_id'] and mapping['affected_range'] == vuln['vulnerable_version_range'], 'exact per-alert mapping')
        check(affected('41.0.7', mapping['affected_range']) and not affected(pin[0], mapping['affected_range']), 'positive old-version match and C2 exclusion')
        check(mapping['reported_version_in_range'] is True and mapping['c2_manifest_pin_in_range'] is False, 'mapping flags')

    diff = raw['source-review/c1-to-c2-paths.txt']
    check(diff.decode().splitlines() == ['config/pon/pq-cross-branch-corpus-v1.json', 'scripts/ci/check_public_readiness_evidence.py', 'scripts/ci/test_public_readiness_evidence.py'], 'bounded tracked source delta')
    if repo is not None:
        actual = subprocess.check_output(['git', '--no-replace-objects', '--no-optional-locks', '-C', str(repo), 'diff', '--name-only', C1, C2])
        check(actual == diff, 'exact C1-to-C2 delta')
    static = json.loads(raw['c1-metadata/original-static-summary.json'])
    check(static['source']['commit'] == C1, 'original graph execution identity')
    for result, (name, count) in zip(report['existing_metadata_review'], [('metadata-default', 177), ('metadata-all-features', 182), ('metadata-fuzz', 150)], strict=True):
        receipt = next(x for x in static['commands'] if x['name'] == name)
        check(receipt['exit_code'] == 0 and receipt['source_before'] == receipt['source_after'] == static['source'], 'original graph command completion/source')
        check('--no-deps' not in receipt['argv'] and '--locked' in receipt['argv'] and '--offline' in receipt['argv'], 'full graph command scope')
        for stream in ['stdout', 'stderr']:
            b = raw['c1-metadata/' + name + '.' + stream]
            check(len(b) == receipt[stream]['bytes'] and sha(b) == receipt[stream]['sha256'], 'original graph stream hash')
        graph = json.loads(raw['c1-metadata/' + name + '.stdout'])
        check(graph['resolve'] is not None and len(graph['packages']) == len(graph['resolve']['nodes']) == count, 'complete resolved graph size')
        ids = {p['id'] for p in graph['packages']}
        check({n['id'] for n in graph['resolve']['nodes']} == ids and all(d in ids for n in graph['resolve']['nodes'] for d in n['dependencies']), 'graph node/edge closure')
        check(not any(p['name'] == 'cryptography' for p in graph['packages']), 'no matching Cargo package identity')
        check(result['executed_commit'] == C1 and result['name'] == name and result['resolve_nodes'] == count, 'graph not relabelled as C2 run')
    for path, count in [('trillionnium/Cargo.lock', 182), ('tests/fuzz/Cargo.lock', 150)]:
        packages = tomllib.loads(raw['c2-source/' + path].decode())['package']
        check(len(packages) == count and not any(p['name'] == 'cryptography' for p in packages), 'exact C2 lock package identity mapping')
    check(sha(raw['interruption/partial-readback.json']) == 'eac9de969095823b0eef729d6d2c6262dd8deca48e398e0972a14d387add6db5', 'interrupted observation retained unchanged')
    check(report['post_interruption_metadata_review_completed'] is True, 'separate resumed graph review')
    check(report['default_branch_exact_commit'] is None, 'unobserved default branch SHA remains unknown')
    check(report['scope']['new_tests_executed'] == 0, 'no new tests claimed')
    check(all(value is False for key, value in report['scope'].items() if key != 'new_tests_executed'), 'scope and qualification flags')
    return {'verified': True, 'original_job_recovered': True, 'complete_alert_records': 7, 'affected_package_identities': 1, 'c2_pin': pin[0], 'c2_pin_inside_retained_ranges': 0, 'original_c1_graph_nodes': {'default': 177, 'all_features': 182, 'fuzz': 150}, 'c2_new_metadata_execution': False, 'repo_objects_rechecked': repo is not None, 'interrupted_observation_preserved': True, 'complete_vulnerability_scan': False, 'whole_chain_pq_qualified': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, help='Optional exact Git-object/delta recheck; still no resolution or network')
    args = parser.parse_args()
    print(json.dumps(verify(Path(__file__).resolve().parent, args.repo), indent=2, sort_keys=True))

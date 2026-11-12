#!/usr/bin/env python3
"""Audit exact original CI 43131129970 identities and gates; execute no native code."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import zipfile

HEAD = 'ff35430d27eea56dd803e05aa6d48573e37ed4c9'
TREE = 'ccf72585d2ac3b361ec169a62a607d7bce055582'
RUN, JOB, ARTIFACT = 43131129970, 130895252279, 13906427974
ZIP_SHA = 'c56b845bda15360abe3e45b2b3d3893d0990984220afd5bdcfb754b6e1bb9f82'
ZIP_BYTES = 8016966
PREFIX, HOST = 'sp27-receiver-strata/', 'sp27-receiver-strata-host/'
LIMITS = {'cpu.max': '25000 100000', 'cpu.max.burst': '0', 'memory.max': '2147483648',
          'memory.swap.max': '0', 'pids.max': '256'}
COMPILED = {
    'compiled_test_source_sha256': 'trillionnium/crates/trnm-pon-node/tests/public_v3_from_zero.rs',
    'compiled_health_module_sha256': 'trillionnium/crates/trnm-pon-node/tests/public_v3_from_zero/sp27_receiver_controls.rs',
    'compiled_strata_module_sha256': 'trillionnium/crates/trnm-pon-node/tests/public_v3_from_zero/sp27_receiver_strata.rs',
    'compiled_campaign_module_sha256': 'trillionnium/crates/trnm-pon-node/tests/public_v3_from_zero/sp27_receiver_campaign.rs',
}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def new_json(path, value):
    with path.open('xb') as stream:
        stream.write((json.dumps(value, indent=2, sort_keys=True) + '\n').encode())
    path.chmod(0o444)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    parser.add_argument('--source-repo', type=Path, required=True)
    parser.add_argument('--artifact-metadata', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    assert not args.out.exists(), 'output must be new'
    raw_zip = args.archive.read_bytes()
    assert len(raw_zip) == ZIP_BYTES and digest(raw_zip) == ZIP_SHA
    metadata = json.loads(args.artifact_metadata.read_bytes())
    artifacts = [row for row in metadata['artifacts'] if row['id'] == ARTIFACT]
    assert len(artifacts) == 1
    artifact = artifacts[0]
    assert artifact['size_in_bytes'] == ZIP_BYTES and artifact['digest'] == 'sha256:' + ZIP_SHA
    assert artifact['workflow_run']['id'] == RUN and artifact['workflow_run']['head_sha'] == HEAD
    git_env = os.environ.copy()
    git_env['GIT_NO_LAZY_FETCH'] = '1'
    git_env['GIT_TERMINAL_PROMPT'] = '0'

    def git(*argv):
        return subprocess.check_output(['git', '-C', str(args.source_repo), *argv], env=git_env)

    assert git('rev-parse', HEAD + '^{tree}').decode().strip() == TREE
    with zipfile.ZipFile(args.archive) as archive:
        entries = [entry for entry in archive.infolist() if not entry.is_dir()]
        names = [entry.filename for entry in entries]
        assert len(names) == len(set(names)) == 265
        members = {}
        for entry in entries:
            path = PurePosixPath(entry.filename)
            assert not path.is_absolute() and '..' not in path.parts
            assert not stat.S_ISLNK(entry.external_attr >> 16)
            raw = archive.read(entry)
            members[entry.filename] = {'bytes': len(raw), 'sha256': digest(raw), 'zip_crc32': f'{entry.CRC:08x}'}

        def load(name):
            return json.loads(archive.read(name))

        prepared = load(PREFIX + 'preparation.json')
        manifest = load(PREFIX + 'manifest.json')
        source = prepared['source_before']
        assert source == prepared['source_after'] == manifest['source_before'] == manifest['source_after']
        assert source['commit'] == HEAD and source['tree'] == TREE
        assert prepared['completed'] is True and prepared['failures'] == []
        assert prepared['job'] == manifest['job'] == {'GITHUB_JOB': 'health', 'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_RUN_ID': str(RUN)}
        declared = load('source.json')
        assert declared['tested_commit'] == HEAD and declared['tested_tree'] == TREE
        assert declared['tracked_worktree_verified'] is True
        assert source['tracked_source_identity'] == declared
        source_files = {}
        for path, expected in source['files_sha256'].items():
            raw = git('show', HEAD + ':' + path)
            assert digest(raw) == expected, path
            source_files[path] = {'bytes': len(raw), 'sha256': expected,
                'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}
        assert len(source_files) == 7
        binary = members[PREFIX + 'public_v3_from_zero']
        assert prepared['binary'] == manifest['binary_before'] == manifest['binary_after']
        assert binary['bytes'] == prepared['binary']['size_bytes']
        assert binary['sha256'] == prepared['binary']['sha256']
        identity = load(PREFIX + 'native/identity-before.json')
        assert identity == load(PREFIX + 'native/identity-after.json')
        assert identity['binary_identity_error'] is None and identity['binary_sha256'] == binary['sha256']
        assert identity['runner_declared_source_sha'] == HEAD
        assert identity['github_run_id'] == str(RUN) and identity['github_run_attempt'] == '1'
        for field, path in COMPILED.items():
            assert identity[field] == source_files[path]['sha256']

        runner_hosts = [load(HOST + 'inside-before.json'), load(HOST + 'inside-after.json')]
        controller = load(HOST + 'controller-result.json')
        child = load(HOST + 'child-result.json')
        assert controller['passed'] is True and controller['final_host_errors'] == []
        assert child['native_child_exit'] == 0 and child['host_errors'] == []
        assert controller['parent_reused'] is False
        assert controller['parent_lease'] == controller['final_parent_lease']
        assert runner_hosts[0]['parent'] == runner_hosts[1]['parent']
        for host in runner_hosts:
            assert host['limits'] == LIMITS and host['read_errors'] == {}
            assert host['boot_id'] == identity['boot_id']
            assert host['uid'] == host['gid'] == 1001
            assert host['thread_privileges'] == {'CapBnd': '0000000000000000', 'NoNewPrivs': '1'}
        native_host_members = [PREFIX + 'native/host-before.json', PREFIX + 'native/host-after.json']

        report = load(PREFIX + 'native/report.json')
        assert report['requested_window_ns'] == 4_000_000_000
        assert report['qualification'] == 'COLLECTED_CONTROL_SERIES'
        assert report['causal_mechanism_status'] == report['mechanism_status'] == 'UNKNOWN'
        assert report['planned_phases'] == report['attempted_phases'] == report['helper_invoked_phases'] == report['completed_phases'] == 13
        assert report['incomplete_phases'] == report['unstarted_phases'] == 0
        assert report['pressure_controls_planned'] == report['pressure_controls_attempted'] == report['pressure_controls_executed'] == 8
        assert report['pressure_controls_unstarted'] == 0
        assert report['healthy_completed_phases'] == 5 and report['health_gate_passed'] is True
        assert report['first_divergence'] is None
        assert len(report['phases']) == 13
        phases = []
        for i, row in enumerate(report['phases']):
            assert row['planned_index'] == i
            assert row['attempted'] is row['helper_invoked'] is row['completed'] is True
            member = PREFIX + 'native/' + row['raw_phase_record']
            assert members[member]['sha256'] == row['raw_phase_sha256']
            raw = load(member)
            assert raw['requested_window_ns'] == row['requested_window_ns'] == 4_000_000_000
            assert raw['workers'] == row['workers_max'] == (16 if row['arm'] is not None else 0)
            assert raw['client_confirmed_before_original_window_end'] == row['native_final_gate']
            assert raw['client_confirmed_transactions'] == row['client_confirmed_transactions']
            assert raw['confirmation_ended_ns'] == row['confirmation_ended_ns']
            assert raw['verification_errors'] == []
            observations = raw['observations']
            assert observations['records_not_retained'] == observations['measurement_failures'] == 0
            assert observations['counter_overflow'] is False
            for edge in ['before', 'after']:
                native_host_members.append(PREFIX + 'native/raw/' + row['phase_id'] + '-host-' + edge + '.json')
            endpoint = raw['confirmation_ended_ns']
            credited = raw['client_confirmed_before_original_window_end'] is True and type(endpoint) is int and 0 <= endpoint < 4_000_000_000
            phases.append({'planned_index': i, 'phase_id': row['phase_id'], 'kind': row['kind'],
                'arm': row['arm'], 'raw_member': member, 'raw_sha256': row['raw_phase_sha256'],
                'workers': raw['workers'], 'requested_window_ns': raw['requested_window_ns'],
                'confirmation_ended_ns': endpoint, 'original_native_final_gate': row['native_final_gate'],
                'strict_window_and_original_gate': credited, 'confirmed_transactions': raw['client_confirmed_transactions'],
                'control_integrity_met': row['control_integrity_met'], 'full_native_state_equal': raw['full_native_state_equal'],
                'observer_records': len(observations['records']), 'verification_errors': []})
        for member in native_host_members:
            host = load(member)
            assert host['verified'] is True and host['error'] is None
            assert host['fixed_parent'] == '/sys/fs/cgroup/trnmponpublic.slice'
        process = load(PREFIX + 'run/process.json')
        assert process == manifest['process'] and process['exit_code'] == 0 and process['timed_out'] is False
        assert process['stdout_sha256'] == members[PREFIX + 'run/stdout']['sha256']
        assert process['stderr_sha256'] == members[PREFIX + 'run/stderr']['sha256']
        assert manifest['runtime_limits_or_deadlines_changed'] is False
        assert manifest['causal_mechanism_established'] is False
        acquisition = {}
        for name in ['business-acquisition.json', 'strata-input-acquisition-native.json', 'strata-inputs-index.json']:
            full_name = PREFIX + 'native/' + name
            value = load(full_name)
            acquisition[name] = {'member': full_name, **members[full_name],
                'scalar_original_fields': {key: item for key, item in value.items() if type(item) in (bool, int, float) or item is None}}
        dt = [datetime.datetime.fromisoformat(host['observed_utc']) for host in runner_hosts]
        audit = {'schema': 'sp27-02-original-strata-ci-provenance-audit-v1',
            'source_commit': HEAD, 'source_tree': TREE, 'run_id': RUN, 'job_id': JOB, 'artifact_id': ARTIFACT,
            'artifact_bytes': ZIP_BYTES, 'artifact_sha256': ZIP_SHA, 'members_checked': len(members),
            'archive_crc_verified': True, 'platform_digest_verified': True,
            'source_files': source_files, 'binary': binary, 'identity_before_and_after': identity,
            'runner_host_before': runner_hosts[0], 'runner_host_after': runner_hosts[1],
            'native_host_readbacks_verified': native_host_members,
            'cooperative_parent_lease': controller['parent_lease'], 'parent_reused': False,
            'physical_cpu_exclusivity': 'NOT_ESTABLISHED; fixed-parent resource eligibility and cooperative ownership are verified',
            'qualification': report['qualification'], 'first_divergence': report['first_divergence'],
            'planned': 13, 'attempted': 13, 'helper_invoked': 13, 'completed': 13, 'incomplete': 0, 'unstarted': 0,
            'health_controls_completed': 5, 'pressure_controls_completed': 8,
            'strict_confirmed_transactions': sum(row['confirmed_transactions'] for row in phases if row['strict_window_and_original_gate']),
            'phases': phases, 'native_process': process, 'native_child_timeout_seconds': 90,
            'runner_inside_snapshot_interval_ns': round((dt[1] - dt[0]).total_seconds() * 1_000_000_000),
            'acquisition_member_identities': acquisition, 'mechanism_status': 'UNKNOWN',
            'new_native_runs_executed_by_audit': 0, 'implicit_git_lazy_fetch_disabled': True,
            'audit_script_sha256': digest(Path(__file__).read_bytes()),
            'scope': 'Original-byte/source/run/Host/denominator audit; independent frozen analysis supplies realized arrival, validation-stage, nested cost and 06 consumption details.'}
    args.out.mkdir(parents=True, exist_ok=False)
    new_json(args.out / 'RAW_SHA256.json', members)
    new_json(args.out / 'STRATA_CI_AUDIT.json', audit)
    print(json.dumps({'qualification': audit['qualification'], 'confirmed': audit['strict_confirmed_transactions'],
        'planned': 13, 'native_host_readbacks_verified': len(native_host_members), 'members_checked': len(members),
        'out': str(args.out), 'audit_sha256': digest((args.out / 'STRATA_CI_AUDIT.json').read_bytes())}, sort_keys=True))


if __name__ == '__main__':
    main()

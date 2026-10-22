#!/usr/bin/env python3
"""Read one retained original native campaign; never execute or certify a node.

The caller must pin the artifact file-list hash and measured source identities.
Hashes and internal consistency are checked, not host custody, software execution
identity, current-source applicability, cryptographic work or public-network TPS.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import zlib

import pon_public_v3_phase_read as phase_reader
from run_pon_w1_native_campaign import validate_resources

MAX_MANIFEST_BYTES = 1024 * 1024
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_FILES = 4096
MAX_JSON_BYTES = 64 * 1024 * 1024
SELECTOR = 'separate_process_work_and_signed_confirmation_campaign'
METHODS = ('prepared-generic', 'tiled-classical', 'tiled-strassen-one-level',
           'paired-product', 'maintenance-periodic', 'maintenance-integer-paired',
           'maintenance-prefix', 'maintenance-limb')
INPUTS = {'seed_transfers': 1024, 'seed_blocks': 4, 'business_blocks': 21,
          'phase_seconds': 30, 'modes': list(phase_reader.MODES),
          'attacker_processes': [0, 24, 24]}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def integer(value, *, signed=False):
    require(type(value) is int and (-2**127 if signed else 0) <= value < 2**127,
            'bounded integer required')
    return value


def exact_digest(value, digits=64):
    require(type(value) is str and re.fullmatch('[0-9a-f]{' + str(digits) + '}', value),
            'canonical hexadecimal digest required')
    return value


def strict_json(raw):
    def pairs(rows):
        value = {}
        for key, item in rows:
            require(key not in value, 'duplicate JSON key')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


class Bundle:
    """Read only descriptor-relative regular files, refusing symlink components."""
    def __init__(self, root, expected_manifest_sha256):
        self.fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            raw = self._read('artifact-files.json', MAX_MANIFEST_BYTES)
            require(hashlib.sha256(raw).hexdigest() == exact_digest(expected_manifest_sha256),
                    'artifact file-list SHA256 mismatch')
            manifest = strict_json(raw)
            rows = manifest['files']
            require(type(rows) is list and 0 < len(rows) <= MAX_FILES, 'finite file list required')
            self.files = {}
            total = 0
            for row in rows:
                path = self.path_parts(row['path'])
                name = '/'.join(path)
                require(name not in self.files and name != 'artifact-files.json',
                        'duplicate or recursive artifact path')
                size = integer(row['bytes'])
                require(size <= MAX_FILE_BYTES, 'artifact member exceeds byte bound')
                exact_digest(row['sha256'])
                total += size
                require(total <= MAX_TOTAL_BYTES, 'artifact total exceeds byte bound')
                self.files[name] = row
            # Check every listed member, including raw databases and failed rows.
            # Extra local audit outputs are not claimed as producer artifacts.
            for name in self.files:
                self._read(name, MAX_FILE_BYTES, retain=False, expected=self.files[name])
            self.manifest_sha256 = expected_manifest_sha256
            self.total_bytes = total
            self.coverage = 'full-artifact'
            self.verified_paths = set(self.files)
        except BaseException:
            os.close(self.fd)
            raise

    @staticmethod
    def path_parts(name):
        require(type(name) is str and name and '\\' not in name and '\0' not in name,
                'invalid artifact relative path')
        parts = name.split('/')
        require(all(part not in ('', '.', '..') for part in parts)
                and not PurePosixPath(name).is_absolute(), 'artifact path escapes root')
        return parts

    def _read(self, name, limit, *, retain=True, expected=None):
        parts = self.path_parts(name)
        directory = os.dup(self.fd)
        try:
            for part in parts[:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=directory)
                os.close(directory)
                directory = child
            fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                         dir_fd=directory)
            with os.fdopen(fd, 'rb') as stream:
                before = os.fstat(stream.fileno())
                require(stat.S_ISREG(before.st_mode) and before.st_size <= limit,
                        'bounded regular artifact file required')
                if expected is not None:
                    require(before.st_size == expected['bytes'], 'artifact member length mismatch')
                digest, chunks, size = hashlib.sha256(), [], 0
                while chunk := stream.read(min(1024 * 1024, limit - size + 1)):
                    size += len(chunk)
                    require(size <= limit, 'artifact member grew past byte bound')
                    digest.update(chunk)
                    if retain:
                        chunks.append(chunk)
                after = os.fstat(stream.fileno())
                require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                         before.st_ctime_ns) == (after.st_dev, after.st_ino, after.st_size,
                                                after.st_mtime_ns, after.st_ctime_ns),
                        'artifact member changed while reading')
                if expected is not None:
                    require(size == expected['bytes'] and digest.hexdigest() == expected['sha256'],
                            'artifact member SHA256 mismatch')
                return b''.join(chunks) if retain else None
        finally:
            os.close(directory)

    def raw(self, name, limit=MAX_JSON_BYTES):
        require(name in self.files, 'required artifact member not listed: ' + name)
        return self._read(name, limit, expected=self.files[name])

    def json(self, name):
        return strict_json(self.raw(name))

    def close(self):
        os.close(self.fd)


class SubsetBundle(Bundle):
    """An explicit lossless retained subset, never an implicit full-bundle fallback."""
    def __init__(self, root, expected_manifest_sha256):
        self.fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            self.retention = strict_json(self._read('retention.json', MAX_MANIFEST_BYTES))
            value = self.retention
            require(value['schema'] == 'pon-original-native-campaign-retained-subset-v1'
                    and value['coverage'] == 'retained-subset', 'explicit retained-subset schema required')
            original = value['original_manifest']
            raw = self._read(original['path'], MAX_MANIFEST_BYTES, expected=original)
            require(original['sha256'] == exact_digest(expected_manifest_sha256),
                    'artifact file-list SHA256 mismatch')
            rows = strict_json(raw)['files']
            require(type(rows) is list and 0 < len(rows) <= MAX_FILES, 'finite original file list required')
            self.files = {}
            total = 0
            for row in rows:
                name = '/'.join(self.path_parts(row['path']))
                require(name not in self.files and name != original['path'], 'duplicate original artifact path')
                require(integer(row['bytes']) <= MAX_FILE_BYTES, 'artifact member exceeds byte bound')
                exact_digest(row['sha256'])
                total += row['bytes']
                require(total <= MAX_TOTAL_BYTES, 'artifact total exceeds byte bound')
                self.files[name] = row
            require(integer(value['original_artifact_file_count']) == len(self.files),
                    'original file count mismatch')
            retained = value['files']
            require(type(retained) is list and 0 < len(retained) <= len(self.files),
                    'finite retained file list required')
            self.retained_files, paths, retained_bytes = {}, set(), 0
            for row in retained:
                name = '/'.join(self.path_parts(row['original_path']))
                path = '/'.join(self.path_parts(row['retained_path']))
                require(name in self.files and name not in self.retained_files
                        and path not in paths and path not in ('retention.json', original['path']),
                        'duplicate or unlisted retained path')
                expected = self.files[name]
                require(integer(row['bytes']) == expected['bytes'] and row['sha256'] == expected['sha256'],
                        'retained mapping contradicts original manifest')
                require(row['encoding'] in ('identity', 'gzip')
                        and integer(row['retained_bytes']) <= MAX_FILE_BYTES,
                        'bounded identity/gzip retention required')
                require(row['encoding'] == 'identity' or (
                    re.fullmatch(r'run-[123]-raw/report\.json', name)
                    and row['bytes'] <= MAX_JSON_BYTES), 'bounded original gzip report required')
                exact_digest(row['retained_sha256'])
                retained_bytes += row['retained_bytes']
                require(retained_bytes <= MAX_TOTAL_BYTES, 'retained total exceeds byte bound')
                if row['encoding'] == 'identity':
                    require(row['bytes'] == row['retained_bytes']
                            and row['sha256'] == row['retained_sha256'], 'identity retention changed bytes')
                self.retained_files[name] = row
                paths.add(path)
            self.coverage = 'retained-subset'
            self.verified_paths = set(self.retained_files)
            self.total_bytes = sum(self.files[name]['bytes'] for name in self.verified_paths)
            self.manifest_sha256 = expected_manifest_sha256
            for name in self.retained_files:
                self.raw(name, MAX_FILE_BYTES)
        except BaseException:
            os.close(self.fd)
            raise

    def raw(self, name, limit=MAX_JSON_BYTES):
        require(name in self.retained_files, 'required artifact member was not retained: ' + name)
        row = self.retained_files[name]
        require(row['bytes'] <= limit, 'decoded retention exceeds byte bound')
        wire = self._read(row['retained_path'], MAX_FILE_BYTES,
                          expected={'bytes': row['retained_bytes'], 'sha256': row['retained_sha256']})
        if row['encoding'] == 'gzip':
            try:
                with gzip.GzipFile(fileobj=io.BytesIO(wire)) as stream:
                    raw = stream.read(min(limit, row['bytes']) + 1)
            except (OSError, EOFError, zlib.error) as error:
                raise ValueError('invalid retained gzip report') from error
        else:
            raw = wire
        require(len(raw) == row['bytes'] and hashlib.sha256(raw).hexdigest() == row['sha256'],
                'decoded retention length/SHA256 mismatch')
        return raw


def source(value, head, tree):
    require(value['schema'] == 'trnm-ci-source-v1' and value['kind'] == 'head'
            and value['candidate'] == value['tested_commit'] == head
            and value['tested_tree'] == tree and value['base'] is None
            and value['prospective_merge'] is None
            and value['tracked_worktree_verified'] is True
            and value['tests_executed_by_identity_check'] is False,
            'measured source head/tree mismatch')
    require(integer(value['tracked_entries']) > 0 and integer(value['tracked_bytes']) > 0,
            'complete tracked source observation required')
    return value['tracked_entries'], value['tracked_bytes']


def resource(value):
    require(value['schema'] == 'trnm.resource-observation.v1', 'resource observation schema')
    validate_resources(value, 10)
    affinity = value['cpu_affinity']
    require(affinity == sorted(set(integer(n) for n in affinity)), 'canonical CPU affinity required')
    paths = [row['path'] for row in value['limits']]
    first = '/sys/fs/cgroup' + value['cgroup']
    require(paths[0] == first and paths[-1] == '/sys/fs/cgroup'
            and all(str(PurePosixPath(a).parent) == b for a, b in zip(paths, paths[1:])),
            'complete resource ancestor observation required')
    return [(row['path'], row['cpu.max'], row['memory.max']) for row in value['limits']]


def step(bundle, row, name, build=False):
    expected = ['+1.95.0', 'test', '--locked', '--offline', '--release', '--manifest-path',
                'trillionnium/Cargo.toml', '-p', 'trnm-pon-node', '--test', 'public_v3_multiprocess']
    expected += (['--no-run', '--message-format=json'] if build else
                 [SELECTOR, '--', '--exact', '--ignored', '--nocapture', '--test-threads=1'])
    require(row == bundle.json(name + '.step.json') and row['name'] == name
            and row['command'][1:] == expected
            and PurePosixPath(row['command'][0]).is_absolute()
            and PurePosixPath(row['command'][0]).name == 'cargo', 'original exact command required')
    timeout = 1800 if build else 600
    require(type(row['returncode']) is int and row['returncode'] == 0
            and row['error'] is None and row['complete_success'] is True
            and row['outer_stage_timeout_seconds'] == timeout
            and 0 < integer(row['elapsed_ns']) <= timeout * 1_000_000_000,
            'original step did not complete successfully inside its budget')
    require(type(row['elapsed_seconds']) in (int, float)
            and row['elapsed_seconds'] == row['elapsed_ns'] / 1_000_000_000,
            'step elapsed identity mismatch')
    for kind in ('stdout', 'stderr'):
        filename = name + '.' + kind + '.log'
        require(row[kind] == filename and row[kind + '_truncated'] is False,
                'complete original step log required')
        entry = bundle.files[filename]
        require(integer(row[kind + '_bytes']) == entry['bytes']
                and row[kind + '_sha256'] == entry['sha256'], 'step log identity mismatch')
    raw = bundle.raw(row['stdout'])
    if not build:
        text = raw.decode('utf-8')
        require(len(re.findall(r'^running 1 test$', text, re.M)) == 1
                and len(re.findall(r'^test result:', text, re.M)) == 1
                and re.search(r'^test ' + SELECTOR + r' \.\.\. ok$', text, re.M)
                and re.search(r'^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; '
                              r'[0-9]+ filtered out; finished in [0-9.]+s$', text, re.M),
                'exactly one original native test must have passed')
    return raw


def depletion(snapshot):
    meter, flow = snapshot['meter'], snapshot['actual_flow']
    require(meter['schema'] == 'public-v3-local-stored-cpu-budget-v1'
            and meter['burst_ns'] == 2_000_000_000
            and meter['start_reserve_ns'] == 100_000_000
            and meter['refill_ns_per_second'] == 250_000_000 and meter['worker_limit'] == 2,
            'original paid CPU budget required')
    if flow is None:
        require(snapshot['depleted'] is False, 'missing actual flow cannot prove depletion')
        return False
    for key, value in flow.items():
        if key.endswith('_ns') or key == 'live_owners':
            integer(value, signed=key in ('remaining_paid_credit_ns', 'stored_credit_ns'))
    require(flow['schema'] == 'public-v3-local-actual-cpu-flow-v1'
            and flow['balance_identity_verified'] is True
            and flow['paid_cpu_debit_ns'] == flow['live_debited_cpu_ns'] + flow['settlement_residual_cpu_ns']
            and flow['remaining_paid_credit_ns'] == flow['initial_credit_ns'] + flow['credited_refill_ns']
                - flow['paid_cpu_debit_ns'] - flow['settlement_discard_ns']
            and flow['stored_credit_ns'] == flow['remaining_paid_credit_ns'] - flow['booked_reservation_ns']
            and flow['booked_reservation_ns'] == flow['live_owners'] * meter['start_reserve_ns']
            and flow['unsettled_known_live_cpu_ns'] == flow['paid_cpu_debit_ns'] - flow['settled_full_cpu_ns'],
            'actual paid CPU balance identity mismatch')
    actual = (flow['initial_credit_ns'] == meter['burst_ns']
              and flow['remaining_paid_credit_ns'] < meter['start_reserve_ns']
              and flow['paid_cpu_debit_ns'] > meter['burst_ns'] - meter['start_reserve_ns']
              and type(snapshot['clock_failures']) is int and snapshot['clock_failures'] == 0
              and meter['accounting_unavailable'] is False)
    require(snapshot['depleted'] is actual, 'reported depletion contradicts actual paid CPU')
    return actual


def economics(report):
    actors = report['economics']
    require(len(actors) == len(METHODS), 'all original cost methods required')
    candidates = []
    for index, actor in enumerate(actors):
        require(actor['exit_success'] is True and actor['parent_forced_kill'] is False
                and actor['report']['error'] is None, 'failed cost actor retained')
        value = actor['report']['result']
        require(value['method'] == METHODS[index] and type(value['method_index']) is int
                and value['method_index'] == index and len(value['modes']) == 2
                and sum(m['reuse_preparation'] is False for m in value['modes']) == 1
                and sum(m['reuse_preparation'] is True for m in value['modes']) == 1,
                'original cost method/modes required')
        for mode in value['modes']:
            require(len(mode['samples']) == 3, 'three original cost samples required')
            for sample in mode['samples']:
                require(integer(sample['acquisition_cpu_ns']) > 0 and sample['errors'] == []
                        and len(sample['verified_winners']) == len(sample['searches']) == 4
                        and all('Ok' in row for row in sample['verified_winners']),
                        'original legal cost sample is incomplete')
        rejected = value['same_task_target_from_zero_samples']
        require(len(rejected) == 3 and all(integer(row['acquisition_cpu_ns']) > 0
                and len(row['relation_diagnostics']) == 4
                and all(item == {'Err': 'Transcript'} for item in row['relation_diagnostics'])
                for row in rejected), 'original from-zero cost sample is incomplete')
        cold = next(mode for mode in value['modes'] if mode['reuse_preparation'] is False)
        candidates.append([sorted(s['acquisition_cpu_ns'] for s in cold['samples'])[1], index])
    candidates.sort()
    require(report['selection_candidates_cpu_ns'] == candidates
            and report['best_observed_cold_legal_method'] == METHODS[candidates[0][1]]
            and report['economics_complete'] is True, 'observed cold-method selection mismatch')


def phase(value):
    summary = phase_reader.phase_summary(value)
    require('startup_or_campaign_error' not in value, 'failed phase has no positive acceptance')
    hostile = value['mode'] != 'baseline'
    require(value['state_backend'] == 'authenticated-v1' and value['duration_seconds'] == 30
            and value['attacker_processes_requested'] == value['attacker_processes_ready'] == (24 if hostile else 0),
            'original phase workload required')
    records = value['receiver_observation']['records']
    observer = value['receiver_observation']
    complete = (type(observer['records_not_retained']) is int and observer['records_not_retained'] == 0
                and type(observer['measurement_failures']) is int and observer['measurement_failures'] == 0
                and observer['counter_overflow'] is False
                and integer(observer['accepted_connections_seen']) == len(records)
                and len(records) <= integer(observer['capacity'])
                and all(row['complete'] is True and row['observation_failed'] is False for row in records))
    require(value['observer_complete'] is complete and complete, 'incomplete receiver observations')
    accepted = sum(row['full_work_accepted'] is True for row in records)
    rejected = sum(row['full_work_accepted'] is False for row in records)
    require(integer(value['full_work_accepted']) == accepted
            and integer(value['full_work_failed']) == rejected, 'receiver work aggregate mismatch')
    submissions, history = value['submissions'], value['history']
    require(len(submissions) == len(history) == 21
            and [integer(row['packet_index']) for row in submissions] == list(range(21)),
            'all 21 original block submissions/history reads required')
    require(all(row['status'] == 'ok' and row['returned_after_window'] is False
                and row['error'] is None for row in submissions + history)
            and all(row['client_import']['succeeded'] is True for row in history),
            'failed/late client observations cannot be discarded')
    rounds = value['confirmations']
    require([integer(row['round']) for row in rounds] == [0, 1, 2], 'three unique original rounds required')
    samples = []
    for sample in value['budget_samples']:
        start, end = integer(sample['observation_started_ns']), integer(sample['observation_ended_ns'])
        require(start <= end <= integer(sample['at_ns']), 'budget sample interval mismatch')
        observation = sample['meter'].get('Ok')
        if observation is not None:
            require(start <= integer(observation['sample_at_ns']) <= end, 'sample clock outside observation')
            if depletion(observation):
                samples.append((start, end, observation))
    first = samples[0][2] if samples else None
    require(value['depletion_meter'] == first
            and value['depletion_at_ns'] == (first['sample_at_ns'] if first else None)
            and value['genuine_budget_depletion_observed'] is bool(samples), 'depletion aggregate mismatch')
    attacks = []
    require(len(value['children']) == (24 if hostile else 0), 'all original attacker processes required')
    for child in value['children']:
        require(child['exit_success'] is True and child['parent_forced_kill'] is False
                and child['report']['error'] is None
                and child['report']['result']['attempt_cap_reached'] is False,
                'failed or capped actor retained')
        attacks.extend(child['report']['result']['calls'])
    require(all(row['status'] != 'ok' for row in attacks), 'hostile proof was accepted')
    attack_digests = {digest for row in attacks
                      if (digest := phase_reader.digest(row['public_request_body_digest'])) is not None}
    final_hostile = [row for row in records if row['operation'] == 1
                     and phase_reader.digest(row['body_digest']) in attack_digests]
    overlaps, depleted_rounds = [], []
    for row in rounds:
        start, end = integer(row['started_ns']), integer(row['ended_ns'])
        observation = row['observation']
        require(0 <= start <= end < 30_000_000_000
                and row['confirmed_inside_pressure_window'] is True
                and observation['confirmed'] is True and observation['reorged'] is False
                and observation['finalized'] is observation['execution_authority'] is False
                and type(observation['depth']) is int and observation['depth'] == 6
                and integer(observation['observed_height']) - integer(observation['included_height']) == 6
                and observation['transaction'] == row['transaction']
                and observation['included_block'] == row['included_block']
                and observation['observed_tip'] == row['tip']
                and int(exact_digest(observation['work_delta'], 128), 16)
                    >= int(exact_digest(observation['required_work_delta'], 128), 16),
                'original in-window signed confirmation observation required')
        overlaps.append(sum(integer(call['started_ns']) < end and integer(call['ended_ns']) > start
                            for call in attacks))
        before, after = row['receiver_hostile_before'], row['receiver_hostile_after']
        for key in ('matched_requests', 'work_started', 'work_rejected', 'work_accepted'):
            total = (len(final_hostile) if key == 'matched_requests' else
                     sum(record['full_work_started'] is True for record in final_hostile) if key == 'work_started' else
                     sum(record['full_work_accepted'] is (key == 'work_accepted') for record in final_hostile))
            require(integer(before[key]) <= integer(after[key]) <= total, 'hostile snapshot count mismatch')
        rejected_cpu = sum(integer(record['full_work_thread_cpu_ns']) for record in final_hostile
                           if record['full_work_accepted'] is False)
        require(integer(before['rejected_work_cpu_ns']) <= integer(after['rejected_work_cpu_ns']) <= rejected_cpu,
                'hostile snapshot CPU mismatch')
        hostile_rejected = (after['work_rejected'] > before['work_rejected']
                            and after['rejected_work_cpu_ns'] > before['rejected_work_cpu_ns'])
        require(row['receiver_hostile_work_rejected_during_round'] is hostile_rejected,
                'hostile round rejection aggregate mismatch')
        overlapping_depletion = any(start <= a <= b <= end for a, b, _ in samples)
        require(row['paid_credit_depletion_observed_during_round'] is overlapping_depletion,
                'round depletion overlap mismatch')
        depleted_rounds.append(overlapping_depletion)
        require(not hostile or hostile_rejected, 'round lacks observed hostile work rejection')
    require(value['attack_calls_overlapping_each_signed_round'] == overlaps
            and value['actor_reports_successful_without_cap_or_kill'] is True
            and value['all_signed_rounds_confirmed_in_window'] is True
            and value['receiver_client_state_equal'] is True
            and value['final_receiver_tip'] == value['final_client_tip']
            and value['verifier_errors'] == [] and accepted >= 21
            and value['final_meter']['in_flight'] == 0
            and value['final_meter']['accounting_unavailable'] is False
            and value['service_outcome']['Ok']['mutation_cpu_clock_failures'] == 0
            and (not hostile or (samples and any(depleted_rounds) and min(overlaps) > 0 and rejected > 0))
            and value['finite_phase_criteria_met'] is True, 'original finite phase criteria mismatch')
    return {'mode': value['mode'], 'confirmed_observation_rounds': 3,
            'scheduled_observation_rounds': 3, 'submitted_blocks': len(submissions),
            'depletion_overlapping_rounds': sum(depleted_rounds),
            'round_depletion_overlap': depleted_rounds,
            'observed_transaction_ids': [exact_digest(row['transaction']) for row in rounds],
            'retained_phase_readback': summary}


def read_campaign(root, expected_manifest_sha256, expected_head, expected_tree, *, retained_subset=False):
    exact_digest(expected_head, 40)
    exact_digest(expected_tree, 40)
    bundle = (SubsetBundle if retained_subset else Bundle)(root, expected_manifest_sha256)
    try:
        result = bundle.json('results.json')
        if retained_subset:
            retention = bundle.retention
            require(retention['source'] == {'head': expected_head, 'tree': expected_tree}
                    and retention['artifact']['repository'] == 'TrillionniumFoundation/Trillionnium-Chain'
                    and all(integer(retention['artifact'][key]) > 0 for key in
                            ('artifact_id', 'workflow_run_id', 'zip_bytes')),
                    'retained-subset provenance mismatch')
            exact_digest(retention['artifact']['zip_sha256'])
        require(result['schema'] == 'pon-original-native-campaign-ci-v1'
                and result['expected_head'] == expected_head and result['expected_tree'] == expected_tree
                and result['source_kind'] == 'head' and result['profile'] == 'release'
                and result['toolchain'] == '1.95.0' and result['state_backend'] == 'authenticated-v1'
                and result['planned_complete_runs'] == 3 and result['original_inputs'] == INPUTS
                and result['build_timeout_seconds'] == 1800
                and result['original_campaign_outer_timeout_seconds'] == 600
                and result['expected_resources'] == {'cpu_max': '400000 100000',
                    'memory_max': '17179869184', 'nice': 10}, 'original campaign identity required')
        source_counts = []
        for name in ('source-before.json', 'source-before-build.json', 'source-before-campaigns.json',
                     'source-after-native.json', 'source-after.json',
                     *(f'run-{n}-source-after.json' for n in (1, 2, 3))):
            source_counts.append(source(bundle.json(name), expected_head, expected_tree))
        require(all(row == source_counts[0] for row in source_counts), 'tracked source counts changed')
        require(result['source_after'] == bundle.json('source-after-native.json'), 'final source mismatch')
        resources = [bundle.json(name) for name in ('resource-before-build.json', 'resource-after-native.json',
                     *(f'run-{n}-resource-{when}.json' for n in (1, 2, 3) for when in ('before', 'after')))]
        limits = [resource(row) for row in resources]
        require(all(row == limits[0] for row in limits)
                and all(row['cgroup'] == resources[0]['cgroup'] for row in resources),
                'resource profile changed across runs')
        require(bundle.json('hardware.json')['machine'] == 'x86_64', 'actual x64 observation required')
        require(result['runner_sha256'] == bundle.files['run-native-campaign.py']['sha256'],
                'campaign runner hash mismatch')
        build_stdout = step(bundle, result['build'], 'build', build=True)
        artifacts = [row for row in map(strict_json, build_stdout.splitlines())
                     if row.get('reason') == 'compiler-artifact'
                     and row.get('target', {}).get('name') == 'public_v3_multiprocess'
                     and row.get('profile', {}).get('test') is True and row.get('executable')]
        require(len(artifacts) == 1, 'one actual compiler test artifact required')
        binary, artifact = result['binary'], artifacts[0]
        require(binary['retained'] == 'public_v3_multiprocess.bin'
                and binary['sha256_before'] == binary['sha256_after'] == bundle.files[binary['retained']]['sha256']
                and integer(binary['bytes']) == bundle.files[binary['retained']]['bytes']
                and binary['actual_compiler_artifact_profile'] == artifact['profile']
                and artifact['profile'] == {'debug_assertions': False, 'debuginfo': 0,
                    'opt_level': '3', 'overflow_checks': False, 'test': True}
                and artifact['profile']['debug_assertions'] is False
                and artifact['profile']['overflow_checks'] is False
                and type(artifact['profile']['debuginfo']) is int
                and binary['build_artifact'] == artifact['executable']
                and binary['build_separate_from_measured_campaign'] is True, 'release binary identity mismatch')
        before = bundle.json('binary-before.json')
        require(before['sha256_after'] is None
                and {k: v for k, v in before.items() if k != 'sha256_after'}
                    == {k: v for k, v in binary.items() if k != 'sha256_after'}, 'before-build binary mismatch')
        if retained_subset:
            require(bundle.retention['binary'] == {'sha256': binary['sha256_after'], 'bytes': binary['bytes']},
                    'retained binary metadata mismatch')
        attempts = result['attempts']
        require([integer(row['number']) for row in attempts] == [1, 2, 3], 'three original complete runs required')
        runs = []
        for attempt in attempts:
            name = 'run-' + str(attempt['number'])
            require(attempt == bundle.json(name + '-result.json')
                    and attempt['report_directory'] == name + '-raw', 'attempt identity mismatch')
            step(bundle, attempt['step'], name)
            stderr = bundle.raw(attempt['step']['stderr']).decode('utf-8')
            launched = re.findall(r'^\s*Running tests/public_v3_multiprocess\.rs \(([^)]+)\)$',
                                  stderr, re.M)
            require(launched == [binary['build_artifact']]
                    and attempt['step']['cwd'] == result['build']['cwd']
                    and PurePosixPath(attempt['step']['cwd']).is_absolute(),
                    'observed runtime executable/source directory mismatch')
            report_name = name + '-raw/report.json'
            require(attempt['report_sha256'] == bundle.files[report_name]['sha256'], 'report hash mismatch')
            report = bundle.json(report_name)
            prep = report['preparation']
            require(report['schema'] == 'native-public-v3-separate-process-campaign-v2'
                    and report['state_backend'] == prep['state_backend'] == 'authenticated-v1'
                    and prep['actual_signed_seed_transfers'] == 1024 and prep['seed_blocks'] == 4
                    and prep['business_blocks'] == len(prep['business']) == 21
                    and len(prep['seed']) == 4 and sum(integer(row['transactions']) for row in prep['seed']) == 1024
                    and [row['mode'] for row in report['phases']] == list(phase_reader.MODES),
                    'retained original workload mismatch')
            require(all(report[key] is False for key in ('cryptographic_hardness_qualified',
                    'work_profile_qualified', 'independent_operators', 'wan_qualified',
                    'production_candidate', 'release_ready')), 'unsupported qualification claim')
            economics(report)
            phases = [phase(row) for row in report['phases']]
            retained = bundle.json(name + '-phase-readback.json')
            readback_input = retained.pop('input')
            require(retained == phase_reader.analyze(report)
                    and readback_input['sha256'] == attempt['report_sha256']
                    and readback_input['bytes'] == bundle.files[report_name]['bytes']
                    and PurePosixPath(readback_input['report']).parts[-2:] == (name + '-raw', 'report.json'),
                    'retained phase-reader derivation mismatch')
            require(report['finite_experiment_criteria_met'] is True
                    and attempt['original_criteria_met'] is True and attempt['complete_success'] is True
                    and attempt['report_validation_failure'] is None, 'original run did not qualify')
            for value in phases:
                value.pop('retained_phase_readback')
            runs.append({'number': attempt['number'], 'elapsed_ns': attempt['step']['elapsed_ns'], 'phases': phases})
        require(result['complete_success'] is True and result['failure'] is None
                and result['finalization_failures'] == [], 'failed campaign remains failed')
        hostile = [p for row in runs for p in row['phases'] if p['mode'] != 'baseline']
        overlap = sum(p['depletion_overlapping_rounds'] for p in hostile)
        return {'schema': 'pon-original-native-campaign-readback-v1',
                'measured_head': expected_head, 'measured_tree': expected_tree,
                'artifact_manifest_sha256': bundle.manifest_sha256,
                'coverage': bundle.coverage, 'original_manifest_file_count': len(bundle.files),
                'verified_original_file_count': len(bundle.verified_paths),
                'verified_original_bytes': bundle.total_bytes,
                'binary_payload_hash_verified': binary['retained'] in bundle.verified_paths,
                'binary_sha256': binary['sha256_after'], 'original_three_run_record_consistent': True,
                'runs': runs, 'denominators': {'complete_runs': 3, 'phases': 9,
                    'submitted_block_observations': 189, 'confirmation_round_observations': 27,
                    'hostile_round_observations': 18, 'hostile_rounds_with_observed_depletion_overlap': overlap,
                    'all_hostile_rounds_depletion_overlapped': overlap == 18,
                    'unique_observed_transaction_ids': len({tx for row in runs for p in row['phases']
                                                          for tx in p['observed_transaction_ids']})},
                'scope': {'reader_executes_native_test': False, 'reader_replays_consensus_or_verifies_signatures': False,
                    'host_or_custody_attestation': False, 'same_host_controlled_loopback': True,
                    'resource_limits_are_ceilings_not_physical_reservations': True,
                    'source_binding_is_retained_observation_not_checkout_verification': True,
                    'depletion_overlap_is_full_sample_interval_inside_round_not_continuous_saturation': True,
                    'hostile_round_counters_are_retained_original_snapshots_not_reexecuted': True,
                    'omitted_files_or_complete_zip_verified': False if retained_subset else None,
                    'current_source_qualification': False, 'wan_qualified': False,
                    'independent_operators_qualified': False, 'cryptographic_hardness_qualified': False,
                    'model_benefit_measured': False, 'production_activation': False,
                    'sustainable_business_tps': None, 'unknown_is_not_zero': True}}
    finally:
        bundle.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifact-dir', type=Path, required=True)
    parser.add_argument('--expected-manifest-sha256', required=True)
    parser.add_argument('--expected-head', required=True)
    parser.add_argument('--expected-tree', required=True)
    parser.add_argument('--retained-subset', action='store_true',
                        help='Require retention.json and verify only its explicitly retained original files')
    args = parser.parse_args()
    try:
        value = read_campaign(args.artifact_dir, args.expected_manifest_sha256,
                              args.expected_head, args.expected_tree, retained_subset=args.retained_subset)
    except (OSError, ValueError, KeyError, TypeError, IndexError) as error:
        parser.exit(1, 'campaign readback refused: ' + str(error) + '\n')
    print(json.dumps(value, indent=2, sort_keys=True, allow_nan=False))


if __name__ == '__main__':
    main()

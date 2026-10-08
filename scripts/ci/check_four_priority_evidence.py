#!/usr/bin/env python3
"""Fail-closed integrity of one historical observation package, not acceptance."""
from pathlib import Path
import hashlib
import json
import re
import statistics
import subprocess
import sys

from check_invariant_evidence import ROOT, load, require, safe, source_bytes
sys.path.insert(0, str(ROOT / 'scripts'))
import pon_work_cost_report as cost

PACKAGE = 'evidence/pon-four-priority-audit-v1'
COMMIT = '3c63c8368187de895e1dc0df8bbc105c6f39f842'
TREE = '54d2f12c0d783f827d43bc626489f58ab75d7c31'
PAIRED_POLICY = 'config/pon/work-security-acceptance-v1.json'
PREVIEW_SOURCE_PATHS = {
    'trillionnium/Cargo.lock', 'trillionnium/Cargo.toml', 'rust-toolchain.toml',
    'trillionnium/crates/trnm-mvcc-fee/src/pon_commitment.rs',
    'trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs',
    'trillionnium/crates/trnm-pon-node/src/store/mempool.rs',
    'trillionnium/crates/trnm-pon-node/tests/local_mempool.rs',
}
WORK = set('README.md build.log collect_prepared_fresh.py collector-stdout.log diagnostic.exit diagnostic.json execution.json manifest.json native-stderr.log native-verification.json native-work.json packet-manifest.json paired-collector-stdout.log paired-verification.json summary.json paired/build.log paired/execution.json paired/manifest.json paired/prepared-cost.json paired/stderr.log'.split())
EXPECTED = {'README.md', 'manifest.json'} | {'work-cost/' + p for p in WORK} | {'preview/' + p for p in ('manifest.json', 'samples.json', 'benchmark.log')}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def members(folder):
    entries = list(folder.rglob('*'))
    require(not any(p.is_symlink() for p in entries), 'symlink in package')
    return {p.relative_to(folder).as_posix() for p in entries if p.is_file()}


def hashes(folder, manifest, expected):
    require(set(manifest['files']) == expected, 'manifest members differ')
    for name, digest in manifest['files'].items():
        require(isinstance(name, str) and Path(name).as_posix() == name and
                all(part not in ('', '.', '..') for part in name.split('/')), 'noncanonical path')
        require(isinstance(digest, str) and re.fullmatch('[0-9a-f]{64}', digest), 'invalid digest')
        require(sha(safe(folder, name)) == digest, 'changed artifact ' + name)


def tracked_package(root, folder):
    """Check stage-zero blobs, not just working files that may be globally ignored."""
    prefix = folder.relative_to(root).as_posix() + '/'
    result = subprocess.check_output(['git', 'ls-files', '--stage', '-z', '--', prefix], cwd=root)
    entries = {}
    for record in result.decode().split('\0'):
        if not record:
            continue
        header, name = record.split('\t', 1)
        mode, oid, stage = header.split()
        require(stage == '0' and mode in ('100644', '100755'), 'unmerged or nonregular package entry')
        entries[name[len(prefix):]] = oid
    require(set(entries) == EXPECTED, 'Git index missing/extra package members (including ignored logs)')
    for name, oid in entries.items():
        blob = subprocess.check_output(['git', 'cat-file', 'blob', oid], cwd=root)
        require(blob == safe(folder, name).read_bytes(), 'Git index differs from retained bytes: ' + name)


# The recorded four-priority artifact predates the joint-arrival diagnostic
# wording. Its source bytes and derived numerical/security gates are immutable.
# Remove ONLY the later non-executing warning when checking this one historical
# report; current-source work/security acceptance retains the stronger warning
# and joint-offer screening. No historical input is re-labelled as current.
NEW_JOINT_WARNING = (
    'joint offer spans/buckets are local timing checks, not authenticated arrival or attack saturation'
)


def historical_cost_diagnostic(raw, paired):
    result = cost.acceptance(raw, paired, '7' + 'f' * 63)
    require(result['service']['status'] == 'unmeasured' and
            result['local_observation_gate'] == 'not-accepted',
            'historical diagnostic must not claim service')
    require(result['limitations'].count(NEW_JOINT_WARNING) == 1,
            'historical diagnostic projection requires one exact new warning')
    result['limitations'].remove(NEW_JOINT_WARNING)
    return result


def artifacts(folder):
    require(members(folder) == EXPECTED, 'missing/extra package file')
    top = load(folder / 'manifest.json')
    require(top['schema'] == 'pon-four-priority-audit-local-observations-v1', 'package schema')
    hashes(folder, top, EXPECTED - {'manifest.json'})
    require(top['measured_source_commit'] == COMMIT and top['measured_source_tree'] == TREE, 'measured source')
    for key in ('production_activation', 'public_network_ready', 'work_hardness_accepted',
                'positive_model_efficacy_claimed', 'end_to_end_tps_claimed'):
        require(top[key] is False, 'unearned acceptance ' + key)
    for key in ('honest_service', 'physical_vram', 'independent_operators'):
        require(top[key] == 'unmeasured', 'unmeasured scope ' + key)
    for key in ('collection_source_clean_before_and_after', 'source_and_binary_identities_retained',
                'same_operator', 'preview_cold_reported_separately'):
        require(top[key] is True, 'collection scope ' + key)
    # Reject authority promotion even when an attacker recomputes outer hashes.
    forbidden = set(cost.FALSE_FLAGS) | {'public_service_measured', 'hardness_accepted',
                                       'fastest_adversary_qualified', 'fastest_adversary_implemented'}
    def no_acceptance(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key in forbidden:
                    require(item is False, 'unearned nested acceptance ' + key)
                no_acceptance(item)
        elif isinstance(value, list):
            for item in value:
                no_acceptance(item)
    for name in EXPECTED:
        if name.endswith('.json'):
            no_acceptance(load(folder / name))
    work = folder / 'work-cost'
    packet = load(work / 'packet-manifest.json')
    hashes(work, packet, WORK - {'packet-manifest.json'})
    hashes(work, load(work / 'manifest.json'), set('build.log execution.json native-stderr.log native-work.json summary.json'.split()))
    hashes(work / 'paired', load(work / 'paired/manifest.json'), set('build.log execution.json prepared-cost.json stderr.log'.split()))
    for record in (packet, load(work / 'execution.json'), load(work / 'paired/execution.json'),
                   load(work / 'native-verification.json'), load(work / 'paired-verification.json')):
        require(record['source_commit'] == COMMIT, 'work source commit')
        if 'source_tree' in record:
            require(record['source_tree'] == TREE, 'work source tree')
    native_execution = load(work / 'execution.json')
    paired_execution = load(work / 'paired/execution.json')
    native_inputs = native_execution['source_files_sha256']
    paired_inputs = paired_execution['source_files_sha256']
    inventory = cost.source_inventory(set(cost.git('ls-tree', '-r', '--name-only', COMMIT).splitlines()))
    require(bool(native_inputs) and set(native_inputs) == inventory, 'native source inventory')
    require(set(paired_inputs) == set(native_inputs) | {PAIRED_POLICY} and
            all(paired_inputs[name] == digest for name, digest in native_inputs.items()),
            'paired source inventory must equal native inputs plus recorded policy')
    for key in ('returncode', 'build_returncode'):
        require(type(paired_execution[key]) is int and paired_execution[key] == 0, 'paired execution failure')
    for key in ('source_clean_before', 'source_clean_after', 'source_head_unchanged_after',
                'source_inputs_unchanged_after', 'binary_unchanged_after'):
        require(paired_execution[key] is True, 'paired execution scope ' + key)
    raw = load(work / 'native-work.json')
    paired = load(work / 'paired/prepared-cost.json')
    require(len(raw['samples']) == top['original_work_samples'] == 32, 'original sample count')
    require(len(paired['samples']) == top['paired_work_samples'] == 64, 'paired sample count')
    require(all(sum(r['class'] == c for r in raw['samples']) == 8 for c in cost.CLASSES), 'class counts')
    groups = cost.prepared_samples(paired)
    require(len(groups) == 8 and all(len(rows) == 8 for rows in groups.values()), 'paired group counts')
    diagnostic = load(work / 'diagnostic.json')
    require(diagnostic == historical_cost_diagnostic(raw, paired), 'diagnostic derivation')
    require(diagnostic['local_observation_gate'] == 'not-accepted' and
            diagnostic['service']['status'] == 'unmeasured', 'diagnostic acceptance')
    require(type(top['expected_diagnostic_exit']) is int and top['expected_diagnostic_exit'] == 2 and
            (work / 'diagnostic.exit').read_bytes() == b'2\n', 'diagnostic exit')
    preview = load(folder / 'preview/manifest.json')
    require(set(preview['source']['sha256']) == PREVIEW_SOURCE_PATHS, 'preview source inventory')
    require(preview['result'] == 'PASS', 'preview execution result')
    for key in ('returncode', 'build_returncode'):
        if key in preview:
            require(type(preview[key]) is int and preview[key] == 0, 'preview execution failure')
    require(preview['source']['commit'] == COMMIT and preview['source']['tree'] == TREE, 'preview source')
    require(preview['source']['clean_before'] is True and preview['source']['clean_after'] is True, 'preview clean scope')
    for name, key in [('samples.json', 'raw_samples_sha256'), ('benchmark.log', 'raw_log_sha256')]:
        require(sha(folder / 'preview' / name) == preview[key], 'preview artifact hash')
    samples = load(folder / 'preview/samples.json')
    require(samples['samples_per_arm'] == top['preview_samples_per_arm'] == 8 and
            samples['prefixes'] == 16 and samples['state_keys'] == 4099, 'preview workload')
    for record in (samples, preview):
        require(record['public_network_ready'] is False and record['physical_memory_bound'] is False, 'preview acceptance')
    for arm in ('cold', 'warm'):
        medians = []
        for suffix in ('fresh_check_each_prefix_ns', 'operation_bound_ns'):
            values = samples[arm + '_' + suffix]
            require(len(values) == 8 and all(type(v) is int and v > 0 for v in values), 'preview samples')
            medians.append(statistics.median(values) / 1e6)
        fresh, bound = medians
        summary = preview['summary'][arm]
        require(summary['fresh_median_ms'] == fresh and summary['bound_median_ms'] == bound and
                summary['ratio_of_medians'] == fresh / bound and
                summary['component_elapsed_reduction_percent'] == (1 - bound / fresh) * 100, 'preview median derivation')
        if arm == 'warm':
            require(top['preview_warm_fresh_median_ms'] == fresh and top['preview_warm_bound_median_ms'] == bound and
                    top['preview_warm_ratio_of_medians'] == fresh / bound, 'top preview summary')
    return preview


def validate(root=ROOT):
    root = Path(root).resolve()
    folder = root / PACKAGE
    preview = artifacts(folder)
    tracked_package(root, folder)
    require(subprocess.check_output(['git', 'rev-parse', COMMIT + '^{tree}'], cwd=root).decode().strip() == TREE, 'Git source tree')
    for record in (load(folder / 'work-cost/paired/execution.json'), preview):
        inputs = record.get('source_files_sha256', record.get('source', {}).get('sha256'))
        for name, raw in source_bytes(root, COMMIT, list(inputs)).items():
            require(hashlib.sha256(raw).hexdigest() == inputs[name], 'historical source hash ' + name)
        binary = record.get('binary_sha256', record.get('binary', {}).get('sha256'))
        require(isinstance(binary, str) and re.fullmatch('[0-9a-f]{64}', binary), 'binary identity')
    receipt = cost.verify(folder / 'work-cost', require_current=False)
    return {'result': 'PASS', 'measured_source': COMMIT, 'package_files': len(EXPECTED),
            'git_index_bytes_verified': True, 'historical_observations_verified': True,
            'current_measured_inputs_match': receipt['current_measured_inputs_match'],
            'experiment_reexecuted': False, 'acceptance_granted': False}


if __name__ == '__main__':
    try:
        print(json.dumps(validate(), sort_keys=True))
    except (ValueError, KeyError, TypeError, OSError, subprocess.CalledProcessError) as error:
        print('FAIL: ' + str(error), file=sys.stderr)
        sys.exit(1)

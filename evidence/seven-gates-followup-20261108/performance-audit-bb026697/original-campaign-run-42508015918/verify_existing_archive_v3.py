#!/usr/bin/env python3
"""Read this exact retained campaign ZIP. No native execution or qualification."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import zipfile

HEAD = 'bb026697a972521009bc133ae6ed2b653e18e931'
TREE = '18175756871bf341586fc37be1b17a00ef1dd099'
ZIP_HASH = 'c696c8430a27d6c8a2ef5767c4e1f5dcfd4a48ee42fc044c8b0e966221ac3c43'
ROOT = Path(__file__).resolve().parent
REPO = Path('/workspace/scratch/3a200666069f/hepta_cell/chain-native')
ARCHIVE = ROOT / 'original-campaign-bb026697-attempt-1.zip'
SELECTED = ROOT / 'selected-original'
OUT = ROOT / 'archive-verification-v3.json'

def require(value, message):
    if not value:
        raise ValueError(message)

def strict_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate JSON field: ' + key)
            result[key] = value
        return result
    def invalid(value):
        raise ValueError('non-finite JSON: ' + value)
    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def retain(name, raw):
    path = SELECTED / name
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        require(path.is_file() and not path.is_symlink() and path.read_bytes() == raw,
                'existing selected original changed: ' + name)
    else:
        with path.open('xb') as stream:
            stream.write(raw)

def main():
    result = {'schema': 'trnm-original-campaign-archive-verification-v1',
              'started_utc': datetime.now(timezone.utc).isoformat(),
              'head': HEAD, 'tree': TREE, 'native_execution_performed': False,
              'qualification': 'HOLD', 'host_custody_authenticated': False,
              'all_checks_completed': False, 'failure': None}
    require(not OUT.exists(), 'new audit output required')
    try:
        require(subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=REPO,
                text=True).strip() == HEAD, 'auditor repository head')
        require(subprocess.check_output(['git', 'rev-parse', 'HEAD^{tree}'], cwd=REPO,
                text=True).strip() == TREE, 'auditor repository tree')
        pins = []
        for name in ('scripts/run_pon_w1_native_campaign.py',
                     'formal/pon-nakamoto-v1/bounded_process.py',
                     'scripts/pon_public_v3_phase_read.py',
                     'scripts/pon_public_v3_policy_read.py',
                     'scripts/ci/public_host_ci_observation.py',
                     'config/pon/public-resource-profile-vectors-v1.json'):
            raw = (REPO / name).read_bytes()
            require(raw == subprocess.check_output(['git', 'show', HEAD + ':' + name],
                    cwd=REPO), 'reader source bytes: ' + name)
            pins.append({'path': name, 'bytes': len(raw), 'sha256': sha(raw)})
        result['reader_source_pins'] = pins
        sys.dont_write_bytecode = True
        sys.path[:0] = [str(REPO / 'scripts'), str(REPO / 'scripts/ci')]
        from run_pon_w1_native_campaign import validate_resources
        from public_host_ci_observation import validate as validate_host
        from pon_public_v3_phase_read import analyze
        from pon_public_v3_policy_read import load_profiles, policy_id

        digest = hashlib.sha256()
        with ARCHIVE.open('rb') as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                digest.update(chunk)
        require(digest.hexdigest() == ZIP_HASH and ARCHIVE.stat().st_size == 71966725,
                'archive bytes/hash')
        result['archive'] = {'bytes': ARCHIVE.stat().st_size, 'sha256': ZIP_HASH}
        with zipfile.ZipFile(ARCHIVE) as z:
            infos = z.infolist()
            names = [row.filename for row in infos]
            require(len(names) == len(set(names)) <= 4097, 'finite unique archive members')
            for row in infos:
                parts = PurePosixPath(row.filename).parts
                require(parts and not PurePosixPath(row.filename).is_absolute()
                        and all(part not in ('', '.', '..') for part in parts)
                        and '\\' not in row.filename and not row.is_dir()
                        and not stat.S_ISLNK(row.external_attr >> 16),
                        'regular canonical ZIP member: ' + row.filename)
            manifest_raw = z.read('artifact-files.json')
            manifest = strict_json(manifest_raw)
            files = manifest['files']
            require(len(files) == len({row['path'] for row in files}), 'unique manifest paths')
            require(set(names) == {row['path'] for row in files} | {'artifact-files.json'},
                    'full archive file-set coverage')
            hashes = {}
            verified_bytes = 0
            for row in files:
                name = row['path']
                require(0 <= row['bytes'] <= 256 * 1024 * 1024,
                        'bounded manifest member: ' + name)
                require(z.getinfo(name).file_size == row['bytes'], 'member size: ' + name)
                h = hashlib.sha256()
                with z.open(name) as stream:
                    for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                        h.update(chunk)
                require(h.hexdigest() == row['sha256'], 'member digest: ' + name)
                hashes[name] = h.hexdigest()
                verified_bytes += row['bytes']
            result['manifest'] = {'sha256': sha(manifest_raw), 'listed_files': len(files),
                                  'verified_files': len(hashes), 'verified_bytes': verified_bytes,
                                  'all_zip_members_covered': True}
            for name in names:
                if '/' not in name and name != 'public_v3_multiprocess.bin':
                    retain(name, z.read(name))
            data = strict_json(z.read('results.json'))
            require(data['expected_head'] == HEAD and data['expected_tree'] == TREE
                    and data['source_kind'] == 'head', 'exact head result source')
            source_paths = ['source-before.json', 'source-before-build.json',
                            'source-before-campaigns.json', 'source-after-native.json',
                            'source-after.json'] + [f'run-{n}-source-after.json' for n in (1, 2, 3)]
            sources = [strict_json(z.read(name)) for name in source_paths]
            require(all(row == sources[0] for row in sources), 'source receipt equality')
            require(sources[0]['kind'] == 'head' and sources[0]['tested_commit'] == HEAD
                    and sources[0]['tested_tree'] == TREE and sources[0]['prospective_merge'] is None
                    and sources[0]['tracked_worktree_verified'] is True,
                    'source receipts exact head')
            require(data['source_after'] == sources[0], 'embedded final source')
            result['source_receipts'] = {'count': len(sources), 'all_identical': True,
                                         'receipt': sources[0]}
            compiler = [strict_json(line) for line in z.read('build.stdout.log').splitlines()]
            compiler = [row for row in compiler if row.get('reason') == 'compiler-artifact'
                        and row.get('target', {}).get('name') == 'public_v3_multiprocess'
                        and row.get('profile', {}).get('test') is True and row.get('executable')]
            require(len(compiler) == 1, 'one actual compiler artifact')
            binary = data['binary']
            require(binary['build_artifact'] == compiler[0]['executable']
                    and compiler[0]['profile'] == {'debug_assertions': False, 'debuginfo': 0,
                        'opt_level': '3', 'overflow_checks': False, 'test': True},
                    'exact release compiler profile')
            require(binary['sha256_before'] == binary['sha256_after']
                    == hashes[binary['retained']], 'retained executable payload hash')
            require(data['runner_sha256'] == hashes['run-native-campaign.py'], 'runner identity')
            result['binary'] = binary
            resource_paths = ['resource-before-build.json', 'resource-after-native.json'] + [
                f'run-{n}-resource-{when}.json' for n in (1, 2, 3) for when in ('before', 'after')]
            resources = []
            for name in resource_paths:
                value = strict_json(z.read(name))
                validate_resources(value, 10)
                resources.append({'file': name, 'cgroup': value['cgroup'],
                                  'nice': value['nice'], 'cpu_affinity': value['cpu_affinity'],
                                  'leaf_cpu_max': value['limits'][0]['cpu.max'],
                                  'leaf_memory_max': value['limits'][0]['memory.max'],
                                  'all_ancestor_limits_validated': True})
            require(len({row['cgroup'] for row in resources}) == 1, 'stable controller cgroup')
            result['controller_resources'] = resources
            config = load_profiles()
            expected_policy = policy_id(config, config['current_revision'], 8, 2000)
            require(data['expected_public_policy_id'] == expected_policy, 'expected policy pin')
            result['expected_public_policy_id'] = expected_policy
            run_checks, host_checks = [], []
            for n, attempt in enumerate(data['attempts'], 1):
                require(attempt['number'] == n and attempt == strict_json(z.read(f'run-{n}-result.json')),
                        'original attempt identity')
                command = attempt['step']
                require(command == strict_json(z.read(f'run-{n}.step.json')), 'native command receipt')
                stderr = z.read(command['stderr']).decode()
                launched = re.findall(r'^\s*Running tests/public_v3_multiprocess\.rs \(([^)]+)\)$',
                                      stderr, re.M)
                require(launched == [binary['build_artifact']], 'actual native executable path')
                stdout = z.read(command['stdout']).decode()
                require('test result: FAILED. 0 passed; 1 failed; 0 ignored;' in stdout
                        and command['returncode'] == 101 and command['error'] is None
                        and command['stdout_truncated'] is False
                        and command['stderr_truncated'] is False, 'retain actual native failure')
                report_name = f'run-{n}-raw/report.json'
                require(hashes[report_name] == attempt['report_sha256'], 'raw report identity')
                report = strict_json(z.read(report_name))
                retained = strict_json(z.read(f'run-{n}-phase-readback.json'))
                input_row = retained.pop('input')
                require(input_row['sha256'] == hashes[report_name]
                        and input_row['bytes'] == z.getinfo(report_name).file_size,
                        'phase reader input bytes')
                require(analyze(report) == retained, 'exact phase readback recomputation')
                run_checks.append({'number': n, 'returncode': command['returncode'],
                    'elapsed_seconds': command['elapsed_seconds'],
                    'raw_report_sha256': hashes[report_name],
                    'phase_readback_exactly_recomputed': True,
                    'finite_experiment_criteria_met': report['finite_experiment_criteria_met'],
                    'economics_complete_recorded': report['economics_complete']})
                for phase in report['phases']:
                    mode = phase['mode']
                    prefix = f'run-{n}-raw/{mode}-host-control/host/'
                    samples = {}
                    for label in ('outside-before', 'inside-before', 'inside-after', 'outside-after'):
                        path = prefix + label + '.json'
                        raw = z.read(path)
                        retain(path, raw)
                        samples[label] = strict_json(raw)
                    before = samples['outside-before']
                    require(before['uid'] > 0 and before['gid'] >= 0,
                            'nonroot original actor')
                    errors = {}
                    for label, sample in samples.items():
                        errors[label] = validate_host(sample, inside=label.startswith('inside'),
                            uid=before['uid'], gid=before['gid'],
                            cwd=command['cwd'],
                            reference=None if label == 'outside-before' else before)
                        require(not errors[label], 'public Host readback errors: ' + str(errors))
                    job = strict_json(z.read(f'run-{n}-raw/{mode}-host-control/phase-job.json'))
                    require(job['binary_sha256'] == binary['sha256_before'], 'phase executable hash')
                    context = phase['phase_process_context']
                    external = phase['external_controller_observation']
                    require(context['controller_cgroup'] == external['controller_cgroup']
                            == resources[0]['cgroup']
                            and context['same_original_receiver_and_verifier_owners'] is True
                            and context['scalar_policy_changed'] is False
                            and context['runtime_business_deadline_changed'] is False
                            and external['host_launcher_process_exit'] == 0,
                            'unchanged fixed Host placement')
                    host_checks.append({'run': n, 'mode': mode, 'sample_count': 4,
                        'validation_errors': errors, 'limits': before['limits'],
                        'phase_cgroup': context['phase_cgroup'],
                        'controller_cgroup': context['controller_cgroup'],
                        'phase_job_binary_sha256': job['binary_sha256']})
            result['runs'] = run_checks
            result['public_host_resources'] = host_checks
            require(data['complete_success'] is False
                    and data['failure'] == 'ORIGINAL_THREE_RUN_CAMPAIGN_FAILED'
                    and data['finalization_failures'] == [], 'failed result retained')
            result['native_failure'] = data['failure']
            result['all_checks_completed'] = True
            result['full_original_campaign_acceptance_reader_executed'] = False
            result['scope'] = ('Full ZIP and all original manifest members verified; '
                'source/binary/resource receipts and failed native invocations checked; '
                'three original phase derivations recomputed with exact pinned source. '
                'No native rerun, host custody attestation, or passing campaign claim.')
    except Exception as error:
        result['failure'] = type(error).__name__ + ': ' + str(error)
        raise
    finally:
        result['completed_utc'] = datetime.now(timezone.utc).isoformat()
        with OUT.open('x') as stream:
            json.dump(result, stream, indent=2, sort_keys=True)
            stream.write('\n')
    print(json.dumps(result, separators=(',', ':')))

if __name__ == '__main__':
    main()


#!/usr/bin/env python3
"""Pin v4 Node-adapter inputs and run exactly five preflight exercises, no proving.

The preflights are outside the later 23-request/4s quota experiment. Each has a
new store. Four typed FRI response mutations preserve canonical shape and all
transcript-bound fields; the actual adapter must reach the corresponding PCS
verification stage and reject before opening a receiver Node.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time

NODE_REPO = Path('/home/qian-qi/work/chain-w1-node-r4-f16ac')
NODE_REL = Path('formal/pon-nakamoto-v1/w1_node_adapter_research')
BACKEND_REL = Path('formal/pon-nakamoto-v1/w1_public_stark_research')
BACKEND_REPO = Path('/home/qian-qi/work/chain-w1-compact-backend-20261108-f16ac-r4')
FIXTURE = Path('/home/qian-qi/work/w1-r4-evidence-f16ac5/node-fixture-v1')
PROOF = Path('/home/qian-qi/work/w1-r4-evidence-f16ac5/node-full-proof-v1/proof')
BINARY = NODE_REPO / NODE_REL / 'target/release/w1-node-adapter-research'
MUTATOR = BACKEND_REPO / BACKEND_REL / 'target-r4-native/release/examples/mutate_last_query'
EXPECTED_BINARY = '271ac45cc709d1d6e91e9ff78c004668e5e4d2a690e3b4e963220e750bcbeb1b'
EXPECTED_MUTATOR = 'c2df52ce474b340ac6c3d7029f15f996f6421dd8b010d73fc75a1e9abff499c3'
SOURCE_EXPECTED = {
    str(NODE_REL / 'src/lib.rs'): '69457c74801b2ac7b42d5a95edb4a17c32d1664bc00d14d7235415863e891ec6',
    str(NODE_REL / 'src/main.rs'): 'ec8fc3116c4e5a17f134c1c9c61a0cfaa84a51de7306f9ce46fef9b358494c92',
    str(NODE_REL / 'tests/node_bridge.rs'): '9035dead75db8b2f66bfd8ce629ef78721647f096bc4d7c85e12fcb9a5ab9d66',
    str(BACKEND_REL / 'src/sha_schedule_air.rs'): '88557607225e402b6f16ec7edffb7c8b90ddfe14cc7e87a2640042a205011a64',
}
PROOF_EXPECTED = {
    'sha.proof.bin': ('af66da05a9ebab9f0f9224b7b7df19aa6fa8949152fcf714a95797a000728218', 3142981, b'W1P3SCS4'),
    'arith.proof.bin': ('b5ae0d59d060d6fd5c965e31f1ee3c082d3e2cad72a1002f191082c27395cb04', 454085, b'W1P3APC3'),
}
FIXTURE_NAMES = ('operator-plan.json', 'packet.bin', 'statement.bin', 'input.bin',
                 'prefix.bin', 'expected_header.bin', 'expected_artifacts.bin', 'fixture.json')
CASE_SPECS = (
    ('sha-last-fold-query-value', 'sha.proof.bin', 'last-fold-query-value', 'scheduled-sha', 13, 'FinalPolyMismatch', 'BeforeShaVerify', 'SHA_PROOF:'),
    ('sha-last-fold-auth-sibling', 'sha.proof.bin', 'last-fold-auth-sibling', 'scheduled-sha', 13, 'CommitPhaseMmcsError(CapMismatch)', 'BeforeShaVerify', 'SHA_PROOF:'),
    ('arith-last-fold-query-value', 'arith.proof.bin', 'last-fold-query-value', 'packed', 14, 'FinalPolyMismatch', 'BeforeArithmeticVerify', 'ARITHMETIC_PROOF:'),
    ('arith-last-fold-auth-sibling', 'arith.proof.bin', 'last-fold-auth-sibling', 'packed', 14, 'CommitPhaseMmcsError(CapMismatch)', 'BeforeArithmeticVerify', 'ARITHMETIC_PROOF:'),
)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        data = stream.read()
        after = os.fstat(stream.fileno())
    identity = lambda x: (x.st_dev, x.st_ino, x.st_size, x.st_mtime_ns, x.st_ctime_ns)
    if identity(before) != identity(after) or len(data) != before.st_size:
        raise RuntimeError('CHANGED_DURING_READ:' + str(path))
    return data, {'path': str(path), 'bytes': len(data), 'sha256': sha(data),
                  'device': before.st_dev, 'inode': before.st_ino, 'mtime_ns': before.st_mtime_ns,
                  'ctime_ns': before.st_ctime_ns, 'link_count': before.st_nlink}


def save(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def source_paths():
    paths = set()
    for relative in (NODE_REL, BACKEND_REL):
        root = NODE_REPO / relative
        for name in ('Cargo.toml', 'Cargo.lock', 'build.rs'):
            if (root / name).is_file():
                paths.add(root / name)
        paths.update((root / 'src').rglob('*.rs'))
        if relative == NODE_REL:
            paths.update((root / 'tests').rglob('*.rs'))
    for root in sorted((NODE_REPO / 'trillionnium/crates').iterdir()):
        if root.is_dir() and (root / 'Cargo.toml').is_file():
            paths.add(root / 'Cargo.toml')
            paths.update(root.glob('*.rs'))
            paths.update((root / 'src').rglob('*.rs'))
    for name in ('trillionnium/Cargo.toml', 'trillionnium/Cargo.lock'):
        if (NODE_REPO / name).is_file():
            paths.add(NODE_REPO / name)
    return sorted(paths)


def run_logged(root, name, args, env, timeout=40):
    target = root / 'preflight' / name
    target.mkdir(parents=True, exist_ok=False)
    started = time.monotonic_ns()
    utc = datetime.now(timezone.utc).isoformat()
    with (target / 'stdout.jsonl').open('xb') as stdout, (target / 'stderr.log').open('xb') as stderr:
        child = subprocess.Popen(['/usr/bin/time', '-v', '-o', str(target / 'resource.txt'), *args],
                                 stdout=stdout, stderr=stderr, env=env, start_new_session=True)
        try:
            code = child.wait(timeout=timeout)
            timed_out = False
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            code = child.wait()
            timed_out = True
    objects = []
    for line in (target / 'stdout.jsonl').read_text(errors='replace').splitlines():
        try:
            value = json.loads(line)
            if isinstance(value, dict):
                objects.append(value)
        except ValueError:
            pass
    resources = (target / 'resource.txt').read_text() if (target / 'resource.txt').is_file() else ''
    rss = re.search(r'Maximum resident set size \(kbytes\): (\d+)', resources)
    row = {'name': name, 'argv': args, 'started_utc': utc, 'start_ns': started,
           'end_ns': time.monotonic_ns(), 'exit_code': code, 'timed_out': timed_out,
           'max_rss_kib': int(rss.group(1)) if rss else None, 'objects': objects,
           'loadavg_after': Path('/proc/loadavg').read_text().strip()}
    save(target / 'observation.json', row)
    if code != 0 or timed_out:
        raise RuntimeError('PREFLIGHT_PROCESS_FAILED:' + name)
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('--coordination-cleared', required=True)
    args = parser.parse_args()
    root = args.output.resolve()
    inputs = root / 'inputs'
    inputs.mkdir(exist_ok=False)
    files = {}
    origins = {}

    def copy(path, name, expected=None, executable=False):
        data, record = read(path)
        if expected and record['sha256'] != expected:
            raise RuntimeError('EXPECTED_PIN_MISMATCH:' + str(path))
        target = inputs / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as stream:
            stream.write(data)
        if executable:
            target.chmod(0o700)
        record['copy'] = name
        files[name] = record
        origins[str(path)] = {'bytes': len(data), 'sha256': record['sha256']}
        return data

    cpus = sorted(os.sched_getaffinity(0))[:8]
    if len(cpus) != 8:
        raise RuntimeError('EIGHT_CPU_AFFINITY_UNAVAILABLE')
    os.sched_setaffinity(0, cpus)
    env = dict(os.environ, RAYON_NUM_THREADS='8', LC_ALL='C')
    with (root / 'preflight.stdout.log').open('xb') as so, (root / 'preflight.stderr.log').open('xb') as se:
        check = subprocess.run(['bash', 'scripts/project-preflight.sh'], cwd=BACKEND_REPO, stdout=so, stderr=se)
    if check.returncode != 0:
        raise RuntimeError('PROJECT_PREFLIGHT_FAILED')
    before_head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=NODE_REPO, text=True).strip()
    source_files = source_paths()
    for path in source_files:
        relative = path.relative_to(NODE_REPO).as_posix()
        copy(path, 'source/' + relative, SOURCE_EXPECTED.get(relative))
    copy(BINARY, 'node-adapter', EXPECTED_BINARY, True)
    copy(MUTATOR, 'mutate_last_query', EXPECTED_MUTATOR, True)
    for name in FIXTURE_NAMES:
        copy(FIXTURE / name, 'fixture/' + name)
    plan = json.loads((inputs / 'fixture/operator-plan.json').read_text())
    if bytes.fromhex(plan['expected_header']) != (inputs / 'fixture/expected_header.bin').read_bytes():
        raise RuntimeError('EXPECTED_HEADER_DIVERGENCE')
    if bytes.fromhex(plan['expected_artifacts']) != (inputs / 'fixture/expected_artifacts.bin').read_bytes():
        raise RuntimeError('EXPECTED_ARTIFACTS_DIVERGENCE')
    original = {}
    for name, (expected, length, magic) in PROOF_EXPECTED.items():
        data = copy(PROOF / name, 'cases/valid/' + name, expected)
        if len(data) != length or data[:8] != magic:
            raise RuntimeError('FIXED_PROOF_PROFILE_MISMATCH')
        original[name] = data
    cases = []
    for name, component_file, mode, component, degree, subtype, stage, prefix in CASE_SPECS:
        case_dir = inputs / 'cases' / name
        case_dir.mkdir(exist_ok=False)
        for proof_name in PROOF_EXPECTED:
            if proof_name != component_file:
                copy(PROOF / proof_name, 'cases/' + name + '/' + proof_name, PROOF_EXPECTED[proof_name][0])
        changed_path = case_dir / component_file
        observation = run_logged(root, 'mutate-' + name, [str(inputs / 'mutate_last_query'), mode,
            str(inputs / 'cases/valid' / component_file), str(changed_path)], env)
        mutation = observation['objects'][-1]
        if (mutation.get('status') != 'MUTATED_RESEARCH_PROOF_ONLY'
                or mutation.get('component') != component or mutation.get('degree_bits') != degree
                or mutation.get('queries') != 64 or mutation.get('transcript_fields_unchanged') is not True):
            raise RuntimeError('TYPED_MUTATION_INVARIANT:' + name)
        changed, record = read(changed_path)
        old = original[component_file]
        offsets = [i for i, (a, b) in enumerate(zip(old, changed)) if a != b]
        if (len(old) != len(changed) or changed[:8] != old[:8] or not offsets
                or len(offsets) != mutation['changed_byte_count']
                or sha(old) != mutation['proof_sha256_before']
                or sha(changed) != mutation['proof_sha256_after']):
            raise RuntimeError('MUTATION_BYTE_INVARIANT:' + name)
        record['source_kind'] = 'fresh typed mutation of pinned real proof; no proving'
        record['copy'] = changed_path.relative_to(inputs).as_posix()
        files[record['copy']] = record
        cases.append({'name': name, 'kind': 'malicious', 'component': component,
                      'mutation': mutation, 'changed_byte_offsets': offsets,
                      'expected_subtype': subtype, 'required_checkpoint': stage,
                      'expected_error_prefix': prefix})
    cases.append({'name': 'valid', 'kind': 'legitimate', 'expected_error': None, 'required_checkpoint': None})
    preflight = []
    for case in [cases[-1], *cases[:-1]]:
        name = case['name']
        destination = root / 'preflight-node-stores' / name
        destination.parent.mkdir(exist_ok=True)
        observation = run_logged(root, 'exercise-' + name, [str(inputs / 'node-adapter'), 'exercise',
            str(inputs / 'fixture'), str(inputs / 'cases' / name), str(destination), 'none'], env)
        final_outer = next((o for o in reversed(observation['objects']) if isinstance(o.get('result'), dict)), None)
        if final_outer is None:
            raise RuntimeError('MISSING_ADAPTER_OUTCOME:' + name)
        final = final_outer['result']
        stages = [o.get('stage') for o in observation['objects'] if o.get('event') == 'checkpoint']
        receiver = destination / 'receiver-node'
        if final.get('schema') != 'trnm-w1-node-adapter-exercise-v1':
            raise RuntimeError('ADAPTER_SCHEMA:' + name)
        if case['kind'] == 'malicious':
            error = final.get('error')
            if (not isinstance(error, str) or not error.startswith(case['expected_error_prefix'])
                    or case['expected_subtype'] not in error
                    or case['required_checkpoint'] not in stages or 'ProofVerified' in stages
                    or final.get('node_opened') is not False or receiver.exists()):
                raise RuntimeError('ADAPTER_TYPED_REJECTION_NOT_OBSERVED:' + name)
            case['expected_error'] = error
        else:
            outcome = final.get('outcome') or {}
            if (final.get('error') is not None or final.get('node_opened') is not True
                    or outcome.get('native_admitted') is not True or outcome.get('both_real_proofs_verified') is not True
                    or 'ProofVerified' not in stages or 'NodeCommitted' not in stages or not receiver.is_dir()):
                raise RuntimeError('ADAPTER_POSITIVE_FAILED')
        row = {'name': name, 'kind': case['kind'], 'exit_code': observation['exit_code'],
               'outer_wall_seconds': (observation['end_ns'] - observation['start_ns']) / 1e9,
               'max_rss_kib': observation['max_rss_kib'], 'stages': stages,
               'final': final, 'receiver_node_exists': receiver.exists(),
               'receipt_sha256': sha((destination / 'exercise.json').read_bytes()), 'result': 'PASS'}
        preflight.append(row)
        save(root / 'preflight' / ('exercise-' + name) / 'validated.json', row)
        print(json.dumps({k: row[k] for k in ('name', 'result', 'outer_wall_seconds', 'max_rss_kib', 'stages')}), flush=True)
    # Fixed before the measured batch: seven [M,M,L] groups, then two M.
    malicious = [c['name'] for c in cases if c['kind'] == 'malicious']
    schedule = []
    for group in range(7):
        schedule.extend((malicious[(2 * group) % 4], malicious[(2 * group + 1) % 4], 'valid'))
    schedule.extend((malicious[14 % 4], malicious[15 % 4]))
    if len(schedule) != 23 or schedule.count('valid') != 7 or any(schedule.count(n) != 4 for n in malicious):
        raise RuntimeError('FIXED_SCHEDULE_ERROR')
    unchanged = {name: sha(read(Path(name))[0]) == record['sha256'] for name, record in origins.items()}
    if not all(unchanged.values()):
        raise RuntimeError('SOURCE_ORIGINAL_CHANGED_DURING_PREFLIGHT')
    for name, record in files.items():
        if sha((inputs / name).read_bytes()) != record['sha256']:
            raise RuntimeError('INPUT_COPY_CHANGED:' + name)
    manifest = {'schema': 'w1-node-pressure-input-pins-v1', 'created_utc': datetime.now(timezone.utc).isoformat(),
                'coordination_cleared': args.coordination_cleared,
                'source_repository': str(NODE_REPO), 'source_head_before': before_head,
                'source_head_after_preflight': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=NODE_REPO, text=True).strip(),
                'source_observation_does_not_replace_build_receipt': True,
                'binary_expected_sha256': EXPECTED_BINARY, 'binary_version': 'root-final-v4',
                'source_expected': SOURCE_EXPECTED, 'origin_files': origins,
                'origin_files_unchanged_after_preflight': unchanged,
                'original_generation_rayon_num_threads': '8', 'preflight_cpu_affinity': cpus,
                'preflight': preflight, 'preflight_exercises': 5, 'preflight_typed_mutators': 4,
                'preflight_inside_four_second_budget': False, 'new_complete_proofs': 0,
                'case_schedule': schedule, 'cases': cases, 'files': files,
                'qualification': 'HOLD_NO_GO', 'production_node': False, 'single_node_service': False,
                'legitimate_distinct_fixtures': 1, 'legitimate_independent_processes_requested': 7,
                'seven_independent_production_submissions': False,
                'global_malicious_rejection_cost_bound': False,
                'setup_copying_and_controller_outside_workload_quota': True,
                'adapter_proof_archive_persistence_inside_worker_quota': True}
    save(inputs / 'manifest.json', manifest)
    save(root / 'preflight-summary.json', {k: manifest[k] for k in ('schema', 'binary_expected_sha256',
        'source_head_before', 'source_head_after_preflight', 'coordination_cleared', 'preflight_exercises',
        'preflight_typed_mutators', 'preflight_inside_four_second_budget', 'new_complete_proofs',
        'case_schedule', 'preflight', 'qualification')})
    print(json.dumps({'result': 'PASS', 'pinned_files': len(files), 'origin_files': len(origins),
                      'preflight_exercises': 5, 'typed_mutations': 4, 'new_complete_proofs': 0,
                      'input_manifest_sha256': sha((inputs / 'manifest.json').read_bytes())}), flush=True)


if __name__ == '__main__':
    main()

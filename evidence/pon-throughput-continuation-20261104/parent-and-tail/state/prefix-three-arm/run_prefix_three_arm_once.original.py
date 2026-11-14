#!/usr/bin/env python3
"""One independently registered M06 component experiment; never retries timing."""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import shutil
import subprocess
import sys
import time

ROOT = Path('/workspace/scratch/7318d5f890d1/chain-throughput')
WRAPPER = Path('/workspace/scratch/7318d5f890d1/run-throughput.sh')
OUT = Path('/workspace/scratch/7318d5f890d1/throughput-readback/m06-prefix-three-arm-b811-once')
EVIDENCE = ROOT / 'evidence/pon-throughput-continuation-20261104/parent-and-tail/state/prefix-three-arm'
SELECTOR = 'pon_commitment::unchanged_snapshot_tests::checked_prefix_three_arm_tests::checked_prefix_three_arm_full_binding_cost'
EXPECTED_REGISTRATION = '5a6d1f93426df5faac0eec39b97c3712cc41a2885ec925ebd173bad98ba2428a'
SPEC = importlib.util.spec_from_file_location('native_source_manifest', '/workspace/scratch/7318d5f890d1/throughput-readback/run_tail_native_controls.py')
SOURCE_MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SOURCE_MODULE)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def save(name, value):
    with (OUT / name).open('x') as stream:
        stream.write(json.dumps(value, indent=2, sort_keys=True) + '\n')


def registration():
    path = EVIDENCE / 'comparison-preregistration.json'
    assert sha(path) == EXPECTED_REGISTRATION, 'registration changed'
    value = json.loads(path.read_text())
    for path, expected in value['experiment_source_files'].items():
        assert sha(ROOT / path) == expected, path + ' changed after registration'
    return value


def run(command, stem, timeout=1200, cwd=ROOT):
    started = now()
    clock = time.monotonic_ns()
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    with (OUT / (stem + '.stdout')).open('xb') as stdout, (OUT / (stem + '.stderr')).open('xb') as stderr:
        try:
            result = subprocess.run(command, cwd=cwd, stdout=stdout, stderr=stderr, timeout=timeout)
            code = result.returncode
        except subprocess.TimeoutExpired:
            code = 124
    elapsed = time.monotonic_ns() - clock
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    return {'command': command, 'cwd': str(cwd), 'started_at': started, 'finished_at': now(),
            'exit_code': code, 'elapsed_ns': elapsed,
            'child_user_seconds': after.ru_utime - usage.ru_utime,
            'child_system_seconds': after.ru_stime - usage.ru_stime,
            'max_child_rss_kib': after.ru_maxrss,
            'stdout_sha256': sha(OUT / (stem + '.stdout')),
            'stderr_sha256': sha(OUT / (stem + '.stderr'))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['build', 'measure'])
    args = parser.parse_args()
    registered = registration()
    if args.mode == 'build':
        OUT.mkdir(parents=True, exist_ok=False)
        save('registration-bound.json', registered)
        before = SOURCE_MODULE.source()
        save('source-before-build.json', before)
        changed = set(subprocess.check_output(['git', 'diff', '--name-only', 'HEAD'], cwd=ROOT, text=True).splitlines())
        changed |= set(subprocess.check_output(['git', 'ls-files', '--others', '--exclude-standard'], cwd=ROOT, text=True).splitlines())
        snapshot = {}
        for path in sorted(changed & before['native_input_files'].keys()):
            destination = OUT / 'source-snapshot' / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / path, destination)
            assert sha(destination) == before['native_input_files'][path]
            snapshot[path] = sha(destination)
        save('source-snapshot.json', snapshot)
        preflight = run(['bash', 'scripts/project-preflight.sh'], 'preflight', 60)
        save('preflight-result.json', preflight)
        assert preflight['exit_code'] == 0
        env_code = """import json,os,subprocess,platform,pathlib
keys=['RUSTUP_TOOLCHAIN','RUSTUP_HOME','CARGO_HOME','CARGO_TARGET_DIR','CARGO_BUILD_JOBS','CARGO_INCREMENTAL','RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC','RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER','OPENSSL_DIR','OPENSSL_STATIC','RUST_TEST_THREADS']
caps={}
for name in ['cpu.max','cpu.stat','memory.max','cpuset.cpus.effective']:
 p=pathlib.Path('/sys/fs/cgroup')/name
 if p.exists(): caps[name]=p.read_text()
print(json.dumps({'environment':{key:os.environ.get(key) for key in keys},'compiler':subprocess.check_output(['rustc','-vV'],text=True),'cargo':subprocess.check_output(['cargo','--version'],text=True),'platform':platform.platform(),'cgroup':caps,'features':'M06 default; no --all-features','profile':'original Cargo test profile, per-package M06 opt-level 1'}))
"""
        environment = run(['bash', str(WRAPPER), 'python3', '-c', env_code], 'compiler-environment', 60)
        save('compiler-environment-result.json', environment)
        assert environment['exit_code'] == 0
        command = ['bash', str(WRAPPER), 'cargo', 'test', '--offline', '--locked', '--manifest-path', 'trillionnium/Cargo.toml', '-p', 'trnm-mvcc-fee', '--lib', '--no-run', '--message-format=json']
        print(json.dumps({'build_started': True, 'source_manifest_sha256': before['manifest_sha256'], 'source_files': len(before['native_input_files']), 'preregistration_sha256': EXPECTED_REGISTRATION}), flush=True)
        result = run(command, 'build')
        after = SOURCE_MODULE.source()
        save('source-after-build.json', after)
        result.update({'source_unchanged': before == after, 'source_manifest_sha256': before['manifest_sha256'], 'base_head': before['head'], 'preregistration_sha256': EXPECTED_REGISTRATION})
        artifacts = []
        for line in (OUT / 'build.stdout').read_text().splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if item.get('reason') == 'compiler-artifact' and item.get('target', {}).get('name') == 'trnm_mvcc_fee' and item.get('profile', {}).get('test') and item.get('executable'):
                artifacts.append(item)
        if result['exit_code'] == 0 and len(artifacts) == 1:
            artifact = artifacts[0]
            result['artifact'] = artifact
            result['executable_sha256'] = sha(Path(artifact['executable']))
            profile = artifact['profile']
            result['original_profile_verified'] = profile['opt_level'] == '1' and profile['debug_assertions'] is True and profile['overflow_checks'] is True
        else:
            result['artifact_count'] = len(artifacts)
        save('build-result.json', result)
        print(json.dumps({k: v for k, v in result.items() if k != 'artifact'}, sort_keys=True), flush=True)
        print((OUT / 'build.stderr').read_text()[-5500:], flush=True)
        registration()
        assert result['exit_code'] == 0 and result['source_unchanged'] and result.get('original_profile_verified')
        return 0
    build = json.loads((OUT / 'build-result.json').read_text())
    assert build['exit_code'] == 0 and build['source_unchanged'] and build['original_profile_verified']
    executable = Path(build['artifact']['executable'])
    before = SOURCE_MODULE.source()
    assert before == json.loads((OUT / 'source-before-build.json').read_text()), 'source changed after build'
    assert sha(executable) == build['executable_sha256'], 'compiled ELF changed'
    save('source-before-measurement.json', before)
    save('timed-attempt.started.json', {'started_at': now(), 'selector': SELECTOR, 'allowed_attempts': 1, 'preregistration_sha256': EXPECTED_REGISTRATION, 'executable_sha256': sha(executable), 'source_manifest_sha256': before['manifest_sha256']})
    command = ['bash', str(WRAPPER), str(executable), SELECTOR, '--exact', '--ignored', '--nocapture', '--test-threads=1']
    print(json.dumps({'timed_attempt_started': True, 'selector': SELECTOR, 'allowed_attempts': 1}), flush=True)
    result = run(command, 'measurement', 180, ROOT / 'trillionnium/crates/trnm-mvcc-fee')
    after = SOURCE_MODULE.source()
    save('source-after-measurement.json', after)
    result.update({'source_unchanged': before == after, 'executable_sha256': sha(executable), 'executable_unchanged': sha(executable) == build['executable_sha256'], 'source_manifest_sha256': before['manifest_sha256'], 'base_head': before['head'], 'preregistration_sha256': EXPECTED_REGISTRATION, 'scope': 'one M06 component invocation; no Node, durable commit, public throughput or final-source qualification'})
    save('measurement-result.json', result)
    print(json.dumps(result, sort_keys=True), flush=True)
    print((OUT / 'measurement.stdout').read_text()[-1500:], flush=True)
    print((OUT / 'measurement.stderr').read_text(), flush=True)
    registration()
    assert result['source_unchanged'] and result['executable_unchanged']
    return result['exit_code']


if __name__ == '__main__':
    raise SystemExit(main())

#!/usr/bin/env python3
"""Source-bound local engineering qualification; never authorizes a public launch.

Preserves every failed command and delegates the full existing native/reference
regression to its actual owner. Long live-clock TCP campaigns are additional evidence.

Resource observer: defaults to /usr/bin/time. To use an officially installed or
extracted GNU time elsewhere, set TRNM_GNU_TIME to its absolute executable path.
The selected observer is probed with a five-second timeout; its resolved path,
SHA-256 and reported identity are retained in each result and the environment.
This explicit selection survives nested qualification environment sanitization.
Executable hashes are bounded to 16 MiB and probe streams to 16 KiB each.
Hashes are checked before and after commands; post-launch failures retain rows.
These are software file observations, not cryptographic execution attestation or
package provenance authentication; replacement races cannot be excluded.
No shell builtin, PATH fallback, or successful unmeasured mode is provided.
"""
from __future__ import annotations
import argparse, hashlib, json, os, platform, signal, stat, subprocess, sys, time
from importlib.metadata import version
from cryptography.hazmat.backends.openssl.backend import backend as openssl_backend
from pathlib import Path
from qualification_runtime import bind_gnu_time, bind_python_runtime, read_gnu_time_peak_rss, verify_gnu_time

ROOT = Path(__file__).resolve().parents[1]
FLAGS = ('public_network_ready', 'production_activation', 'independent_accepted',
         'future_window_accepted', 'work_profile_qualified', 'physical_power_loss',
         'native_execution_authenticated')
TESTS = ('test_model_attribution', 'test_work_utility', 'test_public_evaluation_lifecycle', 'test_llm_adapter_contract')
PIPELINE_BINARY_LIMIT = 512 * 1024 * 1024
PIPELINE_OBSERVATION_SCOPE = 'software-file-snapshots-and-launcher-exit-not-execution-attestation'

def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT, text=True).strip()

def sha(path, *, limit=None):
    fingerprint, size = hashlib.sha256(), 0
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or (limit is not None and not 0 < info.st_size <= limit):
            raise ValueError('ARTIFACT_BOUNDED_REGULAR_FILE_REQUIRED')
        while chunk := stream.read(65536 if limit is None else min(65536, limit - size + 1)):
            size += len(chunk)
            if limit is not None and size > limit:
                raise ValueError('ARTIFACT_FILE_LIMIT')
            fingerprint.update(chunk)
    return fingerprint.hexdigest()

def relevant(path):
    return (path.startswith(('trillionnium/', 'formal/pon-nakamoto-v1/', 'scripts/'))
            and not path.endswith('.md')) or path.startswith('config/pon/') or path.startswith('.github/workflows/')

def snapshot_pipeline_file(path, *, retain=None):
    """Retain/hash actual bounded file bytes; this does not attest an executed image."""
    path = Path(path)
    if not path.is_absolute() or path != path.resolve(strict=True):
        raise ValueError('PIPELINE_CANONICAL_EXECUTABLE_REQUIRED')
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= PIPELINE_BINARY_LIMIT:
            raise ValueError('PIPELINE_BOUNDED_REGULAR_FILE_REQUIRED')
        def identity(value):
            return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        fingerprint, size = hashlib.sha256(), 0
        copy = Path(retain).open('xb') if retain is not None else None
        try:
            while chunk := stream.read(min(65536, PIPELINE_BINARY_LIMIT - size + 1)):
                size += len(chunk)
                if size > PIPELINE_BINARY_LIMIT:
                    raise ValueError('PIPELINE_EXECUTABLE_LIMIT')
                fingerprint.update(chunk)
                if copy is not None:
                    copy.write(chunk)
            after = os.fstat(stream.fileno())
            if size != before.st_size or identity(before) != identity(after) or identity(after) != identity(path.stat()):
                raise ValueError('PIPELINE_FILE_CHANGED_DURING_SNAPSHOT')
            if copy is not None:
                copy.flush()
                os.fsync(copy.fileno())
        finally:
            if copy is not None:
                copy.close()
    return dict(path=str(path), bytes=size, sha256=fingerprint.hexdigest(),
                device=before.st_dev, inode=before.st_ino,
                mtime_ns=before.st_mtime_ns, ctime_ns=before.st_ctime_ns)


def bind_pipeline_executable(build_log, binary, out):
    records = []
    for line in Path(build_log).read_text().splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue  # Cargo's ordinary stderr shares this retained log.
        if isinstance(value, dict):
            records.append(value)
    artifacts = [row for row in records if row.get('reason') == 'compiler-artifact'
                 and isinstance(row.get('target'), dict)
                 and row['target'].get('name') == 'continuous_pipeline']
    finished = [row for row in records if row.get('reason') == 'build-finished']
    if len(artifacts) != 1 or len(finished) != 1 or finished[0].get('success') is not True:
        raise ValueError('PIPELINE_CARGO_ARTIFACT_REQUIRED')
    artifact = artifacts[0]
    target, profile, filenames = artifact['target'], artifact.get('profile'), artifact.get('filenames')
    expected_manifest = str(ROOT/'trillionnium/crates/trnm-pon-node/Cargo.toml')
    expected_source = str(ROOT/'trillionnium/crates/trnm-pon-node/examples/continuous_pipeline.rs')
    if (artifact.get('manifest_path') != expected_manifest
            or target.get('src_path') != expected_source
            or target.get('kind') != ['example']
            or target.get('crate_types') != ['bin']
            or not isinstance(profile, dict) or profile.get('opt_level') != '3'
            or profile.get('test') is not False
            or type(artifact.get('fresh')) is not bool
            or artifact.get('executable') != str(binary)
            or not isinstance(filenames, list)
            or not all(isinstance(path, str) for path in filenames)
            or str(binary) not in filenames):
        raise ValueError('PIPELINE_CARGO_ARTIFACT_CONTEXT')
    retained = out/'binaries/continuous_pipeline'
    retained.parent.mkdir(mode=0o700)
    initial = snapshot_pipeline_file(binary, retain=retained)
    retained.chmod(0o600)
    copied = snapshot_pipeline_file(retained)
    if (snapshot_pipeline_file(binary) != initial
            or (copied['bytes'], copied['sha256']) != (initial['bytes'], initial['sha256'])):
        raise ValueError('PIPELINE_RETAINED_COPY_CHANGED')
    return dict(cargo_artifact=artifact, build_log='logs/pipeline-build.log',
                retained_path='binaries/continuous_pipeline', initial=initial,
                retained=copied, observation_scope=PIPELINE_OBSERVATION_SCOPE)


def observe_pipeline_executable(binding, out):
    observed = dict(source=snapshot_pipeline_file(binding['initial']['path']),
                    retained=snapshot_pipeline_file(out/binding['retained_path']))
    if observed['source'] != binding['initial'] or observed['retained'] != binding['retained']:
        raise ValueError('PIPELINE_EXECUTABLE_OR_RETAINED_COPY_CHANGED')
    return observed


def run(args):
    if git('status', '--porcelain'):
        raise ValueError('CLEAN_COMMITTED_SOURCE_REQUIRED')
    commit, tree = git('rev-parse', 'HEAD'), git('rev-parse', 'HEAD^{tree}')
    out = Path(args.out).resolve(); out.mkdir(parents=True, exist_ok=False)
    (out/'logs').mkdir()
    env = dict(os.environ)
    for key in list(env):
        if key.startswith('TRNM_') and key != 'TRNM_GNU_TIME': env.pop(key)
    env.update(CARGO_HOME=str(Path(args.cargo_home).resolve()), CARGO_TARGET_DIR=str(Path(args.target).resolve()),
               CARGO_BUILD_JOBS='2', CARGO_NET_OFFLINE='true', RUST_TEST_THREADS='1',
               PYTHONDONTWRITEBYTECODE='1', OPENBLAS_NUM_THREADS='1', OMP_NUM_THREADS='1')
    env, child_python3 = bind_python_runtime(env)
    env, resource_observer = bind_gnu_time(env)
    records = []
    report = dict(schema='trnm-public-readiness-engineering-v2', source_commit=commit, source_tree=tree,
        source_clean=True, all_commands_passed=False, source_files_sha256={p:sha(ROOT/p) for p in git('ls-files').splitlines() if relevant(p)},
        environment=dict(platform=platform.platform(), python=platform.python_version(),
            child_python3=child_python3, resource_observer=resource_observer,
            numpy=__import__('numpy').__version__, cryptography=__import__('cryptography').__version__,
            cryptography_openssl=openssl_backend.openssl_version_text(), cffi=version('cffi'),
            rust=subprocess.check_output(['rustc','--version'],text=True).strip(),
            hardware=subprocess.check_output(['lscpu'],text=True),
            filesystem=subprocess.check_output(['findmnt','-T',str(out),'-n','-o','FSTYPE,TARGET'],text=True).strip(),
            cargo_jobs=2, test_threads=1, gpu_used=False, vram_bytes=None),
        results=records, **{flag:False for flag in FLAGS})
    def execute(name, command, timeout=2400, executable_binding=None):
        log=out/'logs'/(name+'.log'); usage=out/'logs'/(name+'.usage')
        started=time.monotonic_ns(); expired=False
        pipeline = None
        def retain_unlaunched_failure(stage, error):
            pipeline.update(error=str(error), failure_stage=stage)
            row = dict(name=name, command=command, returncode=None, timed_out=False,
                       resource_observer=resource_observer,
                       elapsed_ns=time.monotonic_ns()-started,
                       log=str(log.relative_to(out)) if log.is_file() else None,
                       peak_rss_kib=None, vram_bytes=None, pipeline_execution=pipeline)
            records.append(row); print(json.dumps(row), flush=True)
            raise RuntimeError('QUALIFICATION_FAILED:PIPELINE_'+stage+':'+name) from error
        if executable_binding is not None:
            pipeline = dict(requested_argv=list(command), launched_argv=None, launcher_pid=None,
                            before=None, after=None, observation_scope=PIPELINE_OBSERVATION_SCOPE)
            try:
                if not command or command[0] != executable_binding['initial']['path']:
                    raise ValueError('PIPELINE_EXECUTABLE_ARGV_CHANGED')
                pipeline['before'] = observe_pipeline_executable(executable_binding, out)
            except (OSError, ValueError) as error:
                retain_unlaunched_failure('BEFORE', error)
        try: verify_gnu_time(resource_observer)
        except (OSError, ValueError) as error:
            if pipeline is None: raise
            retain_unlaunched_failure('OBSERVER_BEFORE', error)
        launched = [resource_observer['executable'],'-f','%M %U %S','-o',str(usage),*command]
        code = None
        try:
            with log.open('w') as stream:
                process=subprocess.Popen(launched,
                    cwd=ROOT,env=env,stdout=stream,stderr=subprocess.STDOUT,start_new_session=True)
                if pipeline is not None:
                    pipeline.update(launched_argv=launched, launcher_pid=process.pid)
                try: code=process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    expired=True; os.killpg(process.pid,signal.SIGKILL); code=process.wait()
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            if pipeline is None: raise
            if pipeline['launcher_pid'] is None:
                pipeline['launch_attempted_argv'] = launched
                retain_unlaunched_failure('LAUNCH', error)
            pipeline.update(error=type(error).__name__+': '+str(error), failure_stage='WAIT_OR_CLEANUP')
            # A started case must retain its actual outcome even if wait or
            # cleanup fails. Unknown termination stays null; never invent zero.
            pipeline['cleanup_errors'] = []
            try:
                if process.poll() is None: os.killpg(process.pid, signal.SIGKILL)
            except (OSError, ValueError, subprocess.SubprocessError) as cleanup_error:
                pipeline['cleanup_errors'].append(type(cleanup_error).__name__+': '+str(cleanup_error))
            try: code = process.wait(timeout=5)
            except (OSError, ValueError, subprocess.SubprocessError) as cleanup_error:
                pipeline['cleanup_errors'].append(type(cleanup_error).__name__+': '+str(cleanup_error))
        row=dict(name=name,command=command,returncode=code,timed_out=expired,
                 resource_observer=resource_observer,elapsed_ns=time.monotonic_ns()-started,log=str(log.relative_to(out)),peak_rss_kib=None,vram_bytes=None)
        row['peak_rss_kib']=read_gnu_time_peak_rss(usage)
        if pipeline is not None:
            try: pipeline['after'] = observe_pipeline_executable(executable_binding, out)
            except (OSError, ValueError) as error:
                if 'error' in pipeline: pipeline['post_observation_error'] = str(error)
                else: pipeline.update(error=str(error), failure_stage='AFTER')
            row['pipeline_execution'] = pipeline
        try: verify_gnu_time(resource_observer)
        except (OSError,ValueError) as error: row['resource_observer_error']=str(error)
        records.append(row); print(json.dumps(row),flush=True)
        if pipeline is not None and pipeline.get('error'):
            raise RuntimeError('QUALIFICATION_FAILED:PIPELINE_'+pipeline.get('failure_stage', 'AFTER')+':'+name)
        if row.get('resource_observer_error'): raise RuntimeError('QUALIFICATION_FAILED:OBSERVER_CHANGED:'+name)
        if code or expired: raise RuntimeError('QUALIFICATION_FAILED:'+name)
        if git('rev-parse','HEAD')!=commit or git('status','--porcelain'): raise ValueError('SOURCE_CHANGED')
    try:
        execute('evidence-source-negative-tests',[sys.executable,'scripts/ci/test_evidence_sources.py'])
        execute('evidence-source-preparation',[sys.executable,'scripts/ci/prepare_evidence_sources.py'])
        execute('public-readiness-evidence-negative-tests',[sys.executable,'scripts/ci/test_public_readiness_evidence.py'])
        execute('full-native-reference-regression',[sys.executable,'scripts/run_evaluation_qualification.py',
            '--native-node','--source',commit,'--out',str(out/'baseline'),'--target',env['CARGO_TARGET_DIR'],
            '--cargo-home',env['CARGO_HOME']],timeout=10800)
        for test in TESTS:
            execute(test,[sys.executable,'formal/pon-nakamoto-v1/'+test+'.py'])
        execute('transport-sustained-paid-unpaid',['cargo','test','--offline','--locked','--release',
            '--manifest-path','trillionnium/Cargo.toml','-p','trnm-pon-node','--test','protected_ingress',
            'sustained_protected_socket_cost_campaign','--','--exact','--ignored','--nocapture','--test-threads=1'])
        execute('pipeline-build',['cargo','build','--offline','--locked','--release','--manifest-path','trillionnium/Cargo.toml',
                                '-p','trnm-pon-node','--examples','--bins','--message-format=json-render-diagnostics'])
        binary=Path(env['CARGO_TARGET_DIR'])/'release/examples/continuous_pipeline'
        report['pipeline_executable']=bind_pipeline_executable(out/'logs/pipeline-build.log',binary,out)
        report['pipeline_binary_sha256']=report['pipeline_executable']['initial']['sha256']
        for pattern,profile in [('hot','legacy'),('hot','protected'),('disjoint4','protected'),('growth','protected')]:
            name='pipeline-'+pattern+'-'+profile
            execute(name,[str(binary),str(out/name),str(args.blocks),str(args.batch),str(args.pace_ms),pattern,profile],
                    timeout=(args.blocks+8)*args.pace_ms//1000+300, executable_binding=report['pipeline_executable'])
        inputs=ROOT/'evidence/pon-native-node-v1/model-current/model'
        # Owner bundle digest uses the ledger-domain framing, never the raw-file SHA.
        sys.path.insert(0,str(ROOT/'formal/pon-nakamoto-v1'))
        from contract_wire import H
        bundle=H('evaluation-bundle-v3',(inputs/'evaluation-bundle.json').read_bytes()).hex()
        execute('bounded-model-attribution',[sys.executable,'formal/pon-nakamoto-v1/experiments/model_attribution_campaign.py',
                    '--inputs',str(inputs),'--bundle-hash',bundle,'--out',str(out/'attribution')])
        report['all_commands_passed']=True
    except (ValueError,RuntimeError,OSError,subprocess.SubprocessError) as error:
        report['error']=str(error)
    finally:
        report['source_clean_after']=git('rev-parse','HEAD')==commit and not git('status','--porcelain')
        (out/'qualification.json').write_text(json.dumps(report,indent=2)+'\n')
        try:
            files={str(p.relative_to(out)):sha(p, limit=PIPELINE_BINARY_LIMIT
                    if p.relative_to(out).as_posix() == 'binaries/continuous_pipeline' else None)
                   for p in sorted(out.rglob('*')) if p.is_file() and p != out/'manifest.json'}
        except (OSError, ValueError) as error:
            report.update(all_commands_passed=False, artifact_inventory_error=str(error))
            (out/'qualification.json').write_text(json.dumps(report,indent=2)+'\n')
            raise
        (out/'manifest.json').write_text(json.dumps(dict(schema='trnm-public-readiness-evidence-v2',
            implementation_commit=commit,implementation_tree=tree,files=files,
            source_clean=report['source_clean_after'],all_commands_passed=report['all_commands_passed'],
            **{flag:False for flag in FLAGS}),indent=2)+'\n')
    if not report['all_commands_passed']: raise RuntimeError(report.get('error','INCOMPLETE'))
    print(json.dumps(dict(report=str(out/'qualification.json'),public_network_ready=False)),flush=True)

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--out',required=True); parser.add_argument('--cargo-home',required=True); parser.add_argument('--target',required=True)
    parser.add_argument('--blocks',type=int,default=20); parser.add_argument('--batch',type=int,default=32)
    parser.add_argument('--pace-ms',type=int,default=10000)
    args=parser.parse_args()
    if not 20<=args.blocks<=4096 or not 1<=args.batch<=256 or not 1000<=args.pace_ms<=60000:
        parser.error('live qualification requires20..4096 blocks,1..256 transactions and1000..60000ms pacing')
    run(args)

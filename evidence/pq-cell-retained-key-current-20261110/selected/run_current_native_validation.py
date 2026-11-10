from pathlib import Path
import hashlib, json, os, subprocess, sys, time

BASE=Path(__file__).resolve().parent
ROOT=BASE/'chain-pq'
RUNTIME=BASE/'runtime-current'
OUT=BASE/'current-native-validation'
HEAD='a4c594fc9d5f43d0d2b7ae7e0835d0e1514dc667'
TOOLCHAIN=RUNTIME/'rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu'
env=dict(os.environ,RUSTUP_HOME=str(RUNTIME/'rustup'),CARGO_HOME=str(RUNTIME/'cargo'),
         CARGO_TARGET_DIR=str(RUNTIME/'target'),CARGO_BUILD_JOBS='1',CARGO_INCREMENTAL='0',
         RUST_TEST_THREADS='1',RUSTC=str(TOOLCHAIN/'bin/rustc'),
         LD_LIBRARY_PATH=str(TOOLCHAIN/'lib'),PYTHONDONTWRITEBYTECODE='1')
env['PATH']=str(TOOLCHAIN/'bin')+':'+env['PATH']
for line in (RUNTIME/'provider-build/provider.env').read_text().splitlines():
    key,value=line.split('=',1);env[key]=value
OUT.mkdir(exist_ok=True)
(OUT/'environment.json').write_text(json.dumps({key:env.get(key) for key in (
    'PATH','RUSTUP_HOME','CARGO_HOME','CARGO_TARGET_DIR','CARGO_BUILD_JOBS','CARGO_INCREMENTAL',
    'RUST_TEST_THREADS','RUSTC','LD_LIBRARY_PATH','RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS',
    'OPENSSL_DIR','OPENSSL_STATIC','OPENSSL_CONF','OPENSSL_MODULES','TRNM_PQ_OPENSSL',
    'TRNM_PQ_OPENSSL_SHA256','TRNM_PQ_OPENSSL_VERSION')},indent=2)+'\n')
preflight=subprocess.run(['bash','scripts/project-preflight.sh'],cwd=ROOT,env=env,capture_output=True)
(OUT/'preflight.stdout').write_bytes(preflight.stdout)
(OUT/'preflight.stderr').write_bytes(preflight.stderr)
if preflight.returncode:raise SystemExit(preflight.returncode)

def cargo(action,*args):
    return ['cargo',action,'--offline','--locked','--manifest-path','trillionnium/Cargo.toml',*args]

commands=[
    ('graph-offline',cargo('metadata','--all-features','--format-version','1')),
    ('format',['cargo','fmt','--manifest-path','trillionnium/Cargo.toml','--all','--','--check']),
    ('pipeline-build',cargo('build','-p','trnm-data-availability','--example','cell_signed_sealed_pipeline_v1')),
    ('signed-sealed-pipeline',None),
    ('da-complete',cargo('test','-p','trnm-data-availability','--','--test-threads=1')),
    ('strict-clippy',cargo('clippy','--workspace','--all-targets','--all-features','--','-D','warnings')),
    ('npq-cli',cargo('test','-p','trnm-pon-node','--features','pq-native-openssl',
                     '--test','pq_application_local_cli','--','--nocapture','--test-threads=1')),
]
records=[]
for label,command in commands:
    extra=[]
    if command is None:
        binary=RUNTIME/'target/debug/examples/cell_signed_sealed_pipeline_v1'
        if not binary.is_file():
            row={'label':label,'status':'NOT_DISPATCHED_MISSING_EXECUTABLE','recorder_exit':None}
            records.append(row);print(json.dumps(row),flush=True);continue
        raw=binary.read_bytes();digest=hashlib.sha256(raw).hexdigest()
        (OUT/'pipeline-binary.json').write_text(json.dumps({
            'path':str(binary),'bytes':len(raw),'sha256':digest,
            'source':HEAD,'scope':'build fingerprint before explicitly pinned direct dispatch'},indent=2)+'\n')
        extra=['--native-executable-sha256',digest]
        command=[str(binary)]
    argv=['python3','scripts/ci/record_pq_native_command.py','--kind','head','--candidate',HEAD,
          '--tested',HEAD,'--label',label,'--output',str(OUT),*extra,'--',*command]
    start=time.monotonic_ns()
    result=subprocess.run(argv,cwd=ROOT,env=env,capture_output=True,check=False)
    (OUT/(label+'.recorder.stdout')).write_bytes(result.stdout)
    (OUT/(label+'.recorder.stderr')).write_bytes(result.stderr)
    row={'label':label,'recorder_exit':result.returncode,'wall_ns':time.monotonic_ns()-start}
    records.append(row)
    (OUT/'summary.json').write_text(json.dumps({'source':HEAD,'records':records,'complete':False},indent=2)+'\n')
    print(json.dumps(row),flush=True)
(OUT/'summary.json').write_text(json.dumps({'source':HEAD,'records':records,'complete':True},indent=2)+'\n')
sys.exit(any(row.get('recorder_exit')!=0 for row in records))

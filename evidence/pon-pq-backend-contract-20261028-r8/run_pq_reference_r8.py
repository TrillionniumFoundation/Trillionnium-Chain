#!/usr/bin/env python3
"""Bounded offline qualification of five real PQ reference suites.

This exact action is submitted for automatic review because an earlier, broader
PQ native execution was interrupted. It does not resume that execution, access
deployed state, connect to peers, import credentials, or change any security gate.
"""
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import time

ROOT = Path('/workspace/scratch/56818e4fba76/chain-recovered')
OUT = Path(__file__).resolve().parent / 'pq-reference-bounded-real'
OUT.mkdir(exist_ok=False)


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1048576), b''):
            h.update(chunk)
    return h.hexdigest()


def source_identity():
    files = subprocess.check_output(['git', 'ls-files', '-z', '--', 'trillionnium',
                                     'formal/pon-nakamoto-v1'], cwd=ROOT).decode().split('\0')
    files += ['formal/pon-nakamoto-v1/pq_openssl_backend.py',
              'formal/pon-nakamoto-v1/test_pq_openssl_backend.py']
    rows = {name: digest(ROOT/name) for name in sorted(set(files)) if name and
            Path(name).suffix in ('.rs', '.py', '.toml', '.lock', '.json')}
    return {'commit': subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
            'dirty_diff_sha256': hashlib.sha256(subprocess.check_output(['git','diff','--binary'],cwd=ROOT)).hexdigest(),
            'files': rows}


preflight = subprocess.run(['bash','scripts/project-preflight.sh'], cwd=ROOT, capture_output=True)
(OUT/'preflight.stdout').write_bytes(preflight.stdout)
(OUT/'preflight.stderr').write_bytes(preflight.stderr)
if preflight.returncode:
    raise SystemExit(preflight.returncode)
before = source_identity()
(OUT/'source-before.json').write_text(json.dumps(before,indent=2)+'\n')
prefix = Path('/tmp/pure-pon-openssl-3.5.9')
cli = prefix/'bin/openssl'
env = dict(os.environ, PATH='/tmp/pure-pon-toolchain-20261027/bin:'+os.environ['PATH'],
           CARGO_HOME='/tmp/pure-pon-cargo-20261027',
           CARGO_TARGET_DIR='/tmp/chain-pq-target-56818e4fba76',
           CARGO_BUILD_JOBS='1', CARGO_INCREMENTAL='0',
           CARGO_NET_OFFLINE='true', OPENSSL_DIR=str(prefix), OPENSSL_STATIC='1',
           TRNM_PQ_OPENSSL=str(cli), TRNM_PQ_OPENSSL_SHA256=digest(cli),
           TRNM_PQ_OPENSSL_VERSION='3.5.9', OPENSSL_CONF='/dev/null',
           OPENSSL_MODULES=str(prefix/'lib/ossl-modules'))
argv = ['python3','-m','unittest','-v','test_pq_genesis_handoff',
        'test_pq_envelope','test_pq_pql4_signed_frontier','test_pq_pql5_quorum',
        'test_pq_pql6_equivocation']
run_cwd = ROOT/'formal/pon-nakamoto-v1'

started = time.monotonic()
record = {'schema':'pon-r8-offline-real-pq-reference-v1',
          'started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
          'argv':argv, 'cwd':str(run_cwd), 'wall_limit_seconds':120,
          'disk_free_floor_bytes':1073741824, 'cargo_build_jobs':1,
          'deployed_keys_or_state':False, 'network_requested':False,
          'earlier_interruption_preserved':True, 'qualification_scope':'dirty combined candidate, five original offline PQ suites with ephemeral test keys',
          'backend':{key:env[key] for key in ('OPENSSL_DIR','OPENSSL_STATIC','TRNM_PQ_OPENSSL',
                    'TRNM_PQ_OPENSSL_SHA256','TRNM_PQ_OPENSSL_VERSION','OPENSSL_CONF','OPENSSL_MODULES')},
          'whole_chain_pq_accepted':False, 'interrupted':False, 'stop_reason':None}
(OUT/'intent.json').write_text(json.dumps(record,indent=2)+'\n')
with (OUT/'stdout.txt').open('wb') as stdout, (OUT/'stderr.txt').open('wb') as stderr:
    child = subprocess.Popen(argv,cwd=run_cwd,env=env,stdout=stdout,stderr=stderr,start_new_session=True)
    while True:
        pid,status,usage = os.wait4(child.pid,os.WNOHANG)
        if pid:
            child.returncode = os.waitstatus_to_exitcode(status)
            break
        free = shutil.disk_usage(OUT).free
        if time.monotonic()-started > 120 or free < 1073741824:
            record['interrupted'] = True
            record['stop_reason'] = 'wall-budget' if time.monotonic()-started > 120 else 'disk-floor'
            os.killpg(child.pid,signal.SIGKILL)
            _,status,usage = os.wait4(child.pid,0)
            child.returncode = os.waitstatus_to_exitcode(status)
            break
        time.sleep(0.25)
record.update(returncode=child.returncode,wall_seconds=time.monotonic()-started,
              user_cpu_seconds=usage.ru_utime,system_cpu_seconds=usage.ru_stime,
              max_rss_kib=usage.ru_maxrss,
              completed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
after = source_identity()
(OUT/'source-after.json').write_text(json.dumps(after,indent=2)+'\n')
record['source_unchanged'] = before == after
record['logs'] = {name:{'bytes':(OUT/name).stat().st_size,'sha256':digest(OUT/name)}
                  for name in ('stdout.txt','stderr.txt')}
(OUT/'result.json').write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps(record,indent=2))
raise SystemExit(child.returncode or (0 if record['source_unchanged'] else 1))

#!/usr/bin/env python3
"""One real subprocess reproduction; neither a W1 guest nor a proof test."""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
SOURCE = Path('/workspace/scratch/301262829a43/pon-work-impl/integration/w1-transparent21e')
COMMIT = 'd96138532b656d767d1ef46f6db86e7effae485e'
SCRIPT = 'trillionnium/crates/trnm-crypto-primitives/guests/w1-risc0/measure_step.py'
libc = ctypes.CDLL(None, use_errno=True)
if libc.prctl(36, 1, 0, 0, 0) != 0:
    raise OSError(ctypes.get_errno(), 'control subreaper unavailable')
raw = subprocess.check_output(['git', 'show', f'{COMMIT}:{SCRIPT}'], cwd=SOURCE)
out = HERE / 'original-group-red'
out.mkdir()
(out / 'original_measure_step.py').write_bytes(raw)
code = '''import os,signal,time,json,sys
read,write=os.pipe()
pid=os.fork()
if pid==0:
 os.close(read)
 def stop(*_):
  print('adopted-terminal-tail'); sys.exit(31)
 signal.signal(signal.SIGTERM,stop)
 os.write(write,b'1'); os.close(write); time.sleep(90)
else:
 os.close(write); os.read(read,1); os.close(read)
 print(json.dumps({'pgid':os.getpgrp(),'child':pid}))
 os._exit(0)
'''
(out / 'fixture.py').write_text(code)
command = [sys.executable, str(out / 'original_measure_step.py'), '--out', str(out),
           '--name', 'original', '--timeout', '5', '--', sys.executable, '-u', str(out / 'fixture.py')]
pgid = None
result = {'schema':'pon-w1-original-owned-group-control-v1', 'source_commit':COMMIT,
          'source_path':SCRIPT, 'source_sha256':hashlib.sha256(raw).hexdigest(),
          'command':command, 'actual_w1_guest_or_proof_executed':False,
          'qualification':False, 'cleanup_terminals':[]}
try:
    with (out / 'wrapper.stdout.log').open('xb') as stdout, (out / 'wrapper.stderr.log').open('xb') as stderr:
        completed = subprocess.run(command, stdout=stdout, stderr=stderr, timeout=15)
    result['original_wrapper_returncode'] = completed.returncode
    observed = json.loads((out / 'original.stdout.log').read_text().splitlines()[0])
    pgid = observed['pgid']
    require_child = observed['child']
    result['original_report'] = json.loads((out / 'original.process.json').read_text())
    try:
        os.killpg(pgid, 0)
        result['group_still_present_after_wrapper_finished'] = True
    except ProcessLookupError:
        result['group_still_present_after_wrapper_finished'] = False
    result['reproduced_unbounded_leader_success'] = (
        completed.returncode == 0 and result['original_report']['returncode'] == 0
        and result['group_still_present_after_wrapper_finished'])
finally:
    if pgid is not None:
        for sig in [signal.SIGTERM, signal.SIGKILL]:
            try:
                os.killpg(pgid, sig)
            except ProcessLookupError:
                break
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                try:
                    pid, status = os.waitpid(-1, os.WNOHANG)
                except ChildProcessError:
                    break
                if pid:
                    result['cleanup_terminals'].append({'pid':pid,'returncode':os.waitstatus_to_exitcode(status)})
                try:
                    os.killpg(pgid, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.025)
        try:
            os.killpg(pgid, 0)
            result['owned_group_empty_after_control_cleanup'] = False
        except ProcessLookupError:
            result['owned_group_empty_after_control_cleanup'] = True
    (out / 'control-result.json').write_text(json.dumps(result, indent=2)+'\n')
print(json.dumps({key:result[key] for key in ['reproduced_unbounded_leader_success',
    'original_wrapper_returncode', 'owned_group_empty_after_control_cleanup']}))
raise SystemExit(0 if result['reproduced_unbounded_leader_success']
                 and result['owned_group_empty_after_control_cleanup'] else 1)

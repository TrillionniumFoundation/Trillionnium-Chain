#!/usr/bin/env python3
"""Opt-in ordinary native execution in a temporary kernel envelope.

Administrator-only, finite, no pressure generation or failure injection. One new
parent slice is provisioned only for this test, reused by every native process,
and removed together with root-owned executable copies. No deployed units change.
"""
from __future__ import annotations
import argparse
import concurrent.futures
import hashlib
import json
import os
import shutil
import sys
import tempfile
import uuid
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'formal/pon-nakamoto-v1'))
from bounded_process import run_bounded
from kernel_process import KernelEnvelope, Limits, ParentIdentity, PinnedExecutable, KernelFailure, _systemctl
from work_oracle import task_id, prove, CELLS, Q
from contract_wire import H


def require(value,message):
    if not value:raise RuntimeError(message)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-work',required=True)
    parser.add_argument('--native-node-tests',required=True)
    args=parser.parse_args()
    require(os.geteuid()==0,'administrator execution required')
    name='trnmponnative'+uuid.uuid4().hex[:12]+'.slice'
    unit=Path('/run/systemd/system')/name
    body=('[Unit]\nDescription=PoN ordinary native kernel smoke\nStopWhenUnneeded=no\n'
          '[Slice]\nCPUAccounting=yes\nCPUQuota=25%\nCPUQuotaPeriodSec=100ms\n'
          'MemoryAccounting=yes\nMemoryMax=268435456\nMemorySwapMax=0\n'
          'TasksAccounting=yes\nTasksMax=24\n')
    folder=Path(tempfile.mkdtemp(prefix='trnmponnativeassets',dir='/opt'));folder.chmod(0o755)
    fd=os.open(unit,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o644)
    with os.fdopen(fd,'w') as output:output.write(body)
    rows=[]
    try:
        _systemctl('daemon-reload');_systemctl('start',name)
        def stage(source,label):
            original=Path(source).resolve(strict=True);target=folder/label
            with original.open('rb') as incoming,target.open('xb') as outgoing:shutil.copyfileobj(incoming,outgoing)
            target.chmod(0o555)
            actual=hashlib.sha256(target.read_bytes()).hexdigest()
            require(actual==hashlib.sha256(original.read_bytes()).hexdigest(),'native binary changed during copy')
            return PinnedExecutable(str(target),actual)
        native=stage(args.native_work,'pon_work_io');node=stage(args.native_node_tests,'node_tests')
        group=Path('/sys/fs/cgroup')/name;meta=group.stat()
        identity=ParentIdentity(Path('/proc/sys/kernel/random/boot_id').read_text().strip(),meta.st_dev,meta.st_ino)
        limits=Limits(25000,100000,268435456,24)
        with KernelEnvelope(name,limits,identity) as env:
            initial=env.snapshot()
            c=bytes([43])*32;a=[i%31 for i in range(CELLS)];b=[i%23 for i in range(CELLS)]
            proof=prove(c,a,b);task=task_id(a,b);target=bytes([255])*32
            wrong=bytearray(proof);at=4+8*CELLS;old=int.from_bytes(wrong[at:at+4],'little')
            wrong[at:at+4]=((old+1)%Q).to_bytes(4,'little')
            vectors=[('valid',c+task+target+proof,True),('product',c+task+target+bytes(wrong),False),
                     ('task',c+bytes(32)+target+proof,False),('target',c+task+bytes(32)+proof,False)]
            for label,data,accepted in vectors:
                reference=run_bounded([native.path,'verify'],data,timeout=5,stdout_limit=32,stderr_limit=128)
                result=env.run(native,['verify'],data,runtime=8,stdout_limit=32,stderr_limit=128)
                require(result.native==reference,'isolated result differs from original native verifier')
                require((result.native.returncode==0)==accepted,'unexpected acceptance')
                if accepted:require(result.native.stdout==H('native-work-verification',data),'wrong input binding')
                row={'case':label,'returncode':result.native.returncode,'identical_to_native':True,
                     'unit':result.unit,'parent_inode':result.aggregate_after['parent_inode'],
                     'aggregate_cpu_us':result.aggregate_after['cpu']['usage_usec'],
                     'pids_after':result.aggregate_after['pids_current'],'cleanup':result.cleanup_confirmed}
                require(row['pids_after']==0,'native process not reaped')
                rows.append(row);print(json.dumps(row),flush=True)
            # Two ordinary correct W1 requests in distinct worker processes;
            # this is bounded functional concurrency, not load/saturation testing.
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                jobs=[pool.submit(env.run,native,['verify'],vectors[0][1],runtime=8,
                                  stdout_limit=32,stderr_limit=128) for _ in range(2)]
                completed=[job.result() for job in jobs]
            require(len({r.unit for r in completed})==2,'worker identities collided')
            require(all(r.native.returncode==0 and r.cleanup_confirmed and
                        r.aggregate_after['parent_inode']==identity.inode for r in completed),
                    'ordinary concurrent verifier mismatch')
            print(json.dumps({'case':'two_concurrent_native_verifiers','units':[r.unit for r in completed],
                              'parent_inode':identity.inode,'after':env.snapshot()}),flush=True)
            # Reopen the handle with the SAME already retained parent descriptor.
            # This is not a supervisor crash or operating-system reboot test.
            with KernelEnvelope(name,limits,identity) as attached:
                newer=attached.snapshot()
                require(newer['cpu']['usage_usec']>=rows[-1]['aggregate_cpu_us'],'counter reset')
                require(newer['parent_inode']==initial['parent_inode'],'parent changed')
                result=attached.run(native,['verify'],vectors[0][1],runtime=8,stdout_limit=32,stderr_limit=128)
                require(result.native.returncode==0,'normal handle reconnect failed')
            test=('ingress::public_v3::scalar_cpu::metered_fact_network_tests::'
                  'two_real_listeners_confirm_signed_work_while_bad_cached_request_is_in_flight')
            result=env.run(node,[test,'--exact','--nocapture','--test-threads=1'],runtime=25)
            text=result.native.stdout.decode('utf-8')
            require(result.native.returncode==0 and '1 passed; 0 failed' in text and
                    'listeners=2 honest_confirmed_transactions=8' in text,
                    f'original native Node fixture failed: {result.native}')
            final=env.snapshot()
            require(final['pids_current']==0,'final native tasks remain')
            print(json.dumps({'case':'original_native_node_in_envelope','stdout':text,
                              'native_binary_sha256':node.sha256,'limits':final['limits'],
                              'initial':initial,'final':final}),flush=True)
            try:
                KernelEnvelope(name,limits,ParentIdentity(identity.boot,identity.device,identity.inode+1))
                raise RuntimeError('wrong parent identity accepted')
            except KernelFailure as error:require(str(error)=='KERNEL_PARENT_IDENTITY','unexpected parent error')
            rows.append({'case':'wrong_parent_identity_refused','passed':True})
    finally:
        _systemctl('stop',name)
        require(unit.read_text()==body,'test unit changed, not removing')
        unit.unlink();_systemctl('daemon-reload');shutil.rmtree(folder)
    print(json.dumps({'result':'PASS','w1_vectors':4,'ordinary_concurrent_workers':2,'invalid_accepted':0,'native_node_tests':1,
                      'retained_parent_handle_reattach':True,'wrong_identity_refused':True,
                      'temporary_test_assets_removed':True,'fault_or_saturation_tests':False,
                      'host_reboot_tested':False,'default_receiver_changed':False}),flush=True)


if __name__=='__main__':main()

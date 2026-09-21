#!/usr/bin/env python3
"""Structural rejection tests; cryptographic verification requires real evidence."""
import copy
import hashlib
import pathlib
import tempfile
import native_client_campaign_v1 as c
import run_network_smoke_fleet as base


# The programs below are controlled transport peers, never crypto-positive fixtures.
def test_request_adapter_v1():
    import dataclasses
    import json
    import os
    import secrets
    import shlex
    import shutil
    import socket
    import subprocess
    import sys
    import threading
    import time
    from unittest import mock

    root = pathlib.Path('/tmp') / ('tp3-' + secrets.token_hex(10))
    root.mkdir(mode=0o700)
    try:
        for relative in ('bin', 'v', 'v/v000', 'v/v000/native-client-v1', 'shim'):
            (root / relative).mkdir(mode=0o700)
        node = root / 'v/v000'
        binary = root / 'bin/trnm-poco-lab-validator'
        binary.write_text('''#!/usr/bin/env python3
import json, os, pathlib, socket, sys
assert sys.argv[1:3] == ['native-client','request']
sock, q, r, digest, genesis = sys.argv[3:]
mode = os.environ.get('TRNM_TRANSPORT_TEST_MODE', '')
if mode == 'fail':
    sys.stderr.write('original native request failure\\n'); sys.exit(37)
if mode == 'oversized':
    fd=os.open(r, os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600); os.ftruncate(fd,8404993); os.close(fd); sys.exit(0)
if mode == 'symlink':
    os.symlink(q,r); sys.exit(0)
request = json.loads(pathlib.Path(q).read_bytes())
client = socket.socket(socket.AF_UNIX); client.connect(sock)
client.sendall(pathlib.Path(q).read_bytes()); client.shutdown(socket.SHUT_WR)
response = bytearray()
while True:
    part=client.recv(65536)
    if not part: break
    response.extend(part)
client.close()
fd=os.open(r,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,'wb') as stream: stream.write(response)
''')
        binary.chmod(0o500)
        shim = root / 'shim/ssh'
        shim.write_text('''#!/usr/bin/env python3
import json,os,shlex,sys,time
with open(os.environ['TRNM_TRANSPORT_SSH_LOG'],'a') as stream: stream.write(json.dumps(sys.argv[1:])+'\\n')
assert sys.argv[-2]=='p4-desktop'
mode=os.environ.get('TRNM_TRANSPORT_SSH_MODE','')
if mode=='delay': time.sleep(5)
if mode=='failure': sys.stderr.write('original ssh failure\\n'); sys.exit(255)
args=shlex.split(sys.argv[-1]); assert args[:3]==['python3','-I','-c']
os.execvp(args[0],args)
''')
        shim.chmod(0o500)
        log = root / 'ssh-log'
        process = base.ValidatorProcess('11'*32,'desktop','p4-desktop',node,pathlib.PurePosixPath('public/config.json'),'v000')
        stage = base.HostStage('desktop','p4-desktop',str(root),None)
        paths = {'desktop': str(binary)}
        target = c.request_target_v1([process], {'desktop': stage}, paths, 'native.sock')
        assert target.binary == str(binary)
        local = dataclasses.replace(process, host_id='local',management='local')
        assert c.request_process_v1([process, dataclasses.replace(local,validator_id='22'*32)]) .management == 'local'
        lower = dataclasses.replace(process,host_id='rog',management='p4-rog',validator_id='00'*32)
        assert c.request_process_v1([process,lower]) == lower
        sock = socket.socket(socket.AF_UNIX)
        sock.bind(target.socket); pathlib.Path(target.socket).chmod(0o600); sock.listen(); sock.settimeout(0.1)
        stop = threading.Event(); received = []; failures = []
        def serve():
            while not stop.is_set():
                try: client,_ = sock.accept()
                except TimeoutError: continue
                try:
                    raw=bytearray()
                    while True:
                        part=client.recv(65536)
                        if not part:break
                        raw.extend(part)
                    request=json.loads(raw);received.append(request)
                    result={'request_id':os.environ.get('TRNM_TRANSPORT_RESPONSE_ID',request['request_id']),'ok':True,'data':{'op':request['op']}}
                    client.sendall(base.canonical_json(result))
                except BaseException as error: failures.append(error)
                finally: client.close()
        thread=threading.Thread(target=serve);thread.start()
        def fresh():
            shutil.rmtree(node/'native-client-campaign-requests',ignore_errors=True)
            return c.NativeRequestAdapterV1(target,'22'*32,'33'*32,time.monotonic()+10)
        def reject(fn, kind=RuntimeError, text=None):
            try:fn()
            except kind as error:
                if text is not None:assert text in str(error),str(error)
                return error
            raise AssertionError('transport accepted negative control')
        try:
            with mock.patch.dict(os.environ,{'PATH':str(root/'shim')+os.pathsep+os.environ['PATH'],'TRNM_TRANSPORT_SSH_LOG':str(log)}):
                adapter=fresh()
                for operation in ('status','submit','proof'):
                    assert adapter.request(operation,{'signed_outer_hex':'ab'} if operation=='submit' else {})['data']['op']==operation
                assert [r['op'] for r in received]==['status','submit','proof']
                rows=[json.loads(row) for row in log.read_text().splitlines()]
                assert len(rows)==3 and all(row[-2]=='p4-desktop' and '-T' in row for row in rows)
                assert all('operator.key' not in row[-1] and 'client.key' not in row[-1] for row in rows)
                files=list((node/'native-client-campaign-requests').iterdir())
                assert len(files)==6 and all(p.stat().st_mode&0o777==0o600 for p in files)
                # Local path executes the identical checked program without SSH.
                local_stage=dataclasses.replace(stage,host_id='local',management='local',local_path=root)
                local_target=c.request_target_v1([local],{'local':local_stage},{'local':str(binary)},'native.sock')
                fresh();local_adapter=c.NativeRequestAdapterV1(local_target,'22'*32,'33'*32,time.monotonic()+10)
                assert local_adapter.request('status',{})['ok'] is True
                assert len(log.read_text().splitlines())==3
                # Real exit codes and stderr survive both native and SSH failure.
                with mock.patch.dict(os.environ,{'TRNM_TRANSPORT_TEST_MODE':'fail'}):
                    error=reject(lambda:fresh().request('status',{}),subprocess.CalledProcessError)
                    assert error.returncode==37 and error.stderr==b'original native request failure\n'
                with mock.patch.dict(os.environ,{'TRNM_TRANSPORT_SSH_MODE':'failure'}):
                    error=reject(lambda:fresh().request('status',{}),subprocess.CalledProcessError)
                    assert error.returncode==255 and error.stderr==b'original ssh failure\n'
                for mode in ('oversized','symlink'):
                    with mock.patch.dict(os.environ,{'TRNM_TRANSPORT_TEST_MODE':mode}):
                        reject(lambda:fresh().request('status',{}),subprocess.CalledProcessError)
                with mock.patch.dict(os.environ,{'TRNM_TRANSPORT_RESPONSE_ID':'other-request'}):
                    reject(lambda:fresh().request('status',{}),RuntimeError,'request identity differs')
                # No-follow/mode/owned inventory rejection precedes CLI effects.
                fresh();(node/'native-client-campaign-requests').mkdir(mode=0o700)
                reject(lambda:c.NativeRequestAdapterV1(target,'22'*32,'33'*32,time.monotonic()+10).request('status',{}),subprocess.CalledProcessError)
                pathlib.Path(target.socket).chmod(0o666)
                reject(lambda:fresh().request('status',{}),subprocess.CalledProcessError)
                pathlib.Path(target.socket).chmod(0o600)
                binary.chmod(0o700)
                reject(lambda:fresh().request('status',{}),subprocess.CalledProcessError)
                binary.chmod(0o500)
                # Missing endpoint is the one typed, retryable startup case.
                missing=dataclasses.replace(target,socket=str(pathlib.Path(target.socket).with_name('absent.sock')))
                fresh();waiting=c.NativeRequestAdapterV1(missing,'22'*32,'33'*32,time.monotonic()+10)
                reject(lambda:waiting.request('status',{}),c.NativeEndpointNotReady)
                waiting.target=target;assert waiting.request('status',{})['ok'] is True
                # Tight deadline includes transport startup, rather than granting another 12 seconds.
                with mock.patch.dict(os.environ,{'TRNM_TRANSPORT_SSH_MODE':'delay'}):
                    adapter=fresh();adapter.deadline=time.monotonic()+0.05
                    start=time.monotonic();reject(lambda:adapter.request('status',{}),subprocess.TimeoutExpired)
                    assert time.monotonic()-start<1
                with mock.patch.object(c,'bounded_command_v1',side_effect=AssertionError('effect before rejection')):
                    for field,value in [('sequence',c.MAX_REQUESTS),('request_bytes',c.MAX_REQUEST_BYTES),('response_bytes',c.MAX_RESPONSE_BYTES),('deadline',time.monotonic()-1)]:
                        adapter=fresh();setattr(adapter,field,value)
                        reject(lambda:adapter.request('status',{}),(RuntimeError,TimeoutError))
                    reject(lambda:fresh().request('submit',{'signed_outer_hex':'a'*c.REQUEST_LIMIT}))
                # Bounded reader is exercised with real subprocess output floods.
                reject(lambda:c.bounded_command_v1([sys.executable,'-c','import sys;sys.stdout.write("x"*1025)'],timeout=2,output_limit=1024),RuntimeError,'bounded output')
                reject(lambda:c.bounded_command_v1([sys.executable,'-c','import sys;sys.stderr.write("x"*65537)'],timeout=2),RuntimeError,'bounded output')
            for values in ([dataclasses.replace(process,management='-oProxyCommand=x')], [dataclasses.replace(process,management='local')], [process,process], [dataclasses.replace(process,host_id='mac',management='p4-mac')]):
                reject(lambda:c.request_process_v1(values))
            for basename in ('../escape.sock','A.sock','x'*49+'.sock'):
                reject(lambda:c.request_target_v1([process],{'desktop':stage},paths,basename))
            reject(lambda:c.request_target_v1([process],{'desktop':stage},{'desktop':'/tmp/other'},'native.sock'))
            reject(lambda:c.request_target_v1([process],{'desktop':dataclasses.replace(stage,management='p4-rog')},paths,'native.sock'))
            assert not failures, failures
        finally:
            stop.set();thread.join(timeout=2);sock.close()
    finally:
        shutil.rmtree(root)


def main():
    native={"public_files":[{"path":"public/native-client-profile.json"}]}
    legacy={"public_files":[{"path":"public/workload.corpus"},{"path":"public/workload-policy.json"}]}
    assert c.application_selection(native,pathlib.Path('/candidate/keys'),1)
    assert not c.application_selection(legacy,None,1)
    rejected=0
    def reject(fn):
        nonlocal rejected
        try:fn()
        except (RuntimeError,ValueError,KeyError,TypeError,SystemExit):rejected+=1
        else:raise AssertionError('accepted invalid candidate evidence')
    reject(lambda:c.application_selection(native,None,1))
    reject(lambda:c.application_selection(legacy,pathlib.Path('/keys'),1))
    reject(lambda:c.application_selection(native,pathlib.Path('/keys'),17))
    records=[]
    for i in range(2):
        h=f'{i+1:064x}'
        response={"ok":True,"profile_sha256":"22"*32,"candidate_only":True,"data":{"native_tx_hash":h,"receive_sequence":str(i),"status":"pending"}}
        outer=b'{}'
        records.append({"kind":"funding" if i==0 else "transfer","native_tx_hash":h,"outer_hex":outer.hex(),"outer_sha256":hashlib.sha256(outer).hexdigest(),"submitted_monotonic_ns":10+i*10,"ack_monotonic_ns":11+i*10,"verified_monotonic_ns":12+i*10,"ack":response,"retry_ack":copy.deepcopy(response),"proof_response":copy.deepcopy(response),"mac_verification":{"candidate_only":True,"m05_intent_binding":False,"native_tx_hash":h,"proof_verified_by_client":True,"height":"4","index":i}})
    document={"schema":c.PROFILE,"run_id":"candidate","coordinator_manifest_sha256":"11"*32,"profile_sha256":"22"*32,"submit_validator_id":"33"*32,"signing_host":"mac","verification_host":"mac","transport":"ssh-private-unix-ipc","started_monotonic_ns":1,"completed_monotonic_ns":30,"business_transfer_count":1,"business_window_ns":2,"business_goodput_per_second":500000000.0,"records":records,"candidate_only":True,"m05_intent_binding":False,"fault_matrix_completed":False,"performance_acceptance":False,"host_attestation":False,"production_activation":False}
    def validate(d):c.validate_document(d,run_id='candidate',anchor='11'*32,validator_ids={'33'*32})
    validate(document) # Metadata only. These dummy bytes are never a crypto-positive.
    for field,value in [('schema','fake'),('run_id','other'),('coordinator_manifest_sha256','44'*32),('submit_validator_id','55'*32),('signing_host','local'),('transport','public-http'),('business_transfer_count',2),('business_window_ns',1),('business_goodput_per_second',1),('completed_monotonic_ns',1),('started_monotonic_ns',False),('candidate_only',False),('production_activation',True),('performance_acceptance',True),('host_attestation',True),('m05_intent_binding',True),('fault_matrix_completed',True)]:
        d=copy.deepcopy(document);d[field]=value;reject(lambda:validate(d))
    for mutate in [lambda d:d['records'][1].update(native_tx_hash=d['records'][0]['native_tx_hash']),lambda d:d['records'][0].update(outer_sha256='00'*32),lambda d:d['records'][0].update(ack_monotonic_ns=0),lambda d:d['records'][0]['retry_ack']['data'].update(receive_sequence='99'),lambda d:d['records'][0]['ack'].update(ok=False),lambda d:d['records'][0]['mac_verification'].update(proof_verified_by_client=False),lambda d:d['records'][0].update(kind='transfer')]:
        d=copy.deepcopy(document);mutate(d);reject(lambda:validate(d))
    with tempfile.TemporaryDirectory() as temporary:
        root=pathlib.Path(temporary);keys=root/'keys';keys.mkdir(mode=0o700);profile=b'candidate';coordinator=root/'coordinator';deployments=root/'deployments';coordinator.mkdir();deployments.mkdir()
        for name in ('operator.key','client.key'):base.write_new(keys/name,b'a'*64)
        base.write_new(keys/'native-client-profile.json',profile)
        assert c.key_namespace(keys,coordinator,deployments,profile)==keys
        reject(lambda:c.key_namespace(keys,root,deployments,profile))
        reject(lambda:c.key_namespace(keys,coordinator,deployments,b'other'))
        (keys/'client.key').chmod(0o644);reject(lambda:c.key_namespace(keys,coordinator,deployments,profile));(keys/'client.key').chmod(0o600)
        (keys/'client.key').unlink();(keys/'client.key').symlink_to(keys/'operator.key');reject(lambda:c.key_namespace(keys,coordinator,deployments,profile))
    test_request_adapter_v1()
    print(f'native_campaign_structural_tests=passed negatives={rejected} cryptographic_success_claim=false real_campaign_required=true controlled_ssh_unix_transport=true bounded_io_deadline=true')

if __name__=='__main__':main()
